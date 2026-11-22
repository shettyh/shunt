--------------------------- MODULE RequestPipeline ---------------------------
(***************************************************************************)
(* Formal TLA+ specification of Shunt's 7-stage request lifecycle, retry   *)
(* loop, Stage 4f InspectResponseBody buffering (RFC 0017), HookMask       *)
(* fast-path, and panic isolation (RFC 0001, RFC 0006, RFC 0017).          *)
(***************************************************************************)

EXTENDS Naturals

CONSTANTS
    MaxAttempts \* Upper bound on configured route max_attempts, e.g. 3

VARIABLES
    stage,                \* Lifecycle stage
    attempt,              \* Current upstream attempt (0 before Stage 4, 1..MaxAttempts during)
    max_attempts,         \* Configured max_attempts for this request (1..MaxAttempts)
    mask_req_buffered,    \* HookMask::REQUEST_BODY_BUFFERED
    mask_resp_inspect,    \* HookMask::ON_RESPONSE_BODY_INSPECTED (RFC 0017)
    mask_resp_stream,     \* HookMask::RESPONSE_BODY_STREAM
    mask_on_complete,     \* HookMask::ON_COMPLETE
    body_non_empty,       \* Whether incoming request body is non-empty
    body_buffered,        \* Whether core engine actually buffered the request body
    resp_body_inspected,  \* Whether Stage 4f buffered an upstream response body for inspection
    stream_hooked,        \* Whether core engine spawned response body stream pump
    headers_committed,    \* Whether Stage 5 committed response headers downstream
    attempt_dirty,        \* Whether per-attempt UpstreamRequest was mutated on current attempt
    on_complete_count     \* Number of times Stage 7 on_complete was invoked

vars == <<stage, attempt, max_attempts, mask_req_buffered, mask_resp_inspect,
          mask_resp_stream, mask_on_complete, body_non_empty, body_buffered,
          resp_body_inspected, stream_hooked, headers_committed, attempt_dirty,
          on_complete_count>>

Stages == {
    "ReqHeaders",
    "ReqBody",
    "Route",
    "UpstreamSelect",
    "UpstreamRequest",
    "ResponseHeaders",
    "ResponseBodyInspect",
    "CommittedStream",
    "Finalize",
    "Done"
}

BodyReplayable == body_buffered \/ ~body_non_empty

Init ==
    /\ stage = "ReqHeaders"
    /\ attempt = 0
    /\ max_attempts \in 1..MaxAttempts
    /\ mask_req_buffered \in BOOLEAN
    /\ mask_resp_inspect \in BOOLEAN
    /\ mask_resp_stream \in BOOLEAN
    /\ mask_on_complete \in BOOLEAN
    /\ body_non_empty \in BOOLEAN
    /\ body_buffered = FALSE
    /\ resp_body_inspected = FALSE
    /\ stream_hooked = FALSE
    /\ headers_committed = FALSE
    /\ attempt_dirty = FALSE
    /\ on_complete_count = 0

\* Stage 1: on_request_headers -> Continue | Respond (short-circuit) | Panic (500)
Stage1Continue ==
    /\ stage = "ReqHeaders"
    /\ stage' = "ReqBody"
    /\ UNCHANGED <<attempt, max_attempts, mask_req_buffered, mask_resp_inspect,
                   mask_resp_stream, mask_on_complete, body_non_empty, body_buffered,
                   resp_body_inspected, stream_hooked, headers_committed, attempt_dirty,
                   on_complete_count>>

Stage1ShortCircuitOrPanic ==
    /\ stage = "ReqHeaders"
    /\ stage' = "Finalize"
    /\ UNCHANGED <<attempt, max_attempts, mask_req_buffered, mask_resp_inspect,
                   mask_resp_stream, mask_on_complete, body_non_empty, body_buffered,
                   resp_body_inspected, stream_hooked, headers_committed, attempt_dirty,
                   on_complete_count>>

\* Stage 2: Optional Request Body Buffering (strictly gated on mask_req_buffered)
Stage2Proceed ==
    /\ stage = "ReqBody"
    /\ body_buffered' = mask_req_buffered
    /\ stage' = "Route"
    /\ UNCHANGED <<attempt, max_attempts, mask_req_buffered, mask_resp_inspect,
                   mask_resp_stream, mask_on_complete, body_non_empty,
                   resp_body_inspected, stream_hooked, headers_committed, attempt_dirty,
                   on_complete_count>>

Stage2RejectOrPanic ==
    /\ stage = "ReqBody"
    /\ mask_req_buffered
    /\ body_buffered' = TRUE
    /\ stage' = "Finalize"
    /\ UNCHANGED <<attempt, max_attempts, mask_req_buffered, mask_resp_inspect,
                   mask_resp_stream, mask_on_complete, body_non_empty,
                   resp_body_inspected, stream_hooked, headers_committed, attempt_dirty,
                   on_complete_count>>

\* Stage 3: on_route -> enter Stage 4 attempt 1, or short-circuit/panic
Stage3EnterUpstream ==
    /\ stage = "Route"
    /\ stage' = "UpstreamSelect"
    /\ attempt' = 1
    /\ attempt_dirty' = FALSE
    /\ UNCHANGED <<max_attempts, mask_req_buffered, mask_resp_inspect,
                   mask_resp_stream, mask_on_complete, body_non_empty, body_buffered,
                   resp_body_inspected, stream_hooked, headers_committed, on_complete_count>>

Stage3ShortCircuitOrPanic ==
    /\ stage = "Route"
    /\ stage' = "Finalize"
    /\ UNCHANGED <<attempt, max_attempts, mask_req_buffered, mask_resp_inspect,
                   mask_resp_stream, mask_on_complete, body_non_empty, body_buffered,
                   resp_body_inspected, stream_hooked, headers_committed, attempt_dirty,
                   on_complete_count>>

\* Stage 4a: on_upstream_select -> clone canonical request (attempt_dirty' = FALSE)
Stage4aSelect ==
    /\ stage = "UpstreamSelect"
    /\ stage' = "UpstreamRequest"
    /\ attempt_dirty' = FALSE
    /\ UNCHANGED <<attempt, max_attempts, mask_req_buffered, mask_resp_inspect,
                   mask_resp_stream, mask_on_complete, body_non_empty, body_buffered,
                   resp_body_inspected, stream_hooked, headers_committed, on_complete_count>>

Stage4aShortCircuitOrPanic ==
    /\ stage = "UpstreamSelect"
    /\ stage' = "Finalize"
    /\ UNCHANGED <<attempt, max_attempts, mask_req_buffered, mask_resp_inspect,
                   mask_resp_stream, mask_on_complete, body_non_empty, body_buffered,
                   resp_body_inspected, stream_hooked, headers_committed, attempt_dirty,
                   on_complete_count>>

\* Stage 4b/4c: on_upstream_request mutates per-attempt copy and sends to upstream
Stage4bSendOk ==
    /\ stage = "UpstreamRequest"
    /\ attempt_dirty' = TRUE
    /\ stage' = "ResponseHeaders"
    /\ UNCHANGED <<attempt, max_attempts, mask_req_buffered, mask_resp_inspect,
                   mask_resp_stream, mask_on_complete, body_non_empty, body_buffered,
                   resp_body_inspected, stream_hooked, headers_committed, on_complete_count>>

\* Transport error / timeout during send: retry only if attempt < max_attempts /\ BodyReplayable
Stage4bTransportErrRetry ==
    /\ stage = "UpstreamRequest"
    /\ attempt < max_attempts
    /\ BodyReplayable
    /\ attempt' = attempt + 1
    /\ attempt_dirty' = FALSE
    /\ stage' = "UpstreamSelect"
    /\ UNCHANGED <<max_attempts, mask_req_buffered, mask_resp_inspect,
                   mask_resp_stream, mask_on_complete, body_non_empty, body_buffered,
                   resp_body_inspected, stream_hooked, headers_committed, on_complete_count>>

Stage4bTransportErrTerminal ==
    /\ stage = "UpstreamRequest"
    /\ (attempt = max_attempts \/ ~BodyReplayable)
    /\ stage' = "Finalize"
    /\ UNCHANGED <<attempt, max_attempts, mask_req_buffered, mask_resp_inspect,
                   mask_resp_stream, mask_on_complete, body_non_empty, body_buffered,
                   resp_body_inspected, stream_hooked, headers_committed, attempt_dirty,
                   on_complete_count>>

\* Stage 4e: on_response_headers -> RetryUpstream (only before commit & if replayable)
Stage4eRetry ==
    /\ stage = "ResponseHeaders"
    /\ ~headers_committed
    /\ attempt < max_attempts
    /\ BodyReplayable
    /\ attempt' = attempt + 1
    /\ attempt_dirty' = FALSE
    /\ stage' = "UpstreamSelect"
    /\ UNCHANGED <<max_attempts, mask_req_buffered, mask_resp_inspect,
                   mask_resp_stream, mask_on_complete, body_non_empty, body_buffered,
                   resp_body_inspected, stream_hooked, headers_committed, on_complete_count>>

\* Stage 4e -> Stage 4f: Flow::InspectResponseBody (strictly gated on mask_resp_inspect & before commit)
Stage4eInspectBody ==
    /\ stage = "ResponseHeaders"
    /\ ~headers_committed
    /\ mask_resp_inspect
    /\ resp_body_inspected' = TRUE
    /\ stage' = "ResponseBodyInspect"
    /\ UNCHANGED <<attempt, max_attempts, mask_req_buffered, mask_resp_inspect,
                   mask_resp_stream, mask_on_complete, body_non_empty, body_buffered,
                   stream_hooked, headers_committed, attempt_dirty, on_complete_count>>

Stage4eShortCircuitOrPanic ==
    /\ stage = "ResponseHeaders"
    /\ stage' = "Finalize"
    /\ UNCHANGED <<attempt, max_attempts, mask_req_buffered, mask_resp_inspect,
                   mask_resp_stream, mask_on_complete, body_non_empty, body_buffered,
                   resp_body_inspected, stream_hooked, headers_committed, attempt_dirty,
                   on_complete_count>>

\* Stage 4f: on_response_body_inspected -> RetryUpstream (before commit & if replayable)
Stage4fRetry ==
    /\ stage = "ResponseBodyInspect"
    /\ ~headers_committed
    /\ attempt < max_attempts
    /\ BodyReplayable
    /\ attempt' = attempt + 1
    /\ attempt_dirty' = FALSE
    /\ stage' = "UpstreamSelect"
    /\ UNCHANGED <<max_attempts, mask_req_buffered, mask_resp_inspect,
                   mask_resp_stream, mask_on_complete, body_non_empty, body_buffered,
                   resp_body_inspected, stream_hooked, headers_committed, on_complete_count>>

Stage4fShortCircuitOrPanic ==
    /\ stage = "ResponseBodyInspect"
    /\ stage' = "Finalize"
    /\ UNCHANGED <<attempt, max_attempts, mask_req_buffered, mask_resp_inspect,
                   mask_resp_stream, mask_on_complete, body_non_empty, body_buffered,
                   resp_body_inspected, stream_hooked, headers_committed, attempt_dirty,
                   on_complete_count>>

\* Stage 4f -> Stage 5: Commit inspected buffered response headers downstream
Stage4fCommitBuffered ==
    /\ stage = "ResponseBodyInspect"
    /\ headers_committed' = TRUE
    /\ stream_hooked' = mask_resp_stream
    /\ stage' = "CommittedStream"
    /\ UNCHANGED <<attempt, max_attempts, mask_req_buffered, mask_resp_inspect,
                   mask_resp_stream, mask_on_complete, body_non_empty, body_buffered,
                   resp_body_inspected, attempt_dirty, on_complete_count>>

\* Stage 5: Commit response headers downstream; spawn stream pump iff mask_resp_stream
Stage5Commit ==
    /\ stage = "ResponseHeaders"
    /\ headers_committed' = TRUE
    /\ stream_hooked' = mask_resp_stream
    /\ stage' = "CommittedStream"
    /\ UNCHANGED <<attempt, max_attempts, mask_req_buffered, mask_resp_inspect,
                   mask_resp_stream, mask_on_complete, body_non_empty, body_buffered,
                   resp_body_inspected, attempt_dirty, on_complete_count>>

\* Stage 6: Stream completes cleanly, aborts mid-stream, hits idle timeout, or plugin panics
Stage6FinishOrAbort ==
    /\ stage = "CommittedStream"
    /\ stage' = "Finalize"
    /\ UNCHANGED <<attempt, max_attempts, mask_req_buffered, mask_resp_inspect,
                   mask_resp_stream, mask_on_complete, body_non_empty, body_buffered,
                   resp_body_inspected, stream_hooked, headers_committed, attempt_dirty,
                   on_complete_count>>

\* Stage 7: Invoke on_complete exactly once if HookMask::ON_COMPLETE is set
Stage7Finalize ==
    /\ stage = "Finalize"
    /\ on_complete_count' = IF mask_on_complete THEN on_complete_count + 1 ELSE on_complete_count
    /\ stage' = "Done"
    /\ UNCHANGED <<attempt, max_attempts, mask_req_buffered, mask_resp_inspect,
                   mask_resp_stream, mask_on_complete, body_non_empty, body_buffered,
                   resp_body_inspected, stream_hooked, headers_committed, attempt_dirty>>

Next ==
    \/ Stage1Continue
    \/ Stage1ShortCircuitOrPanic
    \/ Stage2Proceed
    \/ Stage2RejectOrPanic
    \/ Stage3EnterUpstream
    \/ Stage3ShortCircuitOrPanic
    \/ Stage4aSelect
    \/ Stage4aShortCircuitOrPanic
    \/ Stage4bSendOk
    \/ Stage4bTransportErrRetry
    \/ Stage4bTransportErrTerminal
    \/ Stage4eRetry
    \/ Stage4eInspectBody
    \/ Stage4eShortCircuitOrPanic
    \/ Stage4fRetry
    \/ Stage4fShortCircuitOrPanic
    \/ Stage4fCommitBuffered
    \/ Stage5Commit
    \/ Stage6FinishOrAbort
    \/ Stage7Finalize

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

(***************************************************************************)
(* Safety Invariants                                                       *)
(***************************************************************************)

TypeOK ==
    /\ stage \in Stages
    /\ attempt \in 0..MaxAttempts
    /\ max_attempts \in 1..MaxAttempts
    /\ on_complete_count \in 0..2

OnCompleteAtMostOnce ==
    on_complete_count <= 1

NoRetryAfterCommit ==
    headers_committed => stage \in {"CommittedStream", "Finalize", "Done"}

NoUnbufferedNonEmptyReplay ==
    (~body_buffered /\ body_non_empty) => attempt <= 1

CanonicalRequestIsolation ==
    (stage = "UpstreamRequest") => (attempt_dirty = FALSE)

ZeroAllocFastPath ==
    /\ (~mask_req_buffered => ~body_buffered)
    /\ (~mask_resp_inspect => ~resp_body_inspected)
    /\ (~mask_resp_stream => ~stream_hooked)

(***************************************************************************)
(* Liveness Property                                                       *)
(***************************************************************************)

MatchedRequestCompletes ==
    <> (stage = "Done" /\ (mask_on_complete => on_complete_count = 1))

=============================================================================
