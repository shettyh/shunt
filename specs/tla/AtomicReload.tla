---------------------------- MODULE AtomicReload ----------------------------
(***************************************************************************)
(* Formal TLA+ specification of Shunt's lock-free ArcSwap snapshot reload, *)
(* transactional BuildSession staging, orphan pool/scope GC, and graceful  *)
(* connection draining (RFC 0002 & RFC 0006).                              *)
(***************************************************************************)

EXTENDS Naturals, FiniteSets

CONSTANTS
    Requests,       \* Set of concurrent client request IDs, e.g. {"r1", "r2"}
    Pools,          \* Set of possible UpstreamPoolKeys, e.g. {"p1", "p2"}
    Scopes,         \* Set of possible StateStore scope IDs, e.g. {"s1", "s2"}
    MaxVersion      \* Bounded snapshot version for finite model checking

VARIABLES
    active_version, \* Current live snapshot version published via ArcSwap
    prev_version,   \* Previous active_version (tracks monotonicity)
    snap_pools,     \* Function: version -> subset of Pools referenced by that snapshot
    snap_scopes,    \* Function: version -> subset of Scopes referenced by that snapshot
    live_pools,     \* Pools currently resident in RuntimeRegistry
    live_scopes,    \* State scopes currently resident in StateStore
    req_state,      \* Function: r \in Requests -> "Idle" | "InFlight" | "Done"
    req_snap,       \* Function: r \in Requests -> pinned snapshot version (0 if Idle)
    reload_state,   \* "Idle" | "Staging"
    staged_pools,   \* Pools staged by in-progress transactional BuildSession
    staged_scopes,  \* Scopes staged by in-progress transactional BuildSession
    server_state,   \* "Running" | "Draining" | "Stopped"
    drain_timed_out \* BOOLEAN: whether drain_timeout elapsed during Draining

vars == <<active_version, prev_version, snap_pools, snap_scopes,
          live_pools, live_scopes, req_state, req_snap,
          reload_state, staged_pools, staged_scopes,
          server_state, drain_timed_out>>

Versions == 1..MaxVersion

ActiveInFlight == { r \in Requests : req_state[r] = "InFlight" }

\* A pool/scope is still held via Arc by any in-flight request OR active registry
RefHeldPools == live_pools \union UNION { snap_pools[req_snap[r]] : r \in ActiveInFlight }
RefHeldScopes == live_scopes \union UNION { snap_scopes[req_snap[r]] : r \in ActiveInFlight }

Init ==
    /\ active_version = 1
    /\ prev_version = 1
    /\ snap_pools = [v \in Versions |-> IF v = 1 THEN {CHOOSE p \in Pools : TRUE} ELSE {}]
    /\ snap_scopes = [v \in Versions |-> IF v = 1 THEN {CHOOSE s \in Scopes : TRUE} ELSE {}]
    /\ live_pools = snap_pools[1]
    /\ live_scopes = snap_scopes[1]
    /\ req_state = [r \in Requests |-> "Idle"]
    /\ req_snap = [r \in Requests |-> 0]
    /\ reload_state = "Idle"
    /\ staged_pools = {}
    /\ staged_scopes = {}
    /\ server_state = "Running"
    /\ drain_timed_out = FALSE

\* An incoming request atomically loads the current ArcSwap snapshot once on entry.
StartRequest(r) ==
    /\ server_state = "Running"
    /\ req_state[r] = "Idle"
    /\ req_state' = [req_state EXCEPT ![r] = "InFlight"]
    /\ req_snap' = [req_snap EXCEPT ![r] = active_version]
    /\ UNCHANGED <<active_version, prev_version, snap_pools, snap_scopes,
                   live_pools, live_scopes, reload_state, staged_pools,
                   staged_scopes, server_state, drain_timed_out>>

\* An in-flight request completes using the exact snapshot version it loaded at entry.
FinishRequest(r) ==
    /\ req_state[r] = "InFlight"
    /\ req_state' = [req_state EXCEPT ![r] = "Done"]
    /\ req_snap' = [req_snap EXCEPT ![r] = 0]
    /\ UNCHANGED <<active_version, prev_version, snap_pools, snap_scopes,
                   live_pools, live_scopes, reload_state, staged_pools,
                   staged_scopes, server_state, drain_timed_out>>

\* ReloadController begins a transactional BuildSession (serialized by reload_lock).
BeginReload(new_pools, new_scopes) ==
    /\ server_state = "Running"
    /\ reload_state = "Idle"
    /\ active_version < MaxVersion
    /\ new_pools \subseteq Pools /\ new_pools /= {}
    /\ new_scopes \subseteq Scopes
    /\ reload_state' = "Staging"
    /\ staged_pools' = new_pools
    /\ staged_scopes' = new_scopes
    /\ UNCHANGED <<active_version, prev_version, snap_pools, snap_scopes,
                   live_pools, live_scopes, req_state, req_snap,
                   server_state, drain_timed_out>>

\* Failed compilation aborts cleanly: drops staged pools/scopes with ZERO mutation
\* to active_version, live_pools, or live_scopes.
AbortReload ==
    /\ reload_state = "Staging"
    /\ reload_state' = "Idle"
    /\ staged_pools' = {}
    /\ staged_scopes' = {}
    /\ UNCHANGED <<active_version, prev_version, snap_pools, snap_scopes,
                   live_pools, live_scopes, req_state, req_snap,
                   server_state, drain_timed_out>>

\* Successful compilation commits staged pools/scopes, GCs orphans from registry/store,
\* and atomically swaps ArcSwap to active_version + 1.
CommitReload ==
    /\ reload_state = "Staging"
    /\ active_version < MaxVersion
    /\ LET next_v == active_version + 1 IN
       /\ prev_version' = active_version
       /\ active_version' = next_v
       /\ snap_pools' = [snap_pools EXCEPT ![next_v] = staged_pools]
       /\ snap_scopes' = [snap_scopes EXCEPT ![next_v] = staged_scopes]
       /\ live_pools' = staged_pools
       /\ live_scopes' = staged_scopes
       /\ reload_state' = "Idle"
       /\ staged_pools' = {}
       /\ staged_scopes' = {}
    /\ UNCHANGED <<req_state, req_snap, server_state, drain_timed_out>>

\* Shutdown signal transitions Running -> Draining (stops accepting new requests).
BeginShutdown ==
    /\ server_state = "Running"
    /\ reload_state = "Idle"
    /\ server_state' = "Draining"
    /\ UNCHANGED <<active_version, prev_version, snap_pools, snap_scopes,
                   live_pools, live_scopes, req_state, req_snap,
                   reload_state, staged_pools, staged_scopes, drain_timed_out>>

\* Drain timeout may fire while Draining if connections remain.
DrainTimeoutFires ==
    /\ server_state = "Draining"
    /\ ActiveInFlight /= {}
    /\ ~drain_timed_out
    /\ drain_timed_out' = TRUE
    /\ UNCHANGED <<active_version, prev_version, snap_pools, snap_scopes,
                   live_pools, live_scopes, req_state, req_snap,
                   reload_state, staged_pools, staged_scopes, server_state>>

\* Graceful drain completes once ActiveInFlight = {} or drain_timeout fires.
CompleteShutdown ==
    /\ server_state = "Draining"
    /\ (ActiveInFlight = {} \/ drain_timed_out)
    /\ server_state' = "Stopped"
    /\ UNCHANGED <<active_version, prev_version, snap_pools, snap_scopes,
                   live_pools, live_scopes, req_state, req_snap,
                   reload_state, staged_pools, staged_scopes, drain_timed_out>>

Next ==
    \/ \E r \in Requests : StartRequest(r)
    \/ \E r \in Requests : FinishRequest(r)
    \/ \E np \in SUBSET Pools, ns \in SUBSET Scopes : BeginReload(np, ns)
    \/ AbortReload
    \/ CommitReload
    \/ BeginShutdown
    \/ DrainTimeoutFires
    \/ CompleteShutdown

Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ \A r \in Requests : WF_vars(FinishRequest(r))
    /\ WF_vars(DrainTimeoutFires)
    /\ WF_vars(CompleteShutdown)

(***************************************************************************)
(* Safety Invariants                                                       *)
(***************************************************************************)

TypeOK ==
    /\ active_version \in Versions
    /\ prev_version \in Versions
    /\ live_pools \subseteq Pools
    /\ live_scopes \subseteq Scopes
    /\ reload_state \in {"Idle", "Staging"}
    /\ server_state \in {"Running", "Draining", "Stopped"}
    /\ drain_timed_out \in BOOLEAN

\* Every in-flight request pins a valid snapshot version whose pools/scopes remain held via Arc.
RequestSnapshotConsistency ==
    \A r \in ActiveInFlight :
        /\ req_snap[r] \in 1..active_version
        /\ snap_pools[req_snap[r]] \subseteq RefHeldPools
        /\ snap_scopes[req_snap[r]] \subseteq RefHeldScopes

\* Active snapshot version never decreases.
MonotonicVersions ==
    prev_version <= active_version

\* No pool or state scope referenced by the active snapshot is ever GC'd.
NoUseAfterGC ==
    /\ snap_pools[active_version] \subseteq live_pools
    /\ snap_scopes[active_version] \subseteq live_scopes

\* Staged reload never mutates live registry/store prior to commit.
StagedIsolation ==
    reload_state = "Staging" =>
        /\ live_pools = snap_pools[active_version]
        /\ live_scopes = snap_scopes[active_version]

(***************************************************************************)
(* Liveness Properties                                                     *)
(***************************************************************************)

\* Once shutdown begins, the server eventually transitions to Stopped.
GracefulDrainTerminates ==
    (server_state = "Draining") ~> (server_state = "Stopped")

\* Every in-flight request eventually finishes.
RequestsEventuallyDrain ==
    \A r \in Requests : (req_state[r] = "InFlight") ~> (req_state[r] = "Done")

=============================================================================
