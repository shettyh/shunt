---------------------------- MODULE PassiveHealth ----------------------------
(***************************************************************************)
(* Formal TLA+ specification of Shunt's single-word atomic passive health  *)
(* tracking (EndpointState) and 3-pass endpoint selection policy           *)
(* (RFC 0002 & RFC 0006).                                                  *)
(***************************************************************************)

EXTENDS Naturals, FiniteSets

CONSTANTS
    Endpoints,      \* Set of endpoint indices, e.g. {1, 2, 3}
    Threshold,      \* Consecutive failures before cooldown (>= 1)
    Cooldown,       \* Cooldown ticks (>= 1)
    MaxTime         \* Bounded monotonic clock ceiling for TLC

VARIABLES
    now,            \* Monotonic clock tick (0..MaxTime)
    failures,       \* Function: e \in Endpoints -> consecutive failures
    unhealthy_until,\* Function: e \in Endpoints -> cooldown expiry tick (0 = healthy)
    last_selected,  \* Last chosen endpoint index (0 before first selection)
    last_was_optimal\* BOOLEAN: whether last selection satisfied 3-pass optimality

vars == <<now, failures, unhealthy_until, last_selected, last_was_optimal>>

IsHealthy(e) == unhealthy_until[e] = 0 \/ now >= unhealthy_until[e]

Max(a, b) == IF a >= b THEN a ELSE b

Init ==
    /\ now = 0
    /\ failures = [e \in Endpoints |-> 0]
    /\ unhealthy_until = [e \in Endpoints |-> 0]
    /\ last_selected = 0
    /\ last_was_optimal = TRUE

\* Single-word atomic CAS failure transition (models EndpointState::record_failure)
RecordFailure(e) ==
    /\ failures[e] < Threshold + 2
    /\ LET next_f == failures[e] + 1
           next_u == IF next_f >= Threshold
                     THEN Max(unhealthy_until[e], now + Cooldown)
                     ELSE unhealthy_until[e]
       IN /\ failures' = [failures EXCEPT ![e] = next_f]
          /\ unhealthy_until' = [unhealthy_until EXCEPT ![e] = next_u]
    /\ UNCHANGED <<now, last_selected, last_was_optimal>>

\* Single-word atomic store(0) success transition (models EndpointState::record_success)
RecordSuccess(e) ==
    /\ failures' = [failures EXCEPT ![e] = 0]
    /\ unhealthy_until' = [unhealthy_until EXCEPT ![e] = 0]
    /\ UNCHANGED <<now, last_selected, last_was_optimal>>

\* Monotonic clock advance
Tick ==
    /\ now < MaxTime
    /\ now' = now + 1
    /\ UNCHANGED <<failures, unhealthy_until, last_selected, last_was_optimal>>

\* 3-pass endpoint selection (healthy & untried -> untried -> healthy -> fallback)
SelectEndpoint(tried) ==
    /\ LET untried == Endpoints \ tried
           healthy_untried == { e \in untried : IsHealthy(e) }
           healthy_all == { e \in Endpoints : IsHealthy(e) }
           candidates ==
               IF healthy_untried /= {} THEN healthy_untried
               ELSE IF untried /= {} THEN untried
               ELSE IF healthy_all /= {} THEN healthy_all
               ELSE Endpoints
       IN \E chosen \in candidates :
          /\ last_selected' = chosen
          /\ last_was_optimal' =
                ((healthy_untried /= {} => chosen \in healthy_untried)
                 /\ (healthy_untried = {} /\ untried /= {} => chosen \in untried)
                 /\ (untried = {} /\ healthy_all /= {} => chosen \in healthy_all))
    /\ UNCHANGED <<now, failures, unhealthy_until>>

Next ==
    \/ \E e \in Endpoints : RecordFailure(e)
    \/ \E e \in Endpoints : RecordSuccess(e)
    \/ Tick
    \/ \E tried \in SUBSET Endpoints : SelectEndpoint(tried)

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Safety Invariants                                                       *)
(***************************************************************************)

TypeOK ==
    /\ now \in 0..MaxTime
    /\ \A e \in Endpoints : failures[e] \in Nat /\ unhealthy_until[e] \in Nat
    /\ last_selected \in Endpoints \union {0}
    /\ last_was_optimal \in BOOLEAN

\* Single-word atomic invariant: failure counter and cooldown timestamp never split.
NoSplitHealthState ==
    \A e \in Endpoints :
        /\ (failures[e] = 0 => unhealthy_until[e] = 0)
        /\ (failures[e] < Threshold => unhealthy_until[e] = 0)
        /\ (failures[e] >= Threshold => unhealthy_until[e] > 0)

\* An endpoint never enters cooldown with fewer than Threshold consecutive failures.
ThresholdRespected ==
    \A e \in Endpoints : unhealthy_until[e] > 0 => failures[e] >= Threshold

\* Selection always returns a valid endpoint and respects the 3-pass priority policy.
SelectionTotality ==
    /\ (last_selected /= 0 => last_selected \in Endpoints)
    /\ last_was_optimal

=============================================================================
