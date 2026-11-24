------------------------ MODULE ShardedListenerDrain ------------------------
(***************************************************************************)
(* Formal TLA+ specification of Shunt's multi-shard SO_REUSEPORT accept    *)
(* loops, watch-channel shutdown broadcast, ActiveConnGuard atomic count,  *)
(* and Tokio Notify graceful drain loop (crates/shunt-engine/src/server.rs)*)
(***************************************************************************)

EXTENDS Naturals, FiniteSets

CONSTANTS
    Shards,     \* Set of independent SO_REUSEPORT accept shards, e.g. {"s1", "s2", "s3"}
    Conns       \* Bounded set of client connections, e.g. {"c1", "c2"}

VARIABLES
    shard_state,        \* [Shards -> "Running" | "Stopped"]
    conn_state,         \* [Conns -> "Idle" | "Active" | "Closed"]
    active_conns,       \* AtomicUsize counter maintained by accept loop & ActiveConnGuard
    shutdown_sent,      \* watch::Sender<bool> broadcast flag
    phase,              \* "Running" | "JoiningShards" | "CheckDrain" | "WaitNotify" | "Done"
    joined_shards,      \* Subset of Shards already awaited in shutdown()
    waiter_registered,  \* TRUE once `drain_notify.notified()` is registered before load()
    notified,           \* TRUE once `notify_waiters()` fired while waiter_registered = TRUE
    timed_out           \* TRUE if drain_timeout elapsed before active_conns reached 0

vars == <<shard_state, conn_state, active_conns, shutdown_sent, phase,
          joined_shards, waiter_registered, notified, timed_out>>

ActiveConnSet == { c \in Conns : conn_state[c] = "Active" }

Init ==
    /\ shard_state = [s \in Shards |-> "Running"]
    /\ conn_state = [c \in Conns |-> "Idle"]
    /\ active_conns = 0
    /\ shutdown_sent = FALSE
    /\ phase = "Running"
    /\ joined_shards = {}
    /\ waiter_registered = FALSE
    /\ notified = FALSE
    /\ timed_out = FALSE

\* Any running shard may accept an incoming TCP connection, even during the brief race window
\* after `shutdown_tx.send(true)` and before that shard observes `shutdown_rx.changed()`.
AcceptConn(s, c) ==
    /\ shard_state[s] = "Running"
    /\ conn_state[c] = "Idle"
    /\ conn_state' = [conn_state EXCEPT ![c] = "Active"]
    /\ active_conns' = active_conns + 1
    /\ UNCHANGED <<shard_state, shutdown_sent, phase, joined_shards,
                   waiter_registered, notified, timed_out>>

\* A running shard observes `shutdown_rx.changed()` and exits its accept loop.
ShardObserveShutdown(s) ==
    /\ shutdown_sent = TRUE
    /\ shard_state[s] = "Running"
    /\ shard_state' = [shard_state EXCEPT ![s] = "Stopped"]
    /\ UNCHANGED <<conn_state, active_conns, shutdown_sent, phase, joined_shards,
                   waiter_registered, notified, timed_out>>

\* ActiveConnGuard::drop decrements `active_conns` and fires `notify_waiters()` on 1 -> 0.
ConnFinish(c) ==
    /\ conn_state[c] = "Active"
    /\ conn_state' = [conn_state EXCEPT ![c] = "Closed"]
    /\ active_conns' = active_conns - 1
    /\ notified' = IF active_conns = 1 /\ waiter_registered THEN TRUE ELSE notified
    /\ UNCHANGED <<shard_state, shutdown_sent, phase, joined_shards,
                   waiter_registered, timed_out>>

\* ServerHandle::shutdown broadcasts `shutdown_tx.send(true)` and begins joining all shards.
BeginShutdown ==
    /\ phase = "Running"
    /\ shutdown_sent' = TRUE
    /\ phase' = "JoiningShards"
    /\ UNCHANGED <<shard_state, conn_state, active_conns, joined_shards,
                   waiter_registered, notified, timed_out>>

\* Shutdown awaits each shard JoinHandle; once all shards are joined, moves to drain check.
JoinShard(s) ==
    /\ phase = "JoiningShards"
    /\ s \notin joined_shards
    /\ shard_state[s] = "Stopped"
    /\ LET next_joined == joined_shards \union {s} IN
       /\ joined_shards' = next_joined
       /\ phase' = IF next_joined = Shards THEN "CheckDrain" ELSE "JoiningShards"
    /\ UNCHANGED <<shard_state, conn_state, active_conns, shutdown_sent,
                   waiter_registered, notified, timed_out>>

\* Register `let notified = self.drain_notify.notified();` BEFORE checking `active_conns`.
RegisterWaiter ==
    /\ phase = "CheckDrain"
    /\ ~waiter_registered
    /\ waiter_registered' = TRUE
    /\ notified' = FALSE
    /\ UNCHANGED <<shard_state, conn_state, active_conns, shutdown_sent,
                   phase, joined_shards, timed_out>>

\* Fast exit when `active_conns.load(SeqCst) == 0`.
CheckZeroAndFinish ==
    /\ phase = "CheckDrain"
    /\ waiter_registered
    /\ active_conns = 0
    /\ phase' = "Done"
    /\ waiter_registered' = FALSE
    /\ notified' = FALSE
    /\ UNCHANGED <<shard_state, conn_state, active_conns, shutdown_sent,
                   joined_shards, timed_out>>

\* Non-zero active connections: transition to awaiting the registered `notified` future.
CheckNonZeroAndWait ==
    /\ phase = "CheckDrain"
    /\ waiter_registered
    /\ active_conns > 0
    /\ phase' = "WaitNotify"
    /\ UNCHANGED <<shard_state, conn_state, active_conns, shutdown_sent,
                   joined_shards, waiter_registered, notified, timed_out>>

\* Woken by `notify_waiters()`: loop back to re-check `active_conns`.
WakeFromNotify ==
    /\ phase = "WaitNotify"
    /\ notified = TRUE
    /\ phase' = "CheckDrain"
    /\ waiter_registered' = FALSE
    /\ notified' = FALSE
    /\ UNCHANGED <<shard_state, conn_state, active_conns, shutdown_sent,
                   joined_shards, timed_out>>

\* Optional drain_timeout expiry terminates waiting and returns `false`.
DrainTimeout ==
    /\ phase \in {"CheckDrain", "WaitNotify"}
    /\ phase' = "Done"
    /\ timed_out' = TRUE
    /\ waiter_registered' = FALSE
    /\ notified' = FALSE
    /\ UNCHANGED <<shard_state, conn_state, active_conns, shutdown_sent,
                   joined_shards>>

DoneStutter ==
    /\ phase = "Done"
    /\ UNCHANGED vars

Next ==
    \/ \E s \in Shards, c \in Conns : AcceptConn(s, c)
    \/ \E s \in Shards : ShardObserveShutdown(s)
    \/ \E c \in Conns : ConnFinish(c)
    \/ BeginShutdown
    \/ \E s \in Shards : JoinShard(s)
    \/ RegisterWaiter
    \/ CheckZeroAndFinish
    \/ CheckNonZeroAndWait
    \/ WakeFromNotify
    \/ DrainTimeout
    \/ DoneStutter

Fairness ==
    /\ \A s \in Shards : WF_vars(ShardObserveShutdown(s))
    /\ \A s \in Shards : WF_vars(JoinShard(s))
    /\ \A c \in Conns : WF_vars(ConnFinish(c))
    /\ WF_vars(RegisterWaiter)
    /\ WF_vars(CheckZeroAndFinish)
    /\ WF_vars(CheckNonZeroAndWait)
    /\ WF_vars(WakeFromNotify)

Spec == Init /\ [][Next]_vars /\ Fairness

(***************************************************************************)
(* Safety Invariants                                                       *)
(***************************************************************************)

TypeOK ==
    /\ shard_state \in [Shards -> {"Running", "Stopped"}]
    /\ conn_state \in [Conns -> {"Idle", "Active", "Closed"}]
    /\ active_conns \in 0..Cardinality(Conns)
    /\ shutdown_sent \in BOOLEAN
    /\ phase \in {"Running", "JoiningShards", "CheckDrain", "WaitNotify", "Done"}
    /\ joined_shards \subseteq Shards
    /\ waiter_registered \in BOOLEAN
    /\ notified \in BOOLEAN
    /\ timed_out \in BOOLEAN

\* Counter always matches exact number of active connections across all shards.
ActiveCountExact ==
    active_conns = Cardinality(ActiveConnSet)

\* Once all shards are joined, every shard is stopped and no new accepts can occur.
NoRunningShardAfterJoin ==
    phase \in {"CheckDrain", "WaitNotify", "Done"} =>
        \A s \in Shards : shard_state[s] = "Stopped"

\* Returning clean=TRUE (`~timed_out`) guarantees zero remaining active connections.
CleanShutdownMeansZeroActive ==
    (phase = "Done" /\ ~timed_out) => active_conns = 0

\* Zero lost-wakeup invariant: if shutdown is awaiting Notify after active_conns hit 0,
\* the notification MUST already be armed.
NoLostWakeup ==
    (phase = "WaitNotify" /\ active_conns = 0) => notified = TRUE

(***************************************************************************)
(* Liveness Properties                                                     *)
(***************************************************************************)

\* Once shutdown begins, it always terminates (never deadlocks on missed Notify).
ShutdownEventuallyCompletes ==
    shutdown_sent ~> (phase = "Done")

\* Every accepted connection eventually drains cleanly.
AcceptedConnsEventuallyClose ==
    \A c \in Conns : (conn_state[c] = "Active") ~> (conn_state[c] = "Closed")

=============================================================================
