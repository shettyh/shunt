# Shunt TLA+ Formal Specifications

These TLA+ specifications verify concurrency safety and liveness invariants for Shunt's
core state machines (see [RFC 0006](../../rfcs/0006-verification-and-spec-testing.md)):

| Spec | Subsystem | Key Properties Verified |
| --- | --- | --- |
| [`AtomicReload.tla`](./AtomicReload.tla) | `ArcSwap` reload, transactional `BuildSession`, orphan GC, graceful drain | `RequestSnapshotConsistency`, `MonotonicVersions`, `NoUseAfterGC`, `StagedIsolation`, `GracefulDrainTerminates`, `RequestsEventuallyDrain` |
| [`RequestPipeline.tla`](./RequestPipeline.tla) | 7-stage RFC 0001 lifecycle, retry loop, `HookMask` fast path, panic isolation | `OnCompleteAtMostOnce`, `NoRetryAfterCommit`, `NoUnbufferedNonEmptyReplay`, `CanonicalRequestIsolation`, `ZeroAllocFastPath`, `MatchedRequestCompletes` |
| [`PassiveHealth.tla`](./PassiveHealth.tla) | Single-word atomic `EndpointState` CAS & 3-pass endpoint selection | `NoSplitHealthState`, `ThresholdRespected`, `SelectionTotality` |

## Running TLC Locally

Download `tla2tools.jar` from [tlaplus/tlaplus releases](https://github.com/tlaplus/tlaplus/releases) and run:

```bash
for spec in AtomicReload RequestPipeline PassiveHealth; do
  java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC \
    -workers auto -deadlock \
    -config "specs/tla/${spec}.cfg" "specs/tla/${spec}.tla"
done
```
