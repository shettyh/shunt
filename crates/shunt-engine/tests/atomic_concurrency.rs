use std::sync::Arc;
use std::thread;
use std::time::Duration;

use shunt_engine::EndpointState;

/// Concurrent stress test verifying that `EndpointState`'s single-word `AtomicU64` CAS
/// never exposes split `(consecutive_failures, unhealthy_until_ms)` state across threads.
#[test]
fn endpoint_state_single_word_atomic_never_splits_under_concurrency() {
    let threshold = 3usize;
    let cooldown = Duration::from_secs(10);
    let ep = Arc::new(EndpointState::new("http://127.0.0.1:8080".to_owned()).unwrap());

    let mut handles = Vec::new();

    // Writer threads alternating failures and successes
    for tid in 0..4u64 {
        let ep_c = Arc::clone(&ep);
        handles.push(thread::spawn(move || {
            for step in 0..10_000u64 {
                if (step + tid) % 5 == 0 {
                    ep_c.record_success();
                } else {
                    ep_c.record_failure(step + 1, threshold, cooldown);
                }
            }
        }));
    }

    // Reader threads asserting NoSplitHealthState invariant on every snapshot
    for _ in 0..4 {
        let ep_c = Arc::clone(&ep);
        handles.push(thread::spawn(move || {
            for _ in 0..20_000 {
                let (fails, until) = ep_c.health_snapshot();
                if fails == 0 {
                    assert_eq!(until, 0, "split health state: fails=0 but until={until}");
                } else if fails < threshold {
                    assert_eq!(
                        until, 0,
                        "split health state: fails={fails} < threshold={threshold} but until={until}"
                    );
                } else {
                    assert!(
                        until > 0,
                        "split health state: fails={fails} >= threshold={threshold} but until=0"
                    );
                }
            }
        }));
    }

    for h in handles {
        h.join().expect("concurrency worker thread panicked");
    }
}
