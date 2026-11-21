use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Monotonic clock abstraction enabling deterministic testing and simulation
/// without sleeping or mutating global time.
///
/// Production code uses [`SystemClock`] (backed by `std::time::Instant`), while
/// tests and `shunt test` scenarios can inject [`ManualClock`] via [`crate::BuildContext`].
pub trait Clock: fmt::Debug + Send + Sync + 'static {
    /// Returns monotonic elapsed time since this clock's epoch.
    fn now(&self) -> Duration;

    /// Returns monotonic elapsed milliseconds since this clock's epoch.
    #[inline]
    fn now_ms(&self) -> u64 {
        self.now().as_millis().min(u64::MAX as u128) as u64
    }
}

/// Production monotonic clock backed by [`std::time::Instant`].
#[derive(Debug)]
pub struct SystemClock {
    origin: Instant,
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemClock {
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }

    pub fn shared() -> Arc<dyn Clock> {
        Arc::new(Self::new())
    }
}

impl Clock for SystemClock {
    #[inline]
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }
}

/// Deterministic, manually-stepped monotonic clock for tests and simulations.
#[derive(Debug, Default)]
pub struct ManualClock {
    now_nanos: AtomicU64,
}

impl ManualClock {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_millis(ms: u64) -> Self {
        let nanos = ms.saturating_mul(1_000_000);
        Self {
            now_nanos: AtomicU64::new(nanos),
        }
    }

    pub fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }

    /// Advances the clock forward by `delta` (saturating at `u64::MAX` nanoseconds).
    pub fn advance(&self, delta: Duration) {
        let add_nanos = delta.as_nanos().min(u64::MAX as u128) as u64;
        let mut cur = self.now_nanos.load(Ordering::Acquire);
        loop {
            let next = cur.saturating_add(add_nanos);
            match self.now_nanos.compare_exchange_weak(
                cur,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => cur = actual,
            }
        }
    }

    /// Advances the clock forward by `ms` milliseconds.
    pub fn advance_ms(&self, ms: u64) {
        self.advance(Duration::from_millis(ms));
    }

    /// Sets the clock to an exact elapsed duration (only moves forward or sets directly).
    pub fn set(&self, at: Duration) {
        let nanos = at.as_nanos().min(u64::MAX as u128) as u64;
        self.now_nanos.store(nanos, Ordering::Release);
    }

    /// Sets the clock to an exact millisecond timestamp.
    pub fn set_ms(&self, ms: u64) {
        self.set(Duration::from_millis(ms));
    }
}

impl Clock for ManualClock {
    #[inline]
    fn now(&self) -> Duration {
        Duration::from_nanos(self.now_nanos.load(Ordering::Acquire))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_clock_advances_monotonically() {
        let clock = ManualClock::new();
        assert_eq!(clock.now(), Duration::ZERO);
        assert_eq!(clock.now_ms(), 0);

        clock.advance_ms(250);
        assert_eq!(clock.now_ms(), 250);
        assert_eq!(clock.now(), Duration::from_millis(250));

        clock.advance(Duration::from_micros(500));
        assert_eq!(clock.now(), Duration::from_micros(250_500));

        clock.set_ms(10_000);
        assert_eq!(clock.now_ms(), 10_000);
    }

    #[test]
    fn system_clock_is_monotonic() {
        let clock = SystemClock::new();
        let t1 = clock.now();
        let t2 = clock.now();
        assert!(t2 >= t1);
    }
}
