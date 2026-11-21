use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::clock::{Clock, SystemClock};
use crate::flow::BoxFuture;

/// Result of an atomic quota check-and-consume operation on a [`DistributedStore`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotaOutcome {
    /// Whether the requested `amount` was admitted within `limit`.
    pub allowed: bool,
    /// Counter value after the operation (unchanged if rejected).
    pub current: u64,
    /// Configured quota limit for this window.
    pub limit: u64,
    /// Remaining quota in the current window (`limit.saturating_sub(current)`).
    pub remaining: u64,
    /// Suggested `Retry-After` seconds (`0` when allowed, `>= 1` when rejected).
    pub retry_after_secs: u64,
}

/// Failure handling strategy when a distributed state backend is unavailable or times out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FailurePolicy {
    /// Permit traffic gracefully when the distributed store cannot be reached.
    #[default]
    FailOpen,
    /// Reject requests defensively (`503 Service Unavailable`) when the distributed store fails.
    FailClosed,
}

/// Errors returned by [`DistributedStore`] backends.
#[derive(Debug, Error)]
pub enum DistributedStoreError {
    #[error("distributed store connection error: {0}")]
    Connection(String),
    #[error("distributed store timed out after {0:?}")]
    Timeout(Duration),
    #[error("distributed store protocol error: {0}")]
    Protocol(String),
    #[error("distributed store command error: {0}")]
    Command(String),
}

/// General-purpose asynchronous distributed state backend (e.g., Redis / Valkey)
/// shared across multiple Shunt replicas.
///
/// Plugins obtain an optional `Arc<dyn DistributedStore>` from [`crate::BuildContext::distributed_store`].
/// When `None` (the default zero-dependency in-memory mode), plugins stay on the synchronous
/// zero-allocation [`crate::HookResult::Ready`] fast path. When `Some`, plugins return
/// [`crate::HookResult::Pending`] only for hooks that coordinate across replicas.
pub trait DistributedStore: fmt::Debug + Send + Sync + 'static {
    /// Human-readable backend identifier (e.g., `"redis"`, `"memory"`).
    fn backend_name(&self) -> &str;

    /// Configured failure policy (`fail_open` or `fail_closed`).
    fn failure_policy(&self) -> FailurePolicy;

    /// Atomically checks whether `current + amount <= limit` for `key` within `window`.
    ///
    /// If admitted, increments `key` by `amount` and ensures a TTL of `window` on newly created
    /// keys. If rejected, leaves `key` unchanged and returns `retry_after_secs >= 1`.
    fn try_consume_quota<'a>(
        &'a self,
        key: &'a str,
        amount: u64,
        limit: u64,
        window: Duration,
    ) -> BoxFuture<'a, Result<QuotaOutcome, DistributedStoreError>>;

    /// Atomically adjusts integer counter `key` by `delta` (positive or negative), clamping
    /// at `0` so refunds never produce negative values, while preserving any existing TTL
    /// (or setting `ttl` on newly created keys). Returns the updated counter value.
    fn adjust_counter<'a>(
        &'a self,
        key: &'a str,
        delta: i64,
        ttl: Duration,
    ) -> BoxFuture<'a, Result<i64, DistributedStoreError>>;

    /// Reads the current integer value of counter `key` (returns `0` if absent or expired).
    fn get_counter<'a>(&'a self, key: &'a str)
    -> BoxFuture<'a, Result<i64, DistributedStoreError>>;

    /// Sets a boolean presence flag under `key` with expiration `ttl`.
    fn set_flag<'a>(
        &'a self,
        key: &'a str,
        ttl: Duration,
    ) -> BoxFuture<'a, Result<(), DistributedStoreError>>;

    /// Returns `true` if `key` currently exists and has not expired.
    fn has_flag<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<bool, DistributedStoreError>>;

    /// Reads an opaque binary value stored under `key` (`None` if absent or expired).
    fn get_bytes<'a>(
        &'a self,
        key: &'a str,
    ) -> BoxFuture<'a, Result<Option<Bytes>, DistributedStoreError>>;

    /// Stores an opaque binary `value` under `key` with expiration `ttl`.
    fn set_bytes<'a>(
        &'a self,
        key: &'a str,
        value: Bytes,
        ttl: Duration,
    ) -> BoxFuture<'a, Result<(), DistributedStoreError>>;

    /// Deletes `key` if present.
    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), DistributedStoreError>>;
}

#[derive(Debug, Clone)]
enum MemoryValue {
    Counter(i64),
    Blob(Bytes),
}

#[derive(Debug, Clone)]
struct MemoryEntry {
    value: MemoryValue,
    expires_at: Option<Duration>,
}

impl MemoryEntry {
    fn as_counter(&self) -> i64 {
        match self.value {
            MemoryValue::Counter(v) => v,
            MemoryValue::Blob(_) => 0,
        }
    }
}

/// Deterministic in-memory [`DistributedStore`] implementation useful for unit/multi-replica
/// testing without an external server.
#[derive(Debug)]
pub struct InMemoryDistributedStore {
    entries: Mutex<HashMap<String, MemoryEntry>>,
    clock: Arc<dyn Clock>,
    failure_policy: FailurePolicy,
}

impl Default for InMemoryDistributedStore {
    fn default() -> Self {
        Self::new(SystemClock::shared(), FailurePolicy::FailOpen)
    }
}

impl InMemoryDistributedStore {
    pub fn new(clock: Arc<dyn Clock>, failure_policy: FailurePolicy) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            clock,
            failure_policy,
        }
    }

    fn prune_expired(map: &mut HashMap<String, MemoryEntry>, now: Duration) {
        map.retain(|_, e| e.expires_at.map(|exp| now < exp).unwrap_or(true));
    }
}

impl DistributedStore for InMemoryDistributedStore {
    fn backend_name(&self) -> &str {
        "in_memory_distributed"
    }

    fn failure_policy(&self) -> FailurePolicy {
        self.failure_policy
    }

    fn try_consume_quota<'a>(
        &'a self,
        key: &'a str,
        amount: u64,
        limit: u64,
        window: Duration,
    ) -> BoxFuture<'a, Result<QuotaOutcome, DistributedStoreError>> {
        let now = self.clock.now();
        let mut map = self
            .entries
            .lock()
            .expect("InMemoryDistributedStore lock poisoned");
        Self::prune_expired(&mut map, now);

        let cur = map
            .get(key)
            .map(|e| e.as_counter().max(0) as u64)
            .unwrap_or(0);

        let outcome = if cur.saturating_add(amount) <= limit {
            let next = cur.saturating_add(amount);
            let next_i64 = next.min(i64::MAX as u64) as i64;
            let expires_at = map
                .get(key)
                .and_then(|e| e.expires_at)
                .unwrap_or_else(|| now.saturating_add(window));
            map.insert(
                key.to_owned(),
                MemoryEntry {
                    value: MemoryValue::Counter(next_i64),
                    expires_at: Some(expires_at),
                },
            );
            QuotaOutcome {
                allowed: true,
                current: next,
                limit,
                remaining: limit.saturating_sub(next),
                retry_after_secs: 0,
            }
        } else {
            let rem_dur = map
                .get(key)
                .and_then(|e| e.expires_at)
                .map(|exp| exp.saturating_sub(now))
                .unwrap_or(window);
            let retry_after_secs = rem_dur.as_millis().div_ceil(1000).max(1) as u64;
            QuotaOutcome {
                allowed: false,
                current: cur,
                limit,
                remaining: limit.saturating_sub(cur),
                retry_after_secs,
            }
        };

        Box::pin(async move { Ok(outcome) })
    }

    fn adjust_counter<'a>(
        &'a self,
        key: &'a str,
        delta: i64,
        ttl: Duration,
    ) -> BoxFuture<'a, Result<i64, DistributedStoreError>> {
        let now = self.clock.now();
        let mut map = self
            .entries
            .lock()
            .expect("InMemoryDistributedStore lock poisoned");
        Self::prune_expired(&mut map, now);

        let (cur, existing_exp) = map
            .get(key)
            .map(|e| (e.as_counter(), e.expires_at))
            .unwrap_or((0, None));
        let next = cur.saturating_add(delta).max(0);
        let expires_at = existing_exp.or_else(|| Some(now.saturating_add(ttl)));
        map.insert(
            key.to_owned(),
            MemoryEntry {
                value: MemoryValue::Counter(next),
                expires_at,
            },
        );
        Box::pin(async move { Ok(next) })
    }

    fn get_counter<'a>(
        &'a self,
        key: &'a str,
    ) -> BoxFuture<'a, Result<i64, DistributedStoreError>> {
        let now = self.clock.now();
        let mut map = self
            .entries
            .lock()
            .expect("InMemoryDistributedStore lock poisoned");
        Self::prune_expired(&mut map, now);
        let val = map.get(key).map(MemoryEntry::as_counter).unwrap_or(0);
        Box::pin(async move { Ok(val) })
    }

    fn set_flag<'a>(
        &'a self,
        key: &'a str,
        ttl: Duration,
    ) -> BoxFuture<'a, Result<(), DistributedStoreError>> {
        let now = self.clock.now();
        let mut map = self
            .entries
            .lock()
            .expect("InMemoryDistributedStore lock poisoned");
        Self::prune_expired(&mut map, now);
        map.insert(
            key.to_owned(),
            MemoryEntry {
                value: MemoryValue::Counter(1),
                expires_at: Some(now.saturating_add(ttl)),
            },
        );
        Box::pin(async move { Ok(()) })
    }

    fn has_flag<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<bool, DistributedStoreError>> {
        let now = self.clock.now();
        let mut map = self
            .entries
            .lock()
            .expect("InMemoryDistributedStore lock poisoned");
        Self::prune_expired(&mut map, now);
        let present = map.contains_key(key);
        Box::pin(async move { Ok(present) })
    }

    fn get_bytes<'a>(
        &'a self,
        key: &'a str,
    ) -> BoxFuture<'a, Result<Option<Bytes>, DistributedStoreError>> {
        let now = self.clock.now();
        let mut map = self
            .entries
            .lock()
            .expect("InMemoryDistributedStore lock poisoned");
        Self::prune_expired(&mut map, now);
        let val = map.get(key).and_then(|e| match &e.value {
            MemoryValue::Blob(b) => Some(b.clone()),
            MemoryValue::Counter(_) => None,
        });
        Box::pin(async move { Ok(val) })
    }

    fn set_bytes<'a>(
        &'a self,
        key: &'a str,
        value: Bytes,
        ttl: Duration,
    ) -> BoxFuture<'a, Result<(), DistributedStoreError>> {
        let now = self.clock.now();
        let mut map = self
            .entries
            .lock()
            .expect("InMemoryDistributedStore lock poisoned");
        Self::prune_expired(&mut map, now);
        map.insert(
            key.to_owned(),
            MemoryEntry {
                value: MemoryValue::Blob(value),
                expires_at: Some(now.saturating_add(ttl)),
            },
        );
        Box::pin(async move { Ok(()) })
    }

    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), DistributedStoreError>> {
        let mut map = self
            .entries
            .lock()
            .expect("InMemoryDistributedStore lock poisoned");
        map.remove(key);
        Box::pin(async move { Ok(()) })
    }
}
