use std::any::Any;
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::task::{Context, Poll};

use pin_project_lite::pin_project;
use shunt_plugin_sdk::HookResult;

/// Extracts a human-readable message from a panic payload.
pub fn panic_payload_to_string(payload: Box<dyn Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_owned()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "non-string panic payload".to_owned()
    }
}

/// Executes a synchronous closure while catching any unwind panic.
#[inline]
pub fn catch_sync<F, R>(f: F) -> Result<R, String>
where
    F: FnOnce() -> R,
{
    catch_unwind(AssertUnwindSafe(f)).map_err(panic_payload_to_string)
}

pin_project! {
    /// Lightweight future wrapper that catches unwind panics on every `poll`.
    pub struct CatchUnwindFuture<F> {
        #[pin]
        inner: F,
    }
}

impl<F> CatchUnwindFuture<F> {
    #[inline]
    pub fn new(inner: F) -> Self {
        Self { inner }
    }
}

impl<F: Future> Future for CatchUnwindFuture<F> {
    type Output = Result<F::Output, String>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        match catch_unwind(AssertUnwindSafe(|| this.inner.poll(cx))) {
            Ok(Poll::Ready(output)) => Poll::Ready(Ok(output)),
            Ok(Poll::Pending) => Poll::Pending,
            Err(payload) => Poll::Ready(Err(panic_payload_to_string(payload))),
        }
    }
}

/// Runs a hook invocation (sync fast-path or async future) with full panic isolation.
#[inline]
pub async fn run_hook_isolated<'a, T, F>(invoke: F) -> Result<T, String>
where
    F: FnOnce() -> HookResult<'a, T>,
{
    match catch_sync(invoke)? {
        HookResult::Ready(val) => Ok(val),
        HookResult::Pending(fut) => CatchUnwindFuture::new(fut).await,
    }
}
