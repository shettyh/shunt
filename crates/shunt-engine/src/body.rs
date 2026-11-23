use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt;
use tokio::sync::mpsc;
use tokio::time::{Instant, Sleep};

use crate::error::CoreError;

/// Unified HTTP body type used across `shunt-engine`.
///
/// Routes without body hooks or timeouts use `Passthrough(Incoming)` directly with
/// zero buffering, zero channel hops, and zero extra tasks.
pub enum ShuntBody {
    Empty,
    Full(Option<Bytes>),
    Passthrough(hyper::body::Incoming),
    LimitedPassthrough(LimitedIncomingBody),
    IdleTimeout(IdleTimeoutBody<hyper::body::Incoming>),
    TrackedPassthrough(Box<TrackedPassthroughBody>),
    Channel(ChannelBody),
}

impl ShuntBody {
    #[inline]
    pub fn empty() -> Self {
        Self::Empty
    }

    #[inline]
    pub fn full(bytes: Bytes) -> Self {
        if bytes.is_empty() {
            Self::Empty
        } else {
            Self::Full(Some(bytes))
        }
    }

    #[inline]
    pub fn passthrough(incoming: hyper::body::Incoming) -> Self {
        Self::Passthrough(incoming)
    }

    #[inline]
    pub fn limited_passthrough(
        incoming: hyper::body::Incoming,
        max_bytes: usize,
        exceeded_flag: Arc<AtomicBool>,
    ) -> Self {
        Self::LimitedPassthrough(LimitedIncomingBody::new(incoming, max_bytes, exceeded_flag))
    }

    #[inline]
    pub fn with_idle_timeout(incoming: hyper::body::Incoming, timeout: Duration) -> Self {
        Self::IdleTimeout(IdleTimeoutBody::new(incoming, timeout))
    }

    #[inline]
    pub fn channel(rx: mpsc::Receiver<Result<Frame<Bytes>, CoreError>>) -> Self {
        Self::Channel(ChannelBody { rx })
    }
}

impl Body for ShuntBody {
    type Data = Bytes;
    type Error = CoreError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            ShuntBody::Empty => Poll::Ready(None),
            ShuntBody::Full(opt) => match opt.take() {
                Some(bytes) => Poll::Ready(Some(Ok(Frame::data(bytes)))),
                None => Poll::Ready(None),
            },
            ShuntBody::Passthrough(incoming) => match Pin::new(incoming).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => Poll::Ready(Some(Ok(frame))),
                Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(CoreError::Hyper(e)))),
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            },
            ShuntBody::LimitedPassthrough(body) => Pin::new(body).poll_frame(cx),
            ShuntBody::IdleTimeout(body) => Pin::new(body).poll_frame(cx),
            ShuntBody::TrackedPassthrough(body) => Pin::new(body.as_mut()).poll_frame(cx),
            ShuntBody::Channel(body) => Pin::new(body).poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            ShuntBody::Empty => true,
            ShuntBody::Full(opt) => opt.is_none(),
            ShuntBody::Passthrough(incoming) => incoming.is_end_stream(),
            ShuntBody::LimitedPassthrough(body) => body.is_end_stream(),
            ShuntBody::IdleTimeout(body) => body.is_end_stream(),
            ShuntBody::TrackedPassthrough(body) => body.is_end_stream(),
            ShuntBody::Channel(_) => false,
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            ShuntBody::Empty => SizeHint::with_exact(0),
            ShuntBody::Full(Some(b)) => SizeHint::with_exact(b.len() as u64),
            ShuntBody::Full(None) => SizeHint::with_exact(0),
            ShuntBody::Passthrough(incoming) => incoming.size_hint(),
            ShuntBody::LimitedPassthrough(body) => body.size_hint(),
            ShuntBody::IdleTimeout(body) => body.size_hint(),
            ShuntBody::TrackedPassthrough(body) => body.size_hint(),
            ShuntBody::Channel(_) => SizeHint::default(),
        }
    }
}

/// Zero-copy streaming body wrapper enforcing an upper bound on total forwarded bytes
/// without buffering the body or spawning an extra task.
pub struct LimitedIncomingBody {
    inner: hyper::body::Incoming,
    max_bytes: usize,
    bytes_read: usize,
    exceeded: bool,
    exceeded_flag: Arc<AtomicBool>,
}

impl LimitedIncomingBody {
    pub fn new(
        inner: hyper::body::Incoming,
        max_bytes: usize,
        exceeded_flag: Arc<AtomicBool>,
    ) -> Self {
        Self {
            inner,
            max_bytes,
            bytes_read: 0,
            exceeded: false,
            exceeded_flag,
        }
    }
}

impl Body for LimitedIncomingBody {
    type Data = Bytes;
    type Error = CoreError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.exceeded {
            return Poll::Ready(None);
        }
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    let next = self.bytes_read.saturating_add(data.len());
                    if next > self.max_bytes {
                        self.exceeded = true;
                        self.exceeded_flag.store(true, Ordering::Release);
                        return Poll::Ready(Some(Err(CoreError::BodyTooLarge(self.max_bytes))));
                    }
                    self.bytes_read = next;
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(CoreError::Hyper(e)))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.exceeded || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// Wraps an inner [`Body`] and aborts with [`CoreError::IdleChunkTimeout`] if the gap
/// between consecutive frames exceeds `idle_timeout`.
pub struct IdleTimeoutBody<B> {
    inner: B,
    idle_timeout: Duration,
    sleep: Pin<Box<Sleep>>,
}

impl<B> IdleTimeoutBody<B> {
    pub fn new(inner: B, idle_timeout: Duration) -> Self {
        Self {
            inner,
            idle_timeout,
            sleep: Box::pin(tokio::time::sleep(idle_timeout)),
        }
    }
}

impl<B> Body for IdleTimeoutBody<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<CoreError>,
{
    type Data = Bytes;
    type Error = CoreError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                let next_deadline = Instant::now() + self.idle_timeout;
                self.sleep.as_mut().reset(next_deadline);
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e.into()))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => match self.sleep.as_mut().poll(cx) {
                Poll::Ready(()) => {
                    Poll::Ready(Some(Err(CoreError::IdleChunkTimeout(self.idle_timeout))))
                }
                Poll::Pending => Poll::Pending,
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// Callback invoked once a passthrough stream finishes, errors, or is dropped mid-stream.
pub type StreamFinishCallback = Box<dyn FnOnce(u64, Option<String>, bool) + Send + 'static>;

enum TrackedInner {
    Direct(hyper::body::Incoming),
    Idle(IdleTimeoutBody<hyper::body::Incoming>),
}

/// Zero-copy passthrough wrapper that counts bytes and fires `on_complete` when the
/// stream ends or aborts (used only when `HookMask::ON_COMPLETE` is set without
/// `RESPONSE_BODY_STREAM`).
pub struct TrackedPassthroughBody {
    inner: TrackedInner,
    bytes_sent: u64,
    on_finish: Option<StreamFinishCallback>,
}

impl TrackedPassthroughBody {
    pub fn new(
        incoming: hyper::body::Incoming,
        idle_timeout: Option<Duration>,
        on_finish: StreamFinishCallback,
    ) -> Self {
        let inner = match idle_timeout {
            Some(dur) => TrackedInner::Idle(IdleTimeoutBody::new(incoming, dur)),
            None => TrackedInner::Direct(incoming),
        };
        Self {
            inner,
            bytes_sent: 0,
            on_finish: Some(on_finish),
        }
    }

    fn fire_finish(&mut self, error: Option<String>, aborted: bool) {
        if let Some(cb) = self.on_finish.take() {
            cb(self.bytes_sent, error, aborted);
        }
    }
}

impl Drop for TrackedPassthroughBody {
    fn drop(&mut self) {
        if self.on_finish.is_some() {
            if self.is_end_stream() {
                self.fire_finish(None, false);
            } else {
                self.fire_finish(
                    Some("downstream client disconnected mid-stream".to_owned()),
                    true,
                );
            }
        }
    }
}

impl Body for TrackedPassthroughBody {
    type Data = Bytes;
    type Error = CoreError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let polled = match &mut self.inner {
            TrackedInner::Direct(incoming) => match Pin::new(incoming).poll_frame(cx) {
                Poll::Ready(Some(Ok(f))) => Poll::Ready(Some(Ok(f))),
                Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(CoreError::Hyper(e)))),
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            },
            TrackedInner::Idle(idle) => Pin::new(idle).poll_frame(cx),
        };

        match polled {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    self.bytes_sent += data.len() as u64;
                }
                if self.is_end_stream() {
                    self.fire_finish(None, false);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(err))) => {
                self.fire_finish(Some(err.to_string()), true);
                Poll::Ready(Some(Err(err)))
            }
            Poll::Ready(None) => {
                self.fire_finish(None, false);
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        match &self.inner {
            TrackedInner::Direct(i) => i.is_end_stream(),
            TrackedInner::Idle(i) => i.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match &self.inner {
            TrackedInner::Direct(i) => i.size_hint(),
            TrackedInner::Idle(i) => i.size_hint(),
        }
    }
}

/// Backpressure-bounded channel-backed [`Body`] used for hooked streaming bodies.
pub struct ChannelBody {
    rx: mpsc::Receiver<Result<Frame<Bytes>, CoreError>>,
}

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = CoreError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.rx.poll_recv(cx)
    }
}

/// Buffers an incoming body up to `max_bytes`, failing immediately with
/// [`CoreError::BodyTooLarge`] if the size hint or streamed bytes exceed `max_bytes`.
pub async fn collect_body_limited(
    mut incoming: hyper::body::Incoming,
    max_bytes: usize,
) -> Result<Bytes, CoreError> {
    let hint = incoming.size_hint();
    if hint.lower() > max_bytes as u64 {
        return Err(CoreError::BodyTooLarge(max_bytes));
    }

    let initial_cap = (hint.lower() as usize).min(max_bytes).min(64 * 1024);
    let mut buf = BytesMut::with_capacity(initial_cap);

    while let Some(frame_res) = incoming.frame().await {
        let frame = frame_res.map_err(CoreError::Hyper)?;
        if let Some(data) = frame.data_ref() {
            if buf.len().saturating_add(data.len()) > max_bytes {
                return Err(CoreError::BodyTooLarge(max_bytes));
            }
            buf.extend_from_slice(data);
        }
    }

    Ok(buf.freeze())
}
