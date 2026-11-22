use std::io::{self, Write as _};
use std::sync::{Arc, Mutex};

use brotli::CompressorWriter;
use flate2::Compression;
use flate2::write::{DeflateEncoder, GzEncoder};
use serde::Deserialize;
use shunt_plugin_sdk::{
    BuildContext, Bytes, Flow, HeaderMap, HeaderValue, HookMask, HookResult, HttpPlugin, Method,
    PluginBuildError, PluginConfig, PluginFactory, RequestCtx, RequestHead, ResponseHead,
    StreamFlow, header,
};

/// Supported HTTP response content encodings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContentEncoding {
    Zstd,
    Br,
    Gzip,
    Deflate,
}

impl ContentEncoding {
    pub fn as_header_str(self) -> &'static str {
        match self {
            Self::Zstd => "zstd",
            Self::Br => "br",
            Self::Gzip => "gzip",
            Self::Deflate => "deflate",
        }
    }

    pub fn parse_token(tok: &str) -> Option<Self> {
        match tok.trim().to_ascii_lowercase().as_str() {
            "zstd" => Some(Self::Zstd),
            "br" => Some(Self::Br),
            "gzip" | "x-gzip" => Some(Self::Gzip),
            "deflate" => Some(Self::Deflate),
            _ => None,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct CompressionConfig {
    /// Enabled encodings in server preference order (default: `["zstd", "br", "gzip"]`).
    encodings: Vec<ContentEncoding>,
    /// Minimum known `Content-Length` required to compress (default: `1024` bytes).
    min_size_bytes: usize,
    /// Compression quality level (gzip/deflate: `1..=9`, brotli: `1..=11`, zstd: `1..=19`; default: `4`).
    level: u32,
    /// Optional explicit allowlist of compressible content-type prefixes.
    /// When empty, uses Shunt's built-in streaming-safe filter (compresses text, JSON, JS,
    /// XML, SVG, WASM, etc., while always skipping `text/event-stream`, images/video/audio,
    /// and pre-compressed archives).
    content_types: Vec<String>,
    /// Flush encoder state after every chunk for lower streaming latency (default: `false`).
    flush_chunks: bool,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            encodings: vec![
                ContentEncoding::Zstd,
                ContentEncoding::Br,
                ContentEncoding::Gzip,
            ],
            min_size_bytes: 1024,
            level: 4,
            content_types: Vec::new(),
            flush_chunks: false,
        }
    }
}

pub struct CompressionFactory;

impl PluginFactory for CompressionFactory {
    fn name(&self) -> &str {
        "compression"
    }

    fn build(
        &self,
        config: &PluginConfig,
        _ctx: &BuildContext,
    ) -> Result<Arc<dyn HttpPlugin>, PluginBuildError> {
        let cfg: CompressionConfig = config.deserialize(self.name())?;
        if cfg.encodings.is_empty() {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: "compression requires at least one entry in `encodings`".to_owned(),
            });
        }
        if cfg.level == 0 || cfg.level > 19 {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: format!(
                    "compression `level` must be between 1 and 19 (got {})",
                    cfg.level
                ),
            });
        }
        let content_types = cfg
            .content_types
            .into_iter()
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();

        Ok(Arc::new(CompressionPlugin {
            encodings: cfg.encodings,
            min_size_bytes: cfg.min_size_bytes,
            level: cfg.level,
            content_types,
            flush_chunks: cfg.flush_chunks,
        }))
    }
}

#[derive(Debug, Clone)]
struct NegotiatedEncoding(Option<ContentEncoding>);

#[derive(Clone, Default)]
struct DrainBuf(Arc<Mutex<Vec<u8>>>);

impl DrainBuf {
    fn take(&self) -> Vec<u8> {
        let mut g = self.0.lock().expect("compression buffer lock poisoned");
        std::mem::take(&mut *g)
    }
}

impl io::Write for DrainBuf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .expect("compression buffer lock poisoned")
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

enum StreamEncoder {
    Gzip(GzEncoder<DrainBuf>),
    Deflate(DeflateEncoder<DrainBuf>),
    Brotli(Box<CompressorWriter<DrainBuf>>),
    Zstd(zstd::stream::write::Encoder<'static, DrainBuf>),
}

impl StreamEncoder {
    fn new(encoding: ContentEncoding, level: u32, sink: DrainBuf) -> io::Result<Self> {
        match encoding {
            ContentEncoding::Gzip => Ok(Self::Gzip(GzEncoder::new(
                sink,
                Compression::new(level.clamp(1, 9)),
            ))),
            ContentEncoding::Deflate => Ok(Self::Deflate(DeflateEncoder::new(
                sink,
                Compression::new(level.clamp(1, 9)),
            ))),
            ContentEncoding::Br => Ok(Self::Brotli(Box::new(CompressorWriter::new(
                sink,
                4096,
                level.clamp(1, 11),
                22,
            )))),
            ContentEncoding::Zstd => {
                let enc = zstd::stream::write::Encoder::new(sink, level.clamp(1, 19) as i32)?;
                Ok(Self::Zstd(enc))
            }
        }
    }

    fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        match self {
            Self::Gzip(e) => e.write_all(data),
            Self::Deflate(e) => e.write_all(data),
            Self::Brotli(e) => e.write_all(data),
            Self::Zstd(e) => e.write_all(data),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Gzip(e) => e.flush(),
            Self::Deflate(e) => e.flush(),
            Self::Brotli(e) => e.flush(),
            Self::Zstd(e) => e.flush(),
        }
    }

    fn finish(self) -> io::Result<()> {
        match self {
            Self::Gzip(e) => {
                let _ = e.finish()?;
                Ok(())
            }
            Self::Deflate(e) => {
                let _ = e.finish()?;
                Ok(())
            }
            Self::Brotli(mut e) => {
                e.flush()?;
                drop(e);
                Ok(())
            }
            Self::Zstd(e) => {
                let _ = e.finish()?;
                Ok(())
            }
        }
    }
}

struct ActiveCompressorInner {
    encoder: Option<StreamEncoder>,
    sink: DrainBuf,
    flush_chunks: bool,
}

#[derive(Clone)]
struct ActiveCompressor(Arc<Mutex<ActiveCompressorInner>>);

impl ActiveCompressor {
    fn new(encoding: ContentEncoding, level: u32, flush_chunks: bool) -> io::Result<Self> {
        let sink = DrainBuf::default();
        let encoder = StreamEncoder::new(encoding, level, sink.clone())?;
        Ok(Self(Arc::new(Mutex::new(ActiveCompressorInner {
            encoder: Some(encoder),
            sink,
            flush_chunks,
        }))))
    }

    fn process_chunk(&self, input: &[u8], end_of_stream: bool) -> io::Result<Vec<u8>> {
        let mut guard = self.0.lock().expect("compression state lock poisoned");
        let flush_chunks = guard.flush_chunks;
        if !input.is_empty()
            && let Some(enc) = guard.encoder.as_mut()
        {
            enc.write_all(input)?;
            if flush_chunks {
                enc.flush()?;
            }
        }
        if end_of_stream && let Some(enc) = guard.encoder.take() {
            enc.finish()?;
        }
        Ok(guard.sink.take())
    }
}

/// Streaming-safe, SSE-aware HTTP response compression plugin (`zstd`, `br`, `gzip`, `deflate`).
pub struct CompressionPlugin {
    encodings: Vec<ContentEncoding>,
    min_size_bytes: usize,
    level: u32,
    content_types: Vec<String>,
    flush_chunks: bool,
}

impl CompressionPlugin {
    fn is_content_type_compressible(&self, content_type: Option<&str>) -> bool {
        let Some(raw) = content_type else {
            return false;
        };
        let mime = raw
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if mime.is_empty() {
            return false;
        }
        // Never compress SSE streams or multipart streams regardless of config.
        if mime == "text/event-stream" || mime.starts_with("multipart/") {
            return false;
        }

        if !self.content_types.is_empty() {
            return self
                .content_types
                .iter()
                .any(|allowed| mime == *allowed || mime.starts_with(allowed));
        }

        // Default streaming-safe heuristic: skip already-compressed media & archives.
        if mime.starts_with("image/") && mime != "image/svg+xml" {
            return false;
        }
        if mime.starts_with("video/") || mime.starts_with("audio/") {
            return false;
        }
        if matches!(
            mime.as_str(),
            "application/gzip"
                | "application/x-gzip"
                | "application/zip"
                | "application/zstd"
                | "application/x-bzip2"
                | "application/x-xz"
                | "application/x-7z-compressed"
                | "application/octet-stream"
                | "font/woff"
                | "font/woff2"
        ) {
            return false;
        }

        mime.starts_with("text/")
            || mime.contains("json")
            || mime.contains("xml")
            || mime.contains("javascript")
            || mime == "application/wasm"
            || mime == "application/x-www-form-urlencoded"
            || mime == "application/graphql"
    }
}

/// Negotiates the best [`ContentEncoding`] from an RFC 9110 `Accept-Encoding` header value
/// according to client q-values and server `supported` preference order.
pub fn negotiate_accept_encoding(
    accept_encoding: &str,
    supported: &[ContentEncoding],
) -> Option<ContentEncoding> {
    let mut explicit_q: Vec<(ContentEncoding, f32)> = Vec::new();
    let mut wildcard_q: Option<f32> = None;

    for item in accept_encoding.split(',') {
        let mut parts = item.split(';');
        let Some(raw_enc) = parts.next() else {
            continue;
        };
        let enc_str = raw_enc.trim();
        if enc_str.is_empty() {
            continue;
        }
        let mut q = 1.0f32;
        for param in parts {
            let p = param.trim();
            if let Some(q_val) = p.strip_prefix("q=").or_else(|| p.strip_prefix("Q="))
                && let Ok(parsed) = q_val.trim().parse::<f32>()
                && parsed.is_finite()
                && (0.0..=1.0).contains(&parsed)
            {
                q = parsed;
            }
        }
        if enc_str == "*" {
            wildcard_q = Some(q);
        } else if let Some(enc) = ContentEncoding::parse_token(enc_str) {
            explicit_q.push((enc, q));
        }
    }

    let mut best: Option<(ContentEncoding, f32)> = None;
    for &enc in supported {
        let score = explicit_q
            .iter()
            .rfind(|(e, _)| *e == enc)
            .map(|(_, q)| *q)
            .or(wildcard_q)
            .unwrap_or(0.0);
        if score <= 0.0 {
            continue;
        }
        let replace = match best {
            None => true,
            Some((_, best_q)) => score > best_q,
        };
        if replace {
            best = Some((enc, score));
        }
    }

    best.map(|(enc, _)| enc)
}

fn ensure_vary_accept_encoding(headers: &mut HeaderMap) {
    let already_present = headers.get_all(header::VARY).iter().any(|v| {
        v.to_str()
            .map(|s| {
                s.split(',').any(|tok| {
                    let t = tok.trim();
                    t == "*" || t.eq_ignore_ascii_case("accept-encoding")
                })
            })
            .unwrap_or(false)
    });
    if !already_present {
        headers.append(header::VARY, HeaderValue::from_static("Accept-Encoding"));
    }
}

fn weaken_etag_if_strong(headers: &mut HeaderMap) {
    let weakened = headers.get(header::ETAG).and_then(|v| {
        let s = v.to_str().ok()?.trim();
        if s.starts_with("W/") || s.starts_with("w/") {
            None
        } else {
            HeaderValue::from_str(&format!("W/{s}")).ok()
        }
    });
    if let Some(new_val) = weakened {
        headers.insert(header::ETAG, new_val);
    }
}

fn has_no_transform(headers: &HeaderMap) -> bool {
    headers.get_all(header::CACHE_CONTROL).iter().any(|v| {
        v.to_str()
            .map(|s| {
                s.split(',')
                    .any(|dir| dir.trim().eq_ignore_ascii_case("no-transform"))
            })
            .unwrap_or(false)
    })
}

fn has_existing_content_encoding(headers: &HeaderMap) -> bool {
    headers.get_all(header::CONTENT_ENCODING).iter().any(|v| {
        v.to_str()
            .map(|s| {
                s.split(',').any(|tok| {
                    let t = tok.trim();
                    !t.is_empty() && !t.eq_ignore_ascii_case("identity")
                })
            })
            .unwrap_or(true)
    })
}

impl HttpPlugin for CompressionPlugin {
    fn name(&self) -> &str {
        "compression"
    }

    fn hook_mask(&self) -> HookMask {
        HookMask::ON_REQUEST_HEADERS
            | HookMask::ON_RESPONSE_HEADERS
            | HookMask::RESPONSE_BODY_STREAM
    }

    fn on_request_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        req: &'a mut RequestHead,
    ) -> HookResult<'a, Flow> {
        if req.method == Method::HEAD {
            ctx.insert_ext(NegotiatedEncoding(None));
            return HookResult::Ready(Flow::Continue);
        }
        let chosen = req
            .headers
            .get(header::ACCEPT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| negotiate_accept_encoding(s, &self.encodings));
        ctx.insert_ext(NegotiatedEncoding(chosen));
        HookResult::Ready(Flow::Continue)
    }

    fn on_response_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        res: &'a mut ResponseHead,
    ) -> HookResult<'a, Flow> {
        // Skip status codes without a response body.
        if res.status.is_informational()
            || res.status == shunt_plugin_sdk::StatusCode::NO_CONTENT
            || res.status == shunt_plugin_sdk::StatusCode::NOT_MODIFIED
        {
            return HookResult::Ready(Flow::Continue);
        }

        if has_existing_content_encoding(&res.headers) || has_no_transform(&res.headers) {
            return HookResult::Ready(Flow::Continue);
        }

        let ct = res
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok());
        if !self.is_content_type_compressible(ct) {
            return HookResult::Ready(Flow::Continue);
        }

        // Content type is negotiable: always signal `Vary: Accept-Encoding` to downstream caches.
        ensure_vary_accept_encoding(&mut res.headers);

        let Some(NegotiatedEncoding(Some(encoding))) = ctx.get_ext::<NegotiatedEncoding>().cloned()
        else {
            return HookResult::Ready(Flow::Continue);
        };

        if let Some(cl) = res
            .headers
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<usize>().ok())
            && cl < self.min_size_bytes
        {
            return HookResult::Ready(Flow::Continue);
        }

        let Ok(compressor) = ActiveCompressor::new(encoding, self.level, self.flush_chunks) else {
            return HookResult::Ready(Flow::Continue);
        };

        res.headers.insert(
            header::CONTENT_ENCODING,
            HeaderValue::from_static(encoding.as_header_str()),
        );
        res.headers.remove(header::CONTENT_LENGTH);
        res.headers.remove(header::ACCEPT_RANGES);
        weaken_etag_if_strong(&mut res.headers);
        ctx.annotate_str("http.response.compression", encoding.as_header_str());
        ctx.insert_ext(compressor);

        HookResult::Ready(Flow::Continue)
    }

    fn on_response_body_chunk<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        chunk: &'a mut Bytes,
        end_of_stream: bool,
    ) -> HookResult<'a, StreamFlow> {
        let Some(compressor) = ctx.get_ext::<ActiveCompressor>().cloned() else {
            return HookResult::Ready(StreamFlow::Continue);
        };

        match compressor.process_chunk(chunk, end_of_stream) {
            Ok(out) => {
                *chunk = Bytes::from(out);
                HookResult::Ready(StreamFlow::Continue)
            }
            Err(e) => HookResult::Ready(StreamFlow::Abort(format!(
                "response compression failed: {e}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read as _;

    use super::*;

    #[test]
    fn accept_encoding_negotiation_respects_q_values_and_server_order() {
        let supported = [
            ContentEncoding::Zstd,
            ContentEncoding::Br,
            ContentEncoding::Gzip,
        ];
        assert_eq!(
            negotiate_accept_encoding("gzip, deflate, br", &supported),
            Some(ContentEncoding::Br)
        );
        assert_eq!(
            negotiate_accept_encoding("gzip;q=0.9, br;q=0.5", &supported),
            Some(ContentEncoding::Gzip)
        );
        assert_eq!(
            negotiate_accept_encoding("zstd;q=0, br;q=0, gzip;q=1.0", &supported),
            Some(ContentEncoding::Gzip)
        );
        assert_eq!(negotiate_accept_encoding("identity", &supported), None);
        assert_eq!(
            negotiate_accept_encoding("*;q=0.5, zstd;q=0", &supported),
            Some(ContentEncoding::Br)
        );
    }

    #[test]
    fn streaming_encoders_round_trip_cleanly() {
        let payload = "hello shunt gateway compression world! ".repeat(200);
        let chunks = [
            &payload.as_bytes()[..120],
            &payload.as_bytes()[120..900],
            &payload.as_bytes()[900..],
        ];

        for encoding in [
            ContentEncoding::Gzip,
            ContentEncoding::Deflate,
            ContentEncoding::Br,
            ContentEncoding::Zstd,
        ] {
            let comp = ActiveCompressor::new(encoding, 4, false).unwrap();
            let mut compressed = Vec::new();
            for c in &chunks {
                compressed.extend_from_slice(&comp.process_chunk(c, false).unwrap());
            }
            compressed.extend_from_slice(&comp.process_chunk(&[], true).unwrap());
            assert!(
                compressed.len() < payload.len(),
                "{encoding:?} did not shrink repetitive payload"
            );

            let mut decoded = Vec::new();
            match encoding {
                ContentEncoding::Gzip => {
                    flate2::read::GzDecoder::new(&compressed[..])
                        .read_to_end(&mut decoded)
                        .unwrap();
                }
                ContentEncoding::Deflate => {
                    flate2::read::DeflateDecoder::new(&compressed[..])
                        .read_to_end(&mut decoded)
                        .unwrap();
                }
                ContentEncoding::Br => {
                    brotli::Decompressor::new(&compressed[..], 4096)
                        .read_to_end(&mut decoded)
                        .unwrap();
                }
                ContentEncoding::Zstd => {
                    zstd::stream::read::Decoder::new(&compressed[..])
                        .unwrap()
                        .read_to_end(&mut decoded)
                        .unwrap();
                }
            }
            assert_eq!(
                decoded,
                payload.as_bytes(),
                "round-trip mismatch for {encoding:?}"
            );
        }
    }
}
