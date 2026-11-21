//! Pure-Rust incremental binary codec for AWS `application/vnd.amazon.eventstream`.
//!
//! Validates IEEE 802.3 CRC32 checksums on both the 12-byte prelude and trailing 4-byte
//! message CRC, supports arbitrary TCP chunk splitting (including 1-byte splits), and
//! never panics on malformed or truncated frames.

use std::collections::BTreeMap;

/// Maximum single EventStream frame size accepted by the decoder (16 MiB).
const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;
const PRELUDE_LEN: usize = 12;
const MESSAGE_OVERHEAD: usize = 16; // 12-byte prelude + 4-byte trailing message CRC

/// Standard IEEE 802.3 CRC32 lookup table (reflected polynomial `0xEDB88320`).
const CRC32_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut c = i as u32;
        let mut j = 0;
        while j < 8 {
            if c & 1 != 0 {
                c = 0xEDB8_8320 ^ (c >> 1);
            } else {
                c >>= 1;
            }
            j += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
};

/// Computes IEEE 802.3 CRC32 (`0xEDB88320`) over `bytes`.
pub fn crc32_ieee(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in bytes {
        let idx = ((crc ^ (b as u32)) & 0xFF) as usize;
        crc = CRC32_TABLE[idx] ^ (crc >> 8);
    }
    !crc
}

/// Decoded typed AWS EventStream header value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventStreamHeaderValue {
    Bool(bool),
    Int8(i8),
    Int16(i16),
    Int32(i32),
    Int64(i64),
    Bytes(Vec<u8>),
    String(String),
    Timestamp(i64),
    Uuid([u8; 16]),
}

impl EventStreamHeaderValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            EventStreamHeaderValue::String(s) => Some(s.as_str()),
            _ => None,
        }
    }
}

/// A single decoded AWS EventStream binary message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventStreamMessage {
    pub headers: BTreeMap<String, EventStreamHeaderValue>,
    pub payload: Vec<u8>,
}

impl EventStreamMessage {
    pub fn header_str(&self, name: &str) -> Option<&str> {
        self.headers
            .get(name)
            .and_then(EventStreamHeaderValue::as_str)
    }

    pub fn message_type(&self) -> Option<&str> {
        self.header_str(":message-type")
    }

    pub fn event_type(&self) -> Option<&str> {
        self.header_str(":event-type")
    }

    pub fn exception_type(&self) -> Option<&str> {
        self.header_str(":exception-type")
    }
}

/// Errors returned when decoding malformed AWS EventStream frames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventStreamError {
    InvalidTotalLength(usize),
    InvalidHeadersLength {
        headers_len: usize,
        total_len: usize,
    },
    PreludeCrcMismatch {
        expected: u32,
        actual: u32,
    },
    MessageCrcMismatch {
        expected: u32,
        actual: u32,
    },
    MalformedHeaders(String),
}

impl std::fmt::Display for EventStreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventStreamError::InvalidTotalLength(len) => {
                write!(f, "invalid EventStream total_length: {len}")
            }
            EventStreamError::InvalidHeadersLength {
                headers_len,
                total_len,
            } => write!(
                f,
                "invalid EventStream headers_length ({headers_len}) for total_length ({total_len})"
            ),
            EventStreamError::PreludeCrcMismatch { expected, actual } => {
                write!(
                    f,
                    "EventStream prelude CRC32 mismatch (expected {expected:#010x}, actual {actual:#010x})"
                )
            }
            EventStreamError::MessageCrcMismatch { expected, actual } => {
                write!(
                    f,
                    "EventStream message CRC32 mismatch (expected {expected:#010x}, actual {actual:#010x})"
                )
            }
            EventStreamError::MalformedHeaders(msg) => {
                write!(f, "malformed EventStream headers: {msg}")
            }
        }
    }
}

impl std::error::Error for EventStreamError {}

/// Incremental decoder for `application/vnd.amazon.eventstream` binary streams.
#[derive(Debug, Clone, Default)]
pub struct AwsEventStreamDecoder {
    buf: Vec<u8>,
}

impl AwsEventStreamDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds arbitrary incoming bytes and returns all complete decoded frames.
    ///
    /// Returns `Err` immediately on CRC mismatch or invalid header framing (and clears the
    /// corrupt buffer so subsequent calls never loop indefinitely).
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<EventStreamMessage>, EventStreamError> {
        if !chunk.is_empty() {
            self.buf.extend_from_slice(chunk);
        }

        let mut messages = Vec::new();

        loop {
            if self.buf.len() < PRELUDE_LEN {
                break;
            }

            let total_len =
                u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize;
            let headers_len =
                u32::from_be_bytes([self.buf[4], self.buf[5], self.buf[6], self.buf[7]]) as usize;
            let expected_prelude_crc =
                u32::from_be_bytes([self.buf[8], self.buf[9], self.buf[10], self.buf[11]]);

            let actual_prelude_crc = crc32_ieee(&self.buf[0..8]);
            if actual_prelude_crc != expected_prelude_crc {
                self.buf.clear();
                return Err(EventStreamError::PreludeCrcMismatch {
                    expected: expected_prelude_crc,
                    actual: actual_prelude_crc,
                });
            }

            if !(MESSAGE_OVERHEAD..=MAX_FRAME_LEN).contains(&total_len) {
                self.buf.clear();
                return Err(EventStreamError::InvalidTotalLength(total_len));
            }
            if headers_len > total_len - MESSAGE_OVERHEAD {
                self.buf.clear();
                return Err(EventStreamError::InvalidHeadersLength {
                    headers_len,
                    total_len,
                });
            }

            if self.buf.len() < total_len {
                // Wait for remaining bytes of this frame.
                break;
            }

            let msg_crc_offset = total_len - 4;
            let expected_msg_crc = u32::from_be_bytes([
                self.buf[msg_crc_offset],
                self.buf[msg_crc_offset + 1],
                self.buf[msg_crc_offset + 2],
                self.buf[msg_crc_offset + 3],
            ]);
            let actual_msg_crc = crc32_ieee(&self.buf[0..msg_crc_offset]);
            if actual_msg_crc != expected_msg_crc {
                self.buf.clear();
                return Err(EventStreamError::MessageCrcMismatch {
                    expected: expected_msg_crc,
                    actual: actual_msg_crc,
                });
            }

            let headers_slice = &self.buf[PRELUDE_LEN..PRELUDE_LEN + headers_len];
            let headers = match parse_headers(headers_slice) {
                Ok(h) => h,
                Err(e) => {
                    self.buf.clear();
                    return Err(e);
                }
            };
            let payload = self.buf[PRELUDE_LEN + headers_len..msg_crc_offset].to_vec();

            self.buf.drain(..total_len);
            messages.push(EventStreamMessage { headers, payload });
        }

        Ok(messages)
    }

    /// Returns the number of buffered trailing bytes awaiting completion.
    pub fn buffered_len(&self) -> usize {
        self.buf.len()
    }
}

fn parse_headers(
    bytes: &[u8],
) -> Result<BTreeMap<String, EventStreamHeaderValue>, EventStreamError> {
    let mut headers = BTreeMap::new();
    let mut idx = 0usize;

    while idx < bytes.len() {
        let name_len = bytes[idx] as usize;
        idx += 1;
        if idx + name_len + 1 > bytes.len() {
            return Err(EventStreamError::MalformedHeaders(
                "truncated header name or type".to_owned(),
            ));
        }
        let name = String::from_utf8_lossy(&bytes[idx..idx + name_len]).into_owned();
        idx += name_len;

        let value_type = bytes[idx];
        idx += 1;

        let val = match value_type {
            0 => EventStreamHeaderValue::Bool(true),
            1 => EventStreamHeaderValue::Bool(false),
            2 => {
                if idx + 1 > bytes.len() {
                    return Err(EventStreamError::MalformedHeaders("truncated i8".into()));
                }
                let v = bytes[idx] as i8;
                idx += 1;
                EventStreamHeaderValue::Int8(v)
            }
            3 => {
                if idx + 2 > bytes.len() {
                    return Err(EventStreamError::MalformedHeaders("truncated i16".into()));
                }
                let v = i16::from_be_bytes([bytes[idx], bytes[idx + 1]]);
                idx += 2;
                EventStreamHeaderValue::Int16(v)
            }
            4 => {
                if idx + 4 > bytes.len() {
                    return Err(EventStreamError::MalformedHeaders("truncated i32".into()));
                }
                let v = i32::from_be_bytes([
                    bytes[idx],
                    bytes[idx + 1],
                    bytes[idx + 2],
                    bytes[idx + 3],
                ]);
                idx += 4;
                EventStreamHeaderValue::Int32(v)
            }
            5 => {
                if idx + 8 > bytes.len() {
                    return Err(EventStreamError::MalformedHeaders("truncated i64".into()));
                }
                let v = i64::from_be_bytes([
                    bytes[idx],
                    bytes[idx + 1],
                    bytes[idx + 2],
                    bytes[idx + 3],
                    bytes[idx + 4],
                    bytes[idx + 5],
                    bytes[idx + 6],
                    bytes[idx + 7],
                ]);
                idx += 8;
                EventStreamHeaderValue::Int64(v)
            }
            6 => {
                if idx + 2 > bytes.len() {
                    return Err(EventStreamError::MalformedHeaders(
                        "truncated bytes length".into(),
                    ));
                }
                let len = u16::from_be_bytes([bytes[idx], bytes[idx + 1]]) as usize;
                idx += 2;
                if idx + len > bytes.len() {
                    return Err(EventStreamError::MalformedHeaders(
                        "truncated bytes value".into(),
                    ));
                }
                let v = bytes[idx..idx + len].to_vec();
                idx += len;
                EventStreamHeaderValue::Bytes(v)
            }
            7 => {
                if idx + 2 > bytes.len() {
                    return Err(EventStreamError::MalformedHeaders(
                        "truncated string length".into(),
                    ));
                }
                let len = u16::from_be_bytes([bytes[idx], bytes[idx + 1]]) as usize;
                idx += 2;
                if idx + len > bytes.len() {
                    return Err(EventStreamError::MalformedHeaders(
                        "truncated string value".into(),
                    ));
                }
                let v = String::from_utf8_lossy(&bytes[idx..idx + len]).into_owned();
                idx += len;
                EventStreamHeaderValue::String(v)
            }
            8 => {
                if idx + 8 > bytes.len() {
                    return Err(EventStreamError::MalformedHeaders(
                        "truncated timestamp".into(),
                    ));
                }
                let v = i64::from_be_bytes([
                    bytes[idx],
                    bytes[idx + 1],
                    bytes[idx + 2],
                    bytes[idx + 3],
                    bytes[idx + 4],
                    bytes[idx + 5],
                    bytes[idx + 6],
                    bytes[idx + 7],
                ]);
                idx += 8;
                EventStreamHeaderValue::Timestamp(v)
            }
            9 => {
                if idx + 16 > bytes.len() {
                    return Err(EventStreamError::MalformedHeaders("truncated uuid".into()));
                }
                let mut uuid = [0u8; 16];
                uuid.copy_from_slice(&bytes[idx..idx + 16]);
                idx += 16;
                EventStreamHeaderValue::Uuid(uuid)
            }
            other => {
                return Err(EventStreamError::MalformedHeaders(format!(
                    "unknown header value type {other}"
                )));
            }
        };

        headers.insert(name, val);
    }

    Ok(headers)
}

/// Encodes string headers + raw payload into a CRC32-verified binary AWS EventStream frame.
///
/// Used by tests and `shunt-test` mock upstreams to produce wire-accurate Bedrock streams.
pub fn encode_eventstream_frame(headers: &[(&str, &str)], payload: &[u8]) -> Vec<u8> {
    let mut headers_buf = Vec::new();
    for &(name, val) in headers {
        let name_bytes = name.as_bytes();
        let val_bytes = val.as_bytes();
        debug_assert!(name_bytes.len() <= u8::MAX as usize);
        debug_assert!(val_bytes.len() <= u16::MAX as usize);
        headers_buf.push(name_bytes.len() as u8);
        headers_buf.extend_from_slice(name_bytes);
        headers_buf.push(7u8); // String type
        headers_buf.extend_from_slice(&(val_bytes.len() as u16).to_be_bytes());
        headers_buf.extend_from_slice(val_bytes);
    }

    let headers_len = headers_buf.len() as u32;
    let total_len = (MESSAGE_OVERHEAD + headers_buf.len() + payload.len()) as u32;

    let mut frame = Vec::with_capacity(total_len as usize);
    frame.extend_from_slice(&total_len.to_be_bytes());
    frame.extend_from_slice(&headers_len.to_be_bytes());
    let prelude_crc = crc32_ieee(&frame[0..8]);
    frame.extend_from_slice(&prelude_crc.to_be_bytes());
    frame.extend_from_slice(&headers_buf);
    frame.extend_from_slice(payload);
    let msg_crc = crc32_ieee(&frame);
    frame.extend_from_slice(&msg_crc.to_be_bytes());
    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_ieee_matches_standard_check_value() {
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn roundtrips_multi_frame_stream_across_one_byte_splits() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&encode_eventstream_frame(
            &[
                (":message-type", "event"),
                (":event-type", "messageStart"),
                (":content-type", "application/json"),
            ],
            br#"{"role":"assistant"}"#,
        ));
        wire.extend_from_slice(&encode_eventstream_frame(
            &[
                (":message-type", "event"),
                (":event-type", "contentBlockDelta"),
            ],
            br#"{"contentBlockIndex":0,"delta":{"text":"hello"}}"#,
        ));

        let mut whole_dec = AwsEventStreamDecoder::new();
        let whole_msgs = whole_dec.push(&wire).unwrap();
        assert_eq!(whole_dec.buffered_len(), 0);
        assert_eq!(whole_msgs.len(), 2);
        assert_eq!(whole_msgs[0].message_type(), Some("event"));
        assert_eq!(whole_msgs[0].event_type(), Some("messageStart"));
        assert_eq!(whole_msgs[0].payload, br#"{"role":"assistant"}"#);
        assert_eq!(whole_msgs[1].event_type(), Some("contentBlockDelta"));

        let mut byte_dec = AwsEventStreamDecoder::new();
        let mut byte_msgs = Vec::new();
        for &b in &wire {
            byte_msgs.extend(byte_dec.push(&[b]).unwrap());
        }
        assert_eq!(byte_dec.buffered_len(), 0);
        assert_eq!(byte_msgs, whole_msgs);
    }

    #[test]
    fn detects_corrupt_prelude_and_message_crc() {
        let mut frame = encode_eventstream_frame(&[(":message-type", "event")], b"{}");
        let mut bad_prelude = frame.clone();
        bad_prelude[9] ^= 0xFF;
        let mut dec = AwsEventStreamDecoder::new();
        assert!(matches!(
            dec.push(&bad_prelude),
            Err(EventStreamError::PreludeCrcMismatch { .. })
        ));

        let last = frame.len() - 1;
        frame[last] ^= 0x01;
        let mut dec2 = AwsEventStreamDecoder::new();
        assert!(matches!(
            dec2.push(&frame),
            Err(EventStreamError::MessageCrcMismatch { .. })
        ));
    }
}
