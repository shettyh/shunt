/// A single parsed Server-Sent Events (SSE) frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    pub event: Option<String>,
    pub data: String,
}

const UTF8_BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];

/// Incremental WHATWG-compliant SSE parser that handles arbitrary chunk splits
/// (including 1-byte splits across CRLF, bare CR, UTF-8 BOM, and multi-byte UTF-8),
/// comments, multi-line `data:` payloads, and EOF flushing.
#[derive(Debug, Clone, Default)]
pub struct SseParser {
    bom_checked: bool,
    bom_buf: Vec<u8>,
    skip_next_lf: bool,
    line_buf: Vec<u8>,
    event_type: Option<String>,
    data_lines: Vec<String>,
}

impl SseParser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds raw bytes from an incoming stream chunk and returns any complete SSE events.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<SseEvent> {
        let mut events = Vec::new();
        if bytes.is_empty() {
            return events;
        }

        let mut slice = bytes;

        // Strip a single optional leading UTF-8 BOM (0xEF 0xBB 0xBF), preserving exact
        // chunk-split invariance even when the 3 BOM bytes arrive across separate chunks.
        if !self.bom_checked {
            while !slice.is_empty() && self.bom_buf.len() < UTF8_BOM.len() {
                let next_byte = slice[0];
                if next_byte == UTF8_BOM[self.bom_buf.len()] {
                    self.bom_buf.push(next_byte);
                    slice = &slice[1..];
                    if self.bom_buf.len() == UTF8_BOM.len() {
                        // Complete BOM matched -> discard and continue with remaining bytes.
                        self.bom_buf.clear();
                        self.bom_checked = true;
                        break;
                    }
                } else {
                    // Prefix did not match BOM -> replay buffered prefix bytes normally.
                    self.bom_checked = true;
                    let prefix = std::mem::take(&mut self.bom_buf);
                    self.feed_bytes(&prefix, &mut events);
                    break;
                }
            }
            if !self.bom_checked {
                // Still collecting a potential 1-2 byte BOM prefix.
                return events;
            }
        }

        if !slice.is_empty() {
            self.feed_bytes(slice, &mut events);
        }

        events
    }

    /// Flushes any trailing partial line and buffered event when the stream reaches EOF.
    pub fn finish(&mut self) -> Vec<SseEvent> {
        let mut events = Vec::new();

        // If stream ended with a 1-2 byte partial BOM prefix, treat those bytes as normal input.
        if !self.bom_checked {
            self.bom_checked = true;
            let prefix = std::mem::take(&mut self.bom_buf);
            if !prefix.is_empty() {
                self.feed_bytes(&prefix, &mut events);
            }
        }

        if !self.line_buf.is_empty() {
            let trailing = std::mem::take(&mut self.line_buf);
            let line = String::from_utf8_lossy(&trailing).into_owned();
            if let Some(ev) = self.process_line(&line) {
                events.push(ev);
            }
        }
        if let Some(ev) = self.flush_event() {
            events.push(ev);
        }
        events
    }

    fn feed_bytes(&mut self, bytes: &[u8], events: &mut Vec<SseEvent>) {
        for &b in bytes {
            if self.skip_next_lf {
                self.skip_next_lf = false;
                if b == b'\n' {
                    continue;
                }
            }

            if b == b'\r' {
                let line = String::from_utf8_lossy(&self.line_buf).into_owned();
                self.line_buf.clear();
                self.skip_next_lf = true;
                if let Some(ev) = self.process_line(&line) {
                    events.push(ev);
                }
            } else if b == b'\n' {
                let line = String::from_utf8_lossy(&self.line_buf).into_owned();
                self.line_buf.clear();
                if let Some(ev) = self.process_line(&line) {
                    events.push(ev);
                }
            } else {
                self.line_buf.push(b);
            }
        }
    }

    fn process_line(&mut self, line: &str) -> Option<SseEvent> {
        if line.is_empty() {
            return self.flush_event();
        }
        if line.starts_with(':') {
            // SSE comment / heartbeat
            return None;
        }

        let (field, raw_val) = match line.split_once(':') {
            Some((f, v)) => (f, v.strip_prefix(' ').unwrap_or(v)),
            None => (line, ""),
        };

        match field {
            "event" => {
                self.event_type = Some(raw_val.to_owned());
            }
            "data" => {
                self.data_lines.push(raw_val.to_owned());
            }
            _ => {}
        }

        None
    }

    /// WHATWG §9.2.6: If no `data:` lines were accumulated, discard the event (and clear
    /// any pending `event:` type) without dispatching.
    fn flush_event(&mut self) -> Option<SseEvent> {
        if self.data_lines.is_empty() {
            self.event_type = None;
            return None;
        }
        let event = self.event_type.take();
        let data = self.data_lines.join("\n");
        self.data_lines.clear();
        Some(SseEvent { event, data })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_arbitrarily_split_chunks_one_byte_at_a_time() {
        let raw = concat!(
            ": heartbeat\n",
            "event: message_start\r\n",
            "data: {\"type\":\"message_start\"}\r\n",
            "\r\n",
            "event: content_block_delta\n",
            "data: {\"a\":1}\n",
            "data: {\"b\":2}\n",
            "\n",
            "data: [DONE]"
        );

        let mut parser = SseParser::new();
        let mut events = Vec::new();
        for b in raw.as_bytes() {
            events.extend(parser.push(&[*b]));
        }
        events.extend(parser.finish());

        assert_eq!(events.len(), 3);
        assert_eq!(events[0].event.as_deref(), Some("message_start"));
        assert_eq!(events[0].data, r#"{"type":"message_start"}"#);

        assert_eq!(events[1].event.as_deref(), Some("content_block_delta"));
        assert_eq!(events[1].data, "{\"a\":1}\n{\"b\":2}");

        assert_eq!(events[2].event, None);
        assert_eq!(events[2].data, "[DONE]");
    }

    #[test]
    fn whatwg_bom_bare_cr_and_event_only_discard() {
        let mut raw = vec![0xEF, 0xBB, 0xBF];
        raw.extend_from_slice(
            b"event: ignored_no_data\r\rdata: first\r\revent: custom\rdata: line1\rdata: line2\r\n\r\n",
        );

        // Whole parse
        let mut whole = SseParser::new();
        let mut whole_events = whole.push(&raw);
        whole_events.extend(whole.finish());

        // 1-byte chunk parse
        let mut chunked = SseParser::new();
        let mut chunked_events = Vec::new();
        for b in &raw {
            chunked_events.extend(chunked.push(&[*b]));
        }
        chunked_events.extend(chunked.finish());

        assert_eq!(whole_events, chunked_events);
        assert_eq!(whole_events.len(), 2);
        // First frame had no data:, so event: ignored_no_data was discarded & cleared!
        assert_eq!(whole_events[0].event, None);
        assert_eq!(whole_events[0].data, "first");
        assert_eq!(whole_events[1].event.as_deref(), Some("custom"));
        assert_eq!(whole_events[1].data, "line1\nline2");
    }
}
