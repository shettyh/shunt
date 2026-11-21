/// A single parsed Server-Sent Events (SSE) frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    pub event: Option<String>,
    pub data: String,
}

/// Incremental WHATWG-compliant SSE parser that handles arbitrary chunk splits,
/// CRLF / LF line endings, comments, multi-line `data:` payloads, and EOF flushing.
#[derive(Debug, Clone, Default)]
pub struct SseParser {
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
        self.line_buf.extend_from_slice(bytes);

        let mut start = 0;
        while let Some(rel_nl) = self.line_buf[start..].iter().position(|&b| b == b'\n') {
            let nl_idx = start + rel_nl;
            let mut line_slice = &self.line_buf[start..nl_idx];
            if line_slice.ends_with(b"\r") {
                line_slice = &line_slice[..line_slice.len() - 1];
            }
            let line = String::from_utf8_lossy(line_slice).into_owned();
            if let Some(ev) = self.process_line(&line) {
                events.push(ev);
            }
            start = nl_idx + 1;
        }

        if start > 0 {
            self.line_buf.drain(..start);
        }

        events
    }

    /// Flushes any trailing partial line and buffered event when the stream reaches EOF.
    pub fn finish(&mut self) -> Vec<SseEvent> {
        let mut events = Vec::new();
        if !self.line_buf.is_empty() {
            let mut trailing = std::mem::take(&mut self.line_buf);
            if trailing.ends_with(b"\r") {
                trailing.pop();
            }
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

    fn flush_event(&mut self) -> Option<SseEvent> {
        if self.data_lines.is_empty() && self.event_type.is_none() {
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
}
