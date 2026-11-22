//! M7: host-owned WASI stdout / stderr for plugin instances.
//!
//! A plugin's WASI output streams used to be inherited from the host
//! process, so a plugin that printed the plaintext of its own
//! `type = "secret"` config value wrote it straight to the daemon's
//! output, bypassing every redaction rule. Each instance now gets a
//! [`PluginOutput`] per stream that feeds the host log pipeline
//! instead:
//!
//! - **Line-buffered.** Bytes accumulate until `\n`; each line becomes
//!   one `tracing` event with target `plugin.stdout` (INFO) or
//!   `plugin.stderr` (WARN), attributed with `instance_id` and
//!   `plugin_id`. A partial last line is emitted when the instance's
//!   streams are dropped.
//! - **Redacted before it leaves.** Each line has the instance's own
//!   declared secret values replaced
//!   ([`crate::redact::scrub_secret_values`]) and then goes through the
//!   generic rules ([`crate::redact::redact_text`]), so the plaintext
//!   reaches neither the host's console output nor the `SQLite` log
//!   layer nor a tail.
//! - **Bounded.** A line is capped at [`MAX_LOG_MESSAGE_BYTES`] (the
//!   rest is dropped and counted in a `[…truncated N B]` suffix), and
//!   every emitted line spends a token from the instance's shared
//!   `logging::log` rate bucket, so a chatty plugin can't flood the log
//!   through stdio either. Lines refused by the bucket are dropped.
//!
//! Writes always succeed from the guest's point of view: logging is
//! one-way, and a guest must not be able to stall on its own output.

use std::fmt::Write as _;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};

use tokio::io::AsyncWrite;
use wasmtime_wasi::cli::{IsTerminal, StdoutStream};

use super::state::{LogRateBucket, MAX_LOG_MESSAGE_BYTES};

/// Which guest stream a [`PluginOutput`] captures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stream {
    Stdout,
    Stderr,
}

/// What a finished line is handed to. Production emits a `tracing`
/// event; tests capture the lines.
type Sink = Arc<dyn Fn(Stream, &str, &str, &str) + Send + Sync>;

fn emit_tracing(stream: Stream, instance_id: &str, plugin_id: &str, line: &str) {
    match stream {
        Stream::Stdout => {
            tracing::info!(target: "plugin.stdout", instance_id, plugin_id, "{line}");
        }
        Stream::Stderr => {
            tracing::warn!(target: "plugin.stderr", instance_id, plugin_id, "{line}");
        }
    }
}

/// Per-stream line state, shared by every `async_stream` handle the
/// guest opens on that stream.
struct LineState {
    stream: Stream,
    instance_id: Arc<str>,
    plugin_id: Arc<str>,
    /// Plaintext of the instance's declared secrets. Never printed:
    /// the manual `Debug` below omits it.
    secrets: Arc<[String]>,
    rate: Arc<Mutex<LogRateBucket>>,
    sink: Sink,
    buf: Vec<u8>,
    /// Bytes of the current line past the buffer limit.
    dropped: usize,
    /// Buffer limit: the line cap plus the longest secret, so a secret
    /// straddling the cap is still whole when it is scrubbed (the cut
    /// to [`MAX_LOG_MESSAGE_BYTES`] happens after scrubbing).
    limit: usize,
}

impl std::fmt::Debug for LineState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LineState")
            .field("stream", &self.stream)
            .field("instance_id", &self.instance_id)
            .field("buffered", &self.buf.len())
            .finish_non_exhaustive()
    }
}

impl LineState {
    fn write(&mut self, mut bytes: &[u8]) {
        while let Some(nl) = bytes.iter().position(|&b| b == b'\n') {
            self.push(&bytes[..nl]);
            self.finish_line();
            bytes = &bytes[nl + 1..];
        }
        self.push(bytes);
    }

    fn push(&mut self, bytes: &[u8]) {
        let room = self.limit.saturating_sub(self.buf.len());
        let take = room.min(bytes.len());
        self.buf.extend_from_slice(&bytes[..take]);
        self.dropped += bytes.len() - take;
    }

    fn finish_line(&mut self) {
        let raw = std::mem::take(&mut self.buf);
        let dropped = std::mem::take(&mut self.dropped);
        let admitted = self
            .rate
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .consume();
        if !admitted {
            return;
        }
        let mut raw = raw.as_slice();
        if let [rest @ .., b'\r'] = raw {
            raw = rest;
        }
        let text = String::from_utf8_lossy(raw);
        let secrets: Vec<&str> = self.secrets.iter().map(String::as_str).collect();
        let text = crate::redact::scrub_secret_values(&text, &secrets);
        let mut line = crate::redact::redact_text(&text).into_owned();
        let mut dropped = dropped;
        if line.len() > MAX_LOG_MESSAGE_BYTES {
            let mut cut = MAX_LOG_MESSAGE_BYTES;
            while !line.is_char_boundary(cut) {
                cut -= 1;
            }
            dropped += line.len() - cut;
            line.truncate(cut);
        }
        if dropped > 0 {
            let _ = write!(line, " […truncated {dropped} B]");
        }
        (self.sink)(self.stream, &self.instance_id, &self.plugin_id, &line);
    }
}

impl Drop for LineState {
    fn drop(&mut self) {
        if !self.buf.is_empty() || self.dropped > 0 {
            self.finish_line();
        }
    }
}

/// A host-owned guest output stream (see the module docs). Handed to
/// `WasiCtxBuilder::stdout` / `stderr`.
#[derive(Debug, Clone)]
pub(crate) struct PluginOutput {
    state: Arc<Mutex<LineState>>,
}

impl PluginOutput {
    /// The stdout / stderr pair for one instance. Both spend tokens
    /// from `rate`, the instance's `logging::log` bucket.
    pub(crate) fn pair(
        instance_id: &str,
        plugin_id: &str,
        secrets: &[&str],
        rate: &Arc<Mutex<LogRateBucket>>,
    ) -> (Self, Self) {
        Self::pair_with_sink(
            instance_id,
            plugin_id,
            secrets,
            rate,
            &(Arc::new(emit_tracing) as Sink),
        )
    }

    fn pair_with_sink(
        instance_id: &str,
        plugin_id: &str,
        secrets: &[&str],
        rate: &Arc<Mutex<LogRateBucket>>,
        sink: &Sink,
    ) -> (Self, Self) {
        let instance_id: Arc<str> = instance_id.into();
        let plugin_id: Arc<str> = plugin_id.into();
        let secrets: Arc<[String]> = secrets.iter().map(|s| (*s).to_owned()).collect();
        let longest = secrets.iter().map(String::len).max().unwrap_or(0);
        let make = |stream| Self {
            state: Arc::new(Mutex::new(LineState {
                stream,
                instance_id: Arc::clone(&instance_id),
                plugin_id: Arc::clone(&plugin_id),
                secrets: Arc::clone(&secrets),
                rate: Arc::clone(rate),
                sink: Arc::clone(sink),
                buf: Vec::new(),
                dropped: 0,
                limit: MAX_LOG_MESSAGE_BYTES + longest,
            })),
        };
        (make(Stream::Stdout), make(Stream::Stderr))
    }

    fn write(&self, bytes: &[u8]) {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .write(bytes);
    }
}

impl IsTerminal for PluginOutput {
    fn is_terminal(&self) -> bool {
        false
    }
}

impl StdoutStream for PluginOutput {
    fn async_stream(&self) -> Box<dyn AsyncWrite + Send + Sync> {
        Box::new(self.clone())
    }
}

impl AsyncWrite for PluginOutput {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.write(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Lines = Arc<Mutex<Vec<(Stream, String, String, String)>>>;

    fn capture(secrets: &[&str]) -> (PluginOutput, PluginOutput, Lines) {
        let lines: Lines = Arc::default();
        let sink_lines = Arc::clone(&lines);
        let sink: Sink = Arc::new(move |stream, instance, plugin, line| {
            sink_lines.lock().unwrap().push((
                stream,
                instance.to_owned(),
                plugin.to_owned(),
                line.to_owned(),
            ));
        });
        let rate = Arc::new(Mutex::new(LogRateBucket::new()));
        let (out, err) = PluginOutput::pair_with_sink("i-1", "example.p", secrets, &rate, &sink);
        (out, err, lines)
    }

    fn texts(lines: &Lines) -> Vec<String> {
        lines.lock().unwrap().iter().map(|l| l.3.clone()).collect()
    }

    #[test]
    fn secret_printed_to_stdout_is_redacted_and_attributed() {
        let (out, err, lines) = capture(&["hunter2-secret"]);
        out.write(b"connecting with hunter2-secret now\n");
        err.write(b"retry: password=other\r\n");
        let got = lines.lock().unwrap().clone();
        assert_eq!(
            got,
            vec![
                (
                    Stream::Stdout,
                    "i-1".into(),
                    "example.p".into(),
                    "connecting with *** now".into()
                ),
                (
                    Stream::Stderr,
                    "i-1".into(),
                    "example.p".into(),
                    "retry: password=***".into()
                ),
            ]
        );
    }

    #[test]
    fn lines_are_buffered_across_writes_and_handles() {
        let (out, _err, lines) = capture(&["hunter2-secret"]);
        let other = out.clone();
        out.write(b"a hunt");
        other.write(b"er2-secret b\nsecond");
        assert_eq!(texts(&lines), vec!["a *** b".to_owned()]);
        // The partial line is emitted once the last handle goes away.
        drop(out);
        drop(other);
        assert_eq!(
            texts(&lines),
            vec!["a *** b".to_owned(), "second".to_owned()]
        );
    }

    #[test]
    fn long_lines_are_capped_after_scrubbing() {
        let secret = "s".repeat(32);
        let (out, _err, lines) = capture(&[&secret]);
        // The secret straddles the cap: it must still be scrubbed whole.
        let mut line = "a".repeat(MAX_LOG_MESSAGE_BYTES - 8);
        line.push_str(&secret);
        line.push_str(&"b".repeat(10_000));
        line.push('\n');
        out.write(line.as_bytes());
        let got = texts(&lines);
        assert_eq!(got.len(), 1);
        assert!(!got[0].contains("ssss"), "secret fragment leaked");
        assert!(
            got[0].contains("[…truncated"),
            "{}",
            &got[0][got[0].len() - 40..]
        );
        assert!(got[0].len() < MAX_LOG_MESSAGE_BYTES + 40);
    }

    #[test]
    fn lines_spend_the_shared_rate_budget() {
        let (out, _err, lines) = capture(&[]);
        let many = "x\n".repeat(1_000);
        out.write(many.as_bytes());
        let emitted = texts(&lines).len();
        // The burst admits LOG_RATE_BURST lines (plus whatever refilled
        // while the loop ran); the rest are dropped.
        assert!(emitted < 200, "{emitted} lines admitted");
        assert!(emitted >= 32, "{emitted} lines admitted");
    }
}
