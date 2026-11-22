//! [`Snapshot`] — a compact, deterministic text rendering of what one
//! instance left in the host, for whole-state assertions.

use std::fmt;
use std::fmt::Write as _;
use std::path::Path;

use crate::TestHostError;
use crate::view::InstanceRef;
use crate::wit::capabilities::{ButtonEvent, CapabilitySpec};
use crate::wit::events::EventPayload;
use crate::wit::services::{FieldSpec, ValueKind};
use crate::wit::types::{KeyValue, Value};

/// Environment variable that makes [`Snapshot::assert_matches_file`]
/// (re)write the expected file instead of comparing against it.
pub const UPDATE_SNAPSHOTS_ENV: &str = "OXIDHOME_UPDATE_SNAPSHOTS";

/// What one instance has in the host — devices, services, events,
/// storage, blobs — rendered one line per item.
///
/// Built by `snapshot()` on [`crate::TestPluginInstance`] or
/// [`crate::SupervisedInstance`]. Every value the host or the guest
/// stamps from a real clock (event timestamps, receive times, blob
/// creation times) or from a process-wide counter (event-log row
/// ids, `svc-N` service ids, blob ids) is left out, so two runs of
/// the same test render the same text. Device ids stay in: they are
/// a hash of the installation, instance id, and local id, so they
/// are stable as long as the test picks its instance ids (or loads
/// in the same order).
///
/// The text form ([`fmt::Display`]) is what
/// [`Self::assert_matches`] compares, e.g.
///
/// ```text
/// devices:
///   dev-0123456789abcdef "Simulated Switch" [switch]
/// services:
/// events:
///   dev-0123456789abcdef state-changed switch {state=true}
/// storage:
///   count = 3
/// blobs:
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Snapshot {
    /// `<device-id> "<name>" [<capability>, …]`, sorted by device id.
    pub devices: Vec<String>,
    /// `<local-id> "<name>" <command>(<param>: <kind>, …), …`, sorted
    /// by local id. An optional param renders as `name?`.
    pub services: Vec<String>,
    /// `<device-id or -> <payload>`, oldest first.
    pub events: Vec<String>,
    /// `<key> = <value>`, sorted by key.
    pub storage: Vec<String>,
    /// `<name> <size>B <mime or ->`, sorted by name.
    pub blobs: Vec<String>,
}

impl Snapshot {
    pub(crate) fn capture(instance: &InstanceRef<'_>) -> Result<Self, TestHostError> {
        let devices = instance
            .devices()
            .iter()
            .map(|d| {
                let caps: Vec<String> = d.info.capabilities.iter().map(render_spec).collect();
                format!("{} {:?} [{}]", d.id, d.info.name, caps.join(", "))
            })
            .collect();
        let services = instance
            .services()
            .iter()
            .map(|s| {
                let commands: Vec<String> = s
                    .info
                    .commands
                    .iter()
                    .map(|c| {
                        let params: Vec<String> = c.params.iter().map(render_field).collect();
                        format!("{}({})", tok(&c.name), params.join(", "))
                    })
                    .collect();
                format!(
                    "{} {:?} {}",
                    tok(&s.info.local_id),
                    s.info.name,
                    commands.join(", ")
                )
            })
            .collect();
        let events = instance
            .events()?
            .iter()
            .map(|e| {
                format!(
                    "{} {}",
                    e.device_id.as_deref().map_or_else(|| "-".to_owned(), tok),
                    render_payload(&e.payload)
                )
            })
            .collect();
        let view = instance.storage();
        let mut storage = Vec::new();
        for key in view.keys("")? {
            let value = view
                .get(&key)?
                .map_or_else(|| "<removed>".to_owned(), |v| render_value(&v));
            storage.push(format!("{} = {value}", tok(&key)));
        }
        let blobs = instance
            .blobs()?
            .iter()
            .map(|b| {
                format!(
                    "{} {}B {}",
                    tok(&b.name),
                    b.size_bytes,
                    b.mime.as_deref().map_or_else(|| "-".to_owned(), esc)
                )
            })
            .collect();
        Ok(Self {
            devices,
            services,
            events,
            storage,
            blobs,
        })
    }

    /// Panic unless this snapshot renders as `expected`.
    ///
    /// `expected` is compared line by line after normalizing both
    /// sides: leading and trailing blank lines, trailing whitespace,
    /// and indentation common to every non-blank line are ignored, so
    /// it can be an indented raw string literal. The panic message
    /// carries a line diff (`-` expected, `+` actual) and the full
    /// actual text, ready to paste back into the test.
    ///
    /// # Panics
    ///
    /// When the normalized texts differ.
    #[track_caller]
    pub fn assert_matches(&self, expected: &str) {
        let actual = self.to_string();
        let (want, got) = (normalize(expected), normalize(&actual));
        assert!(
            want == got,
            "snapshot mismatch:\n{}\nactual snapshot:\n{}",
            diff(&want, &got),
            got.join("\n"),
        );
    }

    /// Like [`Self::assert_matches`], against the contents of `path`.
    ///
    /// With [`UPDATE_SNAPSHOTS_ENV`] set to anything other than `""`
    /// or `0`, writes the snapshot to `path` instead (creating parent
    /// directories) and passes — review the diff before committing.
    ///
    /// # Panics
    ///
    /// When the file's snapshot differs, or the file can't be read
    /// (including when it doesn't exist yet and the update variable
    /// isn't set) or written.
    #[track_caller]
    pub fn assert_matches_file(&self, path: impl AsRef<Path>) {
        let path = path.as_ref();
        if update_requested() {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).unwrap_or_else(|e| {
                    panic!("creating snapshot directory {}: {e}", parent.display())
                });
            }
            std::fs::write(path, self.to_string())
                .unwrap_or_else(|e| panic!("writing snapshot {}: {e}", path.display()));
            return;
        }
        let expected = std::fs::read_to_string(path).unwrap_or_else(|e| {
            panic!(
                "reading snapshot {}: {e} (set {UPDATE_SNAPSHOTS_ENV}=1 to create it)",
                path.display()
            )
        });
        self.assert_matches(&expected);
    }
}

impl fmt::Display for Snapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (name, lines) in [
            ("devices", &self.devices),
            ("services", &self.services),
            ("events", &self.events),
            ("storage", &self.storage),
            ("blobs", &self.blobs),
        ] {
            writeln!(f, "{name}:")?;
            for line in lines {
                writeln!(f, "  {line}")?;
            }
        }
        Ok(())
    }
}

/// Whether [`UPDATE_SNAPSHOTS_ENV`] asks for snapshot files to be
/// rewritten.
fn update_requested() -> bool {
    std::env::var_os(UPDATE_SNAPSHOTS_ENV).is_some_and(|v| !v.is_empty() && v != "0")
}

/// A WIT value as compact text: bare bools and numbers, quoted
/// strings, hex bytes (abbreviated past 32), `json:` + the JSON text
/// quoted.
#[must_use]
pub fn render_value(value: &Value) -> String {
    match value {
        Value::BoolVal(b) => b.to_string(),
        Value::IntVal(n) => n.to_string(),
        Value::FloatVal(x) => format!("{x:?}"),
        Value::StringVal(s) => format!("{s:?}"),
        Value::BytesVal(bytes) => {
            const SHOWN: usize = 32;
            let mut out = String::from("0x");
            for b in bytes.iter().take(SHOWN) {
                let _ = write!(out, "{b:02x}");
            }
            if bytes.len() > SHOWN {
                let _ = write!(out, "…({} bytes)", bytes.len());
            }
            out
        }
        Value::JsonVal(json) => format!("json:{json:?}"),
    }
}

/// A name in a delimited position (key, id, topic, …): bare when it
/// is a plain word (letters, digits, `_-.:`), otherwise quoted and
/// escaped like a Rust string, so no name can imitate the separators
/// around it and every item stays on one line.
fn tok(text: &str) -> String {
    let plain = !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-.:".contains(c));
    if plain {
        text.to_owned()
    } else {
        format!("{text:?}")
    }
}

/// Trailing free text (an event payload, a blob mime type): escaped
/// onto one line.
fn esc(text: &str) -> String {
    text.escape_debug().to_string()
}

fn render_fields(fields: &[KeyValue]) -> String {
    let parts: Vec<String> = fields
        .iter()
        .map(|kv| format!("{}={}", tok(&kv.key), render_value(&kv.value)))
        .collect();
    format!("{{{}}}", parts.join(", "))
}

fn render_payload(payload: &EventPayload) -> String {
    match payload {
        EventPayload::StateChanged(sc) => {
            format!(
                "state-changed {} {}",
                tok(&sc.capability),
                render_fields(&sc.fields)
            )
        }
        EventPayload::Button(b) => format!("button {}", render_button(b)),
        EventPayload::Inference(r) => format!("inference {} {}", tok(&r.model), esc(&r.payload)),
        EventPayload::Custom(c) => format!("custom {} {}", tok(&c.topic), esc(&c.payload)),
    }
}

fn render_button(event: &ButtonEvent) -> String {
    match event {
        ButtonEvent::Pressed => "pressed".to_owned(),
        ButtonEvent::Released => "released".to_owned(),
        ButtonEvent::SinglePress => "single-press".to_owned(),
        ButtonEvent::DoublePress => "double-press".to_owned(),
        ButtonEvent::LongPress => "long-press".to_owned(),
        ButtonEvent::Rotated(by) => format!("rotated({by:?})"),
    }
}

fn render_spec(spec: &CapabilitySpec) -> String {
    match spec {
        CapabilitySpec::Switch => "switch".to_owned(),
        CapabilitySpec::Dimmer => "dimmer".to_owned(),
        CapabilitySpec::ColorLight(_) => "color-light".to_owned(),
        CapabilitySpec::Sensor(_) => "sensor".to_owned(),
        CapabilitySpec::Button => "button".to_owned(),
        CapabilitySpec::VideoStream => "video-stream".to_owned(),
        CapabilitySpec::AudioStream => "audio-stream".to_owned(),
        CapabilitySpec::Extension(ext) => {
            format!(
                "extension({}/{}@{})",
                tok(&ext.namespace),
                tok(&ext.name),
                ext.version
            )
        }
    }
}

fn render_field(field: &FieldSpec) -> String {
    let kind = match field.kind {
        ValueKind::BoolVal => "bool",
        ValueKind::IntVal => "int",
        ValueKind::FloatVal => "float",
        ValueKind::StringVal => "string",
        ValueKind::BytesVal => "bytes",
        ValueKind::JsonVal => "json",
    };
    let optional = if field.required { "" } else { "?" };
    format!("{}{optional}: {kind}", tok(&field.name))
}

/// Lines of `text` with trailing whitespace, surrounding blank lines,
/// and common indentation removed.
fn normalize(text: &str) -> Vec<String> {
    let lines: Vec<&str> = text.lines().map(str::trim_end).collect();
    let start = lines
        .iter()
        .position(|l| !l.is_empty())
        .unwrap_or(lines.len());
    let end = lines
        .iter()
        .rposition(|l| !l.is_empty())
        .map_or(start, |i| i + 1);
    let lines = &lines[start..end];
    let indent = lines
        .iter()
        .filter(|l| !l.is_empty())
        .map(|l| l.len() - l.trim_start().len())
        .min()
        .unwrap_or(0);
    lines
        .iter()
        .map(|l| l.get(indent..).unwrap_or_default().to_owned())
        .collect()
}

/// Largest LCS table (cells) [`diff`] builds; past it the differing
/// middle is shown as a plain remove-all / add-all.
const MAX_DIFF_CELLS: usize = 1 << 20;

/// A minimal line diff: unchanged lines prefixed with two spaces,
/// removed with `- `, added with `+ `. The common prefix and suffix
/// are matched directly; the middle by longest common subsequence
/// while that stays under [`MAX_DIFF_CELLS`].
fn diff(want: &[String], got: &[String]) -> String {
    let prefix = want.iter().zip(got).take_while(|(a, b)| a == b).count();
    let suffix = want[prefix..]
        .iter()
        .rev()
        .zip(got[prefix..].iter().rev())
        .take_while(|(a, b)| a == b)
        .count();
    let (want_mid, got_mid) = (
        &want[prefix..want.len() - suffix],
        &got[prefix..got.len() - suffix],
    );
    let mut out = String::new();
    for line in &want[..prefix] {
        let _ = writeln!(out, "  {line}");
    }
    let (n, m) = (want_mid.len(), got_mid.len());
    if (n + 1).saturating_mul(m + 1) > MAX_DIFF_CELLS {
        for line in want_mid {
            let _ = writeln!(out, "- {line}");
        }
        for line in got_mid {
            let _ = writeln!(out, "+ {line}");
        }
    } else {
        lcs_diff(want_mid, got_mid, &mut out);
    }
    for line in &want[want.len() - suffix..] {
        let _ = writeln!(out, "  {line}");
    }
    out
}

fn lcs_diff(want: &[String], got: &[String], out: &mut String) {
    let (n, m) = (want.len(), got.len());
    // lcs[i][j] = LCS length of want[i..] and got[j..].
    let mut lcs = vec![vec![0_usize; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if want[i] == got[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let (mut i, mut j) = (0, 0);
    while i < n || j < m {
        if i < n && j < m && want[i] == got[j] {
            let _ = writeln!(out, "  {}", want[i]);
            i += 1;
            j += 1;
        } else if j < m && (i == n || lcs[i][j + 1] >= lcs[i + 1][j]) {
            let _ = writeln!(out, "+ {}", got[j]);
            j += 1;
        } else {
            let _ = writeln!(out, "- {}", want[i]);
            i += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Snapshot {
        Snapshot {
            devices: vec!["dev-1 \"Lamp\" [switch]".into()],
            services: Vec::new(),
            events: vec!["dev-1 state-changed switch {state=true}".into()],
            storage: vec!["count = 3".into()],
            blobs: Vec::new(),
        }
    }

    #[test]
    fn renders_every_section_in_order() {
        assert_eq!(
            sample().to_string(),
            "devices:\n  dev-1 \"Lamp\" [switch]\nservices:\nevents:\n  \
             dev-1 state-changed switch {state=true}\nstorage:\n  count = 3\nblobs:\n"
        );
    }

    #[test]
    fn matches_ignore_indentation_and_blank_edges() {
        sample().assert_matches(
            "
            devices:
              dev-1 \"Lamp\" [switch]
            services:
            events:
              dev-1 state-changed switch {state=true}
            storage:
              count = 3
            blobs:
            ",
        );
    }

    #[test]
    fn mismatch_reports_a_line_diff() {
        let err = std::panic::catch_unwind(|| {
            sample().assert_matches("devices:\nservices:\nevents:\nstorage:\n  count = 4\nblobs:");
        })
        .expect_err("must not match");
        let msg = err.downcast_ref::<String>().expect("string panic");
        assert!(msg.contains("+   dev-1 \"Lamp\" [switch]"), "{msg}");
        assert!(msg.contains("-   count = 4"), "{msg}");
        assert!(msg.contains("+   count = 3"), "{msg}");
        assert!(msg.contains("  events:"), "{msg}");
    }

    #[test]
    fn names_cannot_imitate_separators() {
        assert_eq!(tok("count"), "count");
        assert_eq!(tok("automation.morning"), "automation.morning");
        assert_eq!(tok("a/b@1"), "\"a/b@1\"");
        assert_eq!(tok(""), "\"\"");
        assert_eq!(tok("a = 1\n  b"), "\"a = 1\\n  b\"");
        let kv = |k: &str, v: bool| KeyValue {
            key: k.into(),
            value: Value::BoolVal(v),
        };
        assert_ne!(
            render_fields(&[kv("a", true), kv("b", false)]),
            render_fields(&[kv("a=true, b", false)])
        );
        assert_eq!(
            render_fields(&[kv("a=true, b", false)]),
            "{\"a=true, b\"=false}"
        );
        assert_eq!(
            render_value(&Value::JsonVal("{\"a\": 1}, b=2".into())),
            "json:\"{\\\"a\\\": 1}, b=2\""
        );
        assert_eq!(
            render_payload(&EventPayload::Custom(crate::wit::events::CustomEvent {
                topic: "t x".into(),
                payload: "{\"k\":\n1}".into(),
            })),
            "custom \"t x\" {\\\"k\\\":\\n1}"
        );
    }

    #[test]
    fn values_render_compactly() {
        assert_eq!(render_value(&Value::BoolVal(true)), "true");
        assert_eq!(render_value(&Value::IntVal(-2)), "-2");
        assert_eq!(render_value(&Value::FloatVal(1.0)), "1.0");
        assert_eq!(render_value(&Value::StringVal("a\"b".into())), "\"a\\\"b\"");
        assert_eq!(render_value(&Value::BytesVal(vec![0, 255])), "0x00ff");
        assert_eq!(
            render_value(&Value::BytesVal(vec![1; 33])),
            format!("0x{}…(33 bytes)", "01".repeat(32))
        );
        assert_eq!(render_value(&Value::JsonVal("{}".into())), "json:\"{}\"");
    }

    #[test]
    fn payloads_and_specs_render() {
        use crate::wit::capabilities::{ExtensionSpec, SensorSpec, Unit};
        use crate::wit::events::{CustomEvent, InferenceResult};
        assert_eq!(
            render_payload(&EventPayload::Button(ButtonEvent::Rotated(0.5))),
            "button rotated(0.5)"
        );
        for (b, s) in [
            (ButtonEvent::Pressed, "pressed"),
            (ButtonEvent::Released, "released"),
            (ButtonEvent::SinglePress, "single-press"),
            (ButtonEvent::DoublePress, "double-press"),
            (ButtonEvent::LongPress, "long-press"),
        ] {
            assert_eq!(render_button(&b), s);
        }
        assert_eq!(
            render_payload(&EventPayload::Custom(CustomEvent {
                topic: "t".into(),
                payload: "{}".into()
            })),
            "custom t {}"
        );
        assert_eq!(
            render_payload(&EventPayload::Inference(InferenceResult {
                model: "m".into(),
                payload: "[]".into(),
                frame_timestamp: Some(1),
            })),
            "inference m []"
        );
        assert_eq!(
            render_spec(&CapabilitySpec::Extension(ExtensionSpec {
                namespace: "acme".into(),
                name: "fan".into(),
                version: 2,
            })),
            "extension(acme/fan@2)"
        );
        assert_eq!(
            render_spec(&CapabilitySpec::Sensor(SensorSpec {
                unit: Unit::Celsius,
                min: None,
                max: None,
            })),
            "sensor"
        );
    }

    #[test]
    fn large_diffs_fall_back_to_remove_and_add() {
        let lines = |tag: &str| -> Vec<String> { (0..2000).map(|i| format!("{tag}{i}")).collect() };
        let mut want = vec!["head".to_owned()];
        want.extend(lines("a"));
        want.push("tail".to_owned());
        let mut got = vec!["head".to_owned()];
        got.extend(lines("b"));
        got.push("tail".to_owned());
        let out = diff(&want, &got);
        assert!(out.starts_with("  head\n- a0\n"), "{}", &out[..40]);
        assert!(out.ends_with("+ b1999\n  tail\n"));
        assert_eq!(out.lines().count(), 4002);
        // Small middles still get a real LCS diff.
        let small = diff(
            &["x".into(), "a".into(), "y".into()],
            &["x".into(), "b".into(), "a".into(), "y".into()],
        );
        assert_eq!(small, "  x\n+ b\n  a\n  y\n");
    }

    #[test]
    fn update_env_writes_then_compares() {
        // Only the read path here: setting the variable would race
        // other tests in this binary.
        let dir = crate::tempdir::TempDir::new().expect("tempdir");
        let path = dir.path().join("snap.txt");
        std::fs::write(&path, sample().to_string()).expect("write");
        sample().assert_matches_file(&path);
        // In update mode a missing file is created instead.
        if !update_requested() {
            let missing =
                std::panic::catch_unwind(|| sample().assert_matches_file(dir.path().join("none")));
            assert!(missing.is_err());
        }
    }
}
