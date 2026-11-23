//! M7: data classification and redaction at capture.
//!
//! One module decides what counts as sensitive, so every place a value
//! enters durable diagnostics or leaves through a read API applies the
//! same rules:
//!
//! - **Declared secrets.** A manifest `type = "secret"` config field
//!   resolves to [`ConfigValue::Secret`], which masks itself in `Debug`
//!   and `Serialize`. [`masked_config_view`] is the only shape a read API
//!   returns for an instance's config; [`config_secrets`] +
//!   [`scrub_secret_values`] strip the plaintext from the owning plugin's
//!   own log lines.
//! - **Sensitive key names.** [`is_sensitive_key`] is a conservative
//!   denylist (`password`, `token`, `secret`, `api_key`,
//!   `authorization`, …). [`redact_json`] masks values under such keys;
//!   [`scrub_text`] masks `key=value` / `key: value` pairs, `Bearer`
//!   credentials and `oxh_` API tokens inside free text.
//! - **Raw bytes.** `bytes-val` payloads (camera snapshots, audio,
//!   inference frames) are withheld from callers that lack the
//!   `blobs:read` scope; see [`withhold_bytes_in_kvs`] and friends.
//!
//! Applied at: the `SQLite` log layer (message + structured fields,
//! before the row is queued), the audit ledger (every text column on
//! insert and finalize), MCP resource and tool bodies, and the
//! plugin `logging` host import. Redaction is best-effort defence in
//! depth: a plugin that deliberately encodes a credential in an
//! unrecognisable shape is not caught. Encryption at rest and
//! support-bundle sanitization are separate, deferred work.

use std::borrow::Cow;

use oxidhome_manifest::{ConfigField, ConfigFieldType, ConfigValue, InstanceConfig};
use serde_json::{Map, Value as JsonValue};

use crate::host_impl::plugin::oxidhome::plugin::devices::CommandResult;
use crate::host_impl::plugin::oxidhome::plugin::events::EventPayload;
use crate::host_impl::plugin::oxidhome::plugin::types::{KeyValue, Value};

/// Placeholder written in place of every redacted value.
pub const REDACTED: &str = oxidhome_manifest::MASKED;

/// Shortest declared secret [`scrub_secret_values`] searches for. A
/// one- to three-character secret would match ordinary text all over a
/// log line; such secrets are still masked on every read surface, just
/// not hunted for inside free text.
pub const MIN_SCRUB_SECRET_LEN: usize = 4;

/// Normalised substrings that make a key sensitive wherever they appear.
const SENSITIVE_CONTAINS: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "secret",
    "apikey",
    "privatekey",
    "authorization",
];

/// Normalised suffixes that make a key sensitive (`access_token`,
/// `aws_access_key`, `session_cookie`). Matching on the suffix, not
/// the substring, keeps identifiers such as `token_id` readable.
const SENSITIVE_SUFFIXES: &[&str] = &["token", "accesskey", "credentials", "cookie"];

/// Normalised keys that are sensitive only as a whole word.
const SENSITIVE_EXACT: &[&str] = &["pwd", "pin", "auth", "credential"];

/// Is `key` the name of a field that may hold a credential?
///
/// The key is normalised first: ASCII-lowercased with every
/// non-alphanumeric character dropped, so `API-Key`, `api_key` and
/// `apiKey` all read as `apikey`. Then it is sensitive when it
/// contains `password`, `passwd`, `passphrase`, `secret`, `apikey`,
/// `privatekey` or `authorization`; ends with `token`, `accesskey`,
/// `credentials` or `cookie`; or is exactly `pwd`, `pin`, `auth` or
/// `credential`. `token_id`, `credential_id` and `max_tokens` stay
/// readable.
#[must_use]
pub fn is_sensitive_key(key: &str) -> bool {
    let norm: String = key
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if norm.is_empty() {
        return false;
    }
    SENSITIVE_CONTAINS.iter().any(|s| norm.contains(s))
        || SENSITIVE_SUFFIXES.iter().any(|s| norm.ends_with(s))
        || SENSITIVE_EXACT.contains(&norm.as_str())
}

/// Redact a JSON document in place. Returns `true` if anything changed.
///
/// - Under a sensitive object key, every string and number leaf
///   becomes [`REDACTED`]; booleans and `null` survive, so a masked
///   config entry's `set` flag stays readable.
/// - `{"key": "<sensitive>", "value": …}` objects (the wire shape of a
///   WIT `key-value`) get their `value` redacted the same way.
/// - `["<sensitive>", {…}]` pairs (the wire shape of a structured log
///   field) get their second element redacted.
/// - Every other string goes through [`scrub_text`].
pub fn redact_json(value: &mut JsonValue) -> bool {
    match value {
        JsonValue::Object(map) => {
            let mut changed = false;
            let kv_sensitive = map
                .get("key")
                .and_then(JsonValue::as_str)
                .is_some_and(is_sensitive_key);
            for (k, v) in map.iter_mut() {
                if is_sensitive_key(k) || (kv_sensitive && k == "value") {
                    changed |= mask_leaves(v);
                } else {
                    changed |= redact_json(v);
                }
            }
            changed
        }
        JsonValue::Array(items) => {
            let pair_sensitive = items.len() == 2
                && items[0].as_str().is_some_and(is_sensitive_key)
                && items[1].is_object();
            if pair_sensitive {
                return mask_leaves(&mut items[1]);
            }
            let mut changed = false;
            for item in items {
                changed |= redact_json(item);
            }
            changed
        }
        JsonValue::String(s) => {
            // A string that is itself a JSON document (a `json-val`, a
            // custom event payload) is redacted structurally and
            // re-encoded, so it stays valid JSON.
            let trimmed = s.trim_start();
            if (trimmed.starts_with('{') || trimmed.starts_with('['))
                && let Ok(mut inner) = serde_json::from_str::<JsonValue>(s)
            {
                if !redact_json(&mut inner) {
                    return false;
                }
                if let Ok(encoded) = serde_json::to_string(&inner) {
                    *s = encoded;
                    return true;
                }
            }
            match scrub_text(s) {
                Cow::Borrowed(_) => false,
                Cow::Owned(scrubbed) => {
                    *s = scrubbed;
                    true
                }
            }
        }
        JsonValue::Bool(_) | JsonValue::Null | JsonValue::Number(_) => false,
    }
}

/// [`scrub_text`] for free text that may be a whole JSON document: a
/// text that parses as a JSON object or array is redacted structurally
/// (nested credentials included) and re-encoded, so it stays valid
/// JSON; anything else goes through [`scrub_text`].
#[must_use]
pub fn redact_text(text: &str) -> Cow<'_, str> {
    let trimmed = text.trim_start();
    if !(trimmed.starts_with('{') || trimmed.starts_with('[')) {
        return scrub_text(text);
    }
    let mut value = JsonValue::String(text.to_owned());
    if !redact_json(&mut value) {
        return Cow::Borrowed(text);
    }
    match value {
        JsonValue::String(s) => Cow::Owned(s),
        _ => Cow::Borrowed(text),
    }
}

/// Replace every string / number leaf under `value` with
/// [`REDACTED`]. Object keys are kept so the shape stays readable;
/// tag fields such as a wire value's `"t"` are kept too.
fn mask_leaves(value: &mut JsonValue) -> bool {
    match value {
        JsonValue::String(s) if s == REDACTED => false,
        JsonValue::String(_) | JsonValue::Number(_) => {
            *value = JsonValue::String(REDACTED.to_owned());
            true
        }
        // A tagged wire value (`{"t": "Int", "v": 1234}`): swap the
        // whole value for a `String` one so a typed client can still
        // decode it (`{"t": "Int", "v": "***"}` would not).
        JsonValue::Object(map)
            if map.len() == 2
                && map.get("t").is_some_and(JsonValue::is_string)
                && map.contains_key("v") =>
        {
            let masked = serde_json::json!({"t": "String", "v": REDACTED});
            if *value == masked {
                return false;
            }
            *value = masked;
            true
        }
        JsonValue::Object(map) => {
            let mut changed = false;
            for v in map.values_mut() {
                changed |= mask_leaves(v);
            }
            changed
        }
        JsonValue::Array(items) => {
            let mut changed = false;
            for item in items {
                changed |= mask_leaves(item);
            }
            changed
        }
        JsonValue::Bool(_) | JsonValue::Null => false,
    }
}

/// Mask credentials embedded in free text.
///
/// Recognised shapes:
/// - `<sensitive key>=<value>` and `<sensitive key>: <value>`, with
///   the key optionally quoted (`"password": "x"`) and the value
///   optionally quoted. An unquoted value runs to the next whitespace,
///   `&`, `,`, `;`, quote or bracket. When the unquoted value is an
///   HTTP auth scheme (`Bearer`, `Basic`, `Digest`, `Token`), the
///   credential after it is masked too.
/// - `Bearer <credential>` anywhere, case-insensitively.
/// - `OxidHome` API tokens (`oxh_` + at least 16 base64url characters).
///
/// Returns the input unchanged (borrowed) when nothing matched.
#[must_use]
pub fn scrub_text(text: &str) -> Cow<'_, str> {
    let bytes = text.as_bytes();
    let candidate = text.contains(['=', ':'])
        || text.contains("oxh_")
        || bytes.windows(6).any(|w| w.eq_ignore_ascii_case(b"bearer"));
    if !candidate {
        return Cow::Borrowed(text);
    }
    let mut out = String::new();
    // Everything before `copied` is already in `out`.
    let mut copied = 0;
    let mut pos = 0;
    while pos < bytes.len() {
        if let Some((start, end)) = match_api_token(bytes, pos)
            .or_else(|| match_bearer(bytes, pos))
            .or_else(|| match_key_value(text, pos, copied))
        {
            out.push_str(&text[copied..start]);
            out.push_str(REDACTED);
            copied = end;
            pos = end.max(pos + 1);
            continue;
        }
        pos += 1;
    }
    if copied == 0 {
        return Cow::Borrowed(text);
    }
    out.push_str(&text[copied..]);
    Cow::Owned(out)
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.'
}

fn is_value_end(b: u8) -> bool {
    b.is_ascii_whitespace()
        || matches!(
            b,
            b'&' | b',' | b';' | b'"' | b'\'' | b')' | b']' | b'}' | b'>' | b'<'
        )
}

fn starts_with_ignore_case(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.len() >= needle.len() && haystack[..needle.len()].eq_ignore_ascii_case(needle)
}

fn scan_value(bytes: &[u8], from: usize) -> usize {
    let mut end = from;
    while end < bytes.len() && !is_value_end(bytes[end]) {
        end += 1;
    }
    end
}

/// `oxh_<base64url>` at `pos` → the byte range of the body to mask.
fn match_api_token(bytes: &[u8], pos: usize) -> Option<(usize, usize)> {
    if !bytes[pos..].starts_with(b"oxh_") || (pos > 0 && is_ident_byte(bytes[pos - 1])) {
        return None;
    }
    let start = pos + 4;
    let mut end = start;
    while end < bytes.len()
        && (bytes[end].is_ascii_alphanumeric() || matches!(bytes[end], b'-' | b'_'))
    {
        end += 1;
    }
    (end - start >= 16).then_some((start, end))
}

/// Horizontal whitespace between a key, its separator, an auth scheme
/// and the value. Line breaks are not crossed, so a bare `password:` at
/// the end of a line never masks the next one.
fn is_blank(b: u8) -> bool {
    matches!(b, b' ' | b'\t')
}

/// `Bearer <credential>` at `pos` → the credential's byte range.
fn match_bearer(bytes: &[u8], pos: usize) -> Option<(usize, usize)> {
    let after = pos + "bearer".len();
    if !starts_with_ignore_case(&bytes[pos..], b"bearer")
        || !bytes.get(after).is_some_and(|&b| is_blank(b))
        || (pos > 0 && is_ident_byte(bytes[pos - 1]))
    {
        return None;
    }
    let mut start = after;
    while start < bytes.len() && is_blank(bytes[start]) {
        start += 1;
    }
    let end = scan_value(bytes, start);
    (end > start && &bytes[start..end] != REDACTED.as_bytes()).then_some((start, end))
}

/// `<sensitive key>[=:]<value>` with the separator at `pos` → the
/// value's byte range. `floor` is the first byte not yet copied; the
/// key must start at or after it so an earlier replacement is never
/// re-read as a key.
fn match_key_value(text: &str, pos: usize, floor: usize) -> Option<(usize, usize)> {
    let bytes = text.as_bytes();
    if bytes[pos] != b'=' && bytes[pos] != b':' {
        return None;
    }
    // Walk back over spaces and an optional closing quote to the key.
    let mut key_end = pos;
    while key_end > floor && is_blank(bytes[key_end - 1]) {
        key_end -= 1;
    }
    if key_end > floor && matches!(bytes[key_end - 1], b'"' | b'\'') {
        key_end -= 1;
        // `\"password\":` — JSON nested inside a `Debug`-escaped string.
        if key_end > floor && bytes[key_end - 1] == b'\\' {
            key_end -= 1;
        }
    }
    let mut key_start = key_end;
    while key_start > floor && is_ident_byte(bytes[key_start - 1]) {
        key_start -= 1;
    }
    if key_start == key_end || !is_sensitive_key(&text[key_start..key_end]) {
        return None;
    }
    // Forward over spaces, a `Debug` wrapper such as `String(` or
    // `Some(` (how `{:?}` renders `serde_json` / `toml` values), and an
    // optional opening quote to the value.
    let mut start = pos + 1;
    while start < bytes.len() && is_blank(bytes[start]) {
        start += 1;
    }
    let mut wrapper = start;
    while wrapper < bytes.len() && bytes[wrapper].is_ascii_alphabetic() {
        wrapper += 1;
    }
    if wrapper > start && wrapper < bytes.len() && bytes[wrapper] == b'(' {
        start = wrapper + 1;
    }
    // An escaped opening quote (`\"`) means the value ends at the next
    // escaped quote; a plain one ends at the next unescaped quote.
    let escaped = start + 1 < bytes.len()
        && bytes[start] == b'\\'
        && matches!(bytes[start + 1], b'"' | b'\'');
    if escaped {
        start += 1;
    }
    let end = if !escaped && start < bytes.len() && matches!(bytes[start], b'{' | b'[') {
        // A structured value (`"password": {"value": "x"}`): mask the
        // whole structure, through its closing bracket or, when the
        // text was cut short, to the end.
        scan_structure(bytes, start)
    } else if start < bytes.len() && matches!(bytes[start], b'"' | b'\'') {
        let quote = bytes[start];
        start += 1;
        let mut end = start;
        // Inside an escaped string, `\\` decodes to a backslash and
        // `\"` to a quote; that quote closes the value only when it is
        // not itself escaped at the inner level, i.e. preceded by an
        // even number of decoded backslashes (`\\\"` is data).
        let mut inner_backslashes = 0usize;
        while end < bytes.len() {
            if bytes[end] == b'\\' {
                let next = bytes.get(end + 1).copied();
                if escaped {
                    if next == Some(quote) && inner_backslashes.is_multiple_of(2) {
                        break;
                    }
                    inner_backslashes = if next == Some(b'\\') {
                        inner_backslashes + 1
                    } else {
                        0
                    };
                }
                end += 2;
                continue;
            }
            if bytes[end] == quote {
                break;
            }
            inner_backslashes = 0;
            end += 1;
        }
        end.min(bytes.len())
    } else {
        let word_end = scan_value(bytes, start);
        let word = &bytes[start..word_end];
        let is_scheme = [&b"bearer"[..], b"basic", b"digest", b"token"]
            .iter()
            .any(|s| word.eq_ignore_ascii_case(s));
        if is_scheme && word_end < bytes.len() && is_blank(bytes[word_end]) {
            // Keep the scheme name, mask the credential after it.
            start = word_end;
            while start < bytes.len() && is_blank(bytes[start]) {
                start += 1;
            }
            scan_value(bytes, start)
        } else {
            word_end
        }
    };
    (end > start && &bytes[start..end] != REDACTED.as_bytes()).then_some((start, end))
}

/// End of the bracketed structure opening at `start` (`{` or `[`):
/// one past its matching close bracket, or the end of `bytes` if it is
/// never closed. Brackets inside double-quoted strings don't count.
fn scan_structure(bytes: &[u8], start: usize) -> usize {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut i = start;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if in_string => i += 1,
            b'"' => in_string = !in_string,
            b'{' | b'[' if !in_string => depth += 1,
            b'}' | b']' if !in_string => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    bytes.len()
}

/// The plaintext of every declared secret in a resolved config.
#[must_use]
pub fn config_secrets(config: &InstanceConfig) -> Vec<&str> {
    fn walk<'a>(map: &'a InstanceConfig, out: &mut Vec<&'a str>) {
        for value in map.values() {
            match value {
                ConfigValue::Secret(s) => out.push(s.expose()),
                ConfigValue::Nested(inner) => walk(inner, out),
                _ => {}
            }
        }
    }
    let mut out = Vec::new();
    walk(config, &mut out);
    out
}

/// Replace every occurrence of a known secret value in `text` with
/// [`REDACTED`]. Secrets shorter than [`MIN_SCRUB_SECRET_LEN`] are
/// skipped (see there).
#[must_use]
pub fn scrub_secret_values<'a>(text: &'a str, secrets: &[&str]) -> Cow<'a, str> {
    let secrets: Vec<&str> = secrets
        .iter()
        .copied()
        .filter(|s| s.len() >= MIN_SCRUB_SECRET_LEN && text.contains(s))
        .collect();
    if secrets.is_empty() {
        return Cow::Borrowed(text);
    }
    // One Aho-Corasick pass (linear in text + secrets + matches)
    // reporting overlapping matches in order of their end offset.
    // Replacing one secret before searching for the next would break
    // up an overlapping match and leave a fragment, so matches merge
    // into runs first. A later match can still reach back into an
    // earlier run (a long secret ending after a short one), but never
    // further back than the longest secret, so only runs inside that
    // window stay pending; older ones are final and are copied out.
    // Pinned to the contiguous NFA: the default would pick a DFA for a
    // small pattern set, whose construction is quadratic in a long
    // repetitive secret.
    let Ok(matcher) = aho_corasick::AhoCorasick::builder()
        .kind(Some(aho_corasick::AhoCorasickKind::ContiguousNFA))
        .build(&secrets)
    else {
        // Only fails on pathological sizes; withhold the text rather
        // than risk passing a secret through.
        return Cow::Borrowed(REDACTED);
    };
    let window = secrets.iter().map(|s| s.len()).max().unwrap_or(0);
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    let mut pending: std::collections::VecDeque<(usize, usize)> = std::collections::VecDeque::new();
    let flush = |out: &mut String, copied: &mut usize, (start, end): (usize, usize)| {
        out.push_str(&text[*copied..start]);
        out.push_str(REDACTED);
        *copied = end;
    };
    for m in matcher.find_overlapping_iter(text) {
        let (mut start, mut end) = (m.start(), m.end());
        while let Some(&(s, e)) = pending.back()
            && e >= start
        {
            pending.pop_back();
            start = start.min(s);
            end = end.max(e);
        }
        pending.push_back((start, end));
        // Every later match ends at or after `m.end()`, so it starts at
        // or after `m.end() - window`; a run ending before that is final.
        let horizon = m.end().saturating_sub(window);
        while let Some(&run) = pending.front()
            && run.1 < horizon
        {
            pending.pop_front();
            flush(&mut out, &mut copied, run);
        }
    }
    for run in pending {
        flush(&mut out, &mut copied, run);
    }
    out.push_str(&text[copied..]);
    Cow::Owned(out)
}

/// [`scrub_secret_values`] over the message of a command result's
/// error (or H5 `unknown` text), for plugin-authored text that leaves
/// the sandbox.
pub fn scrub_command_error(result: &mut CommandResult, secrets: &[&str]) {
    use crate::host_impl::plugin::oxidhome::plugin::types::Error as WitError;
    if let CommandResult::Err(
        WitError::NotFound(m)
        | WitError::InvalidArgument(m)
        | WitError::PermissionDenied(m)
        | WitError::Unavailable(m)
        | WitError::Internal(m),
    )
    | CommandResult::Unknown(m) = result
        && let Cow::Owned(scrubbed) = scrub_secret_values(m, secrets)
    {
        *m = scrubbed;
    }
}

/// The read-API projection of an instance's resolved config.
///
/// Walks the manifest schema so unset optional secrets still show up.
/// Plain fields render as their JSON value; a `type = "secret"` field
/// renders as `{"secret": true, "set": <bool>, "value": "***" | null}`.
/// Nested tables recurse. The result never contains a secret's
/// plaintext.
#[must_use]
pub fn masked_config_view(
    schema: &std::collections::BTreeMap<String, ConfigField>,
    config: &InstanceConfig,
) -> JsonValue {
    let mut out = Map::new();
    for (name, field) in schema {
        let value = config.get(name);
        let rendered = match (&field.ty, value) {
            (ConfigFieldType::Secret { .. }, v) => {
                let set = matches!(v, Some(ConfigValue::Secret(_)));
                serde_json::json!({
                    "secret": true,
                    "set": set,
                    "value": if set { JsonValue::from(REDACTED) } else { JsonValue::Null },
                })
            }
            (ConfigFieldType::Nested { fields }, Some(ConfigValue::Nested(inner))) => {
                masked_config_view(fields, inner)
            }
            (_, Some(v)) => serde_json::to_value(v).unwrap_or(JsonValue::Null),
            (_, None) => continue,
        };
        out.insert(name.clone(), rendered);
    }
    JsonValue::Object(out)
}

/// What a withheld `bytes-val` becomes on the wire: a `json-val`
/// naming the size and the scope that would reveal it. A `json-val`
/// (rather than an empty `bytes-val`) lets a client tell "withheld"
/// from "empty".
fn withheld_marker(len: usize) -> Value {
    Value::JsonVal(format!(
        "{{\"withheld\":\"bytes\",\"size_bytes\":{len},\"required_scope\":\"blobs:read\"}}"
    ))
}

/// Replace a `bytes-val` with the withheld marker.
pub fn withhold_bytes(value: &mut Value) {
    if let Value::BytesVal(b) = value {
        *value = withheld_marker(b.len());
    }
}

/// [`withhold_bytes`] over every value in a key-value list.
pub fn withhold_bytes_in_kvs(kvs: &mut [KeyValue]) {
    for kv in kvs {
        withhold_bytes(&mut kv.value);
    }
}

/// [`withhold_bytes`] over an event payload's fields.
pub fn withhold_bytes_in_event(payload: &mut EventPayload) {
    if let EventPayload::StateChanged(sc) = payload {
        withhold_bytes_in_kvs(&mut sc.fields);
    }
}

/// [`withhold_bytes`] over a command result's returned state.
pub fn withhold_bytes_in_command_result(result: &mut CommandResult) {
    if let CommandResult::OkWithState(kvs) = result {
        withhold_bytes_in_kvs(kvs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxidhome_manifest::SecretString;
    use serde_json::json;

    #[test]
    fn sensitive_key_denylist() {
        for k in [
            "password",
            "PASSWORD",
            "db_password",
            "passwd",
            "client_secret",
            "secret",
            "api_key",
            "x-api-key",
            "apiKey",
            "private_key",
            "Authorization",
            "proxy-authorization",
            "token",
            "access_token",
            "refreshToken",
            "aws_access_key",
            "credentials",
            "session_cookie",
            "pin",
            "pwd",
            "auth",
        ] {
            assert!(is_sensitive_key(k), "{k} should be sensitive");
        }
        for k in [
            "token_id",
            "credential_id",
            "credential_fp",
            "max_tokens",
            "author",
            "spin",
            "host",
            "port",
            "required_scope",
            "",
            "__",
        ] {
            assert!(!is_sensitive_key(k), "{k} should not be sensitive");
        }
    }

    #[test]
    fn scrub_text_key_value_shapes() {
        let cases = [
            ("password=hunter2", "password=***"),
            (
                "login ok password=hunter2 user=bob",
                "login ok password=*** user=bob",
            ),
            ("GET /x?api_key=abc123&page=2", "GET /x?api_key=***&page=2"),
            ("token: abc", "token: ***"),
            (
                r#"{"password":"a b c","user":"bob"}"#,
                r#"{"password":"***","user":"bob"}"#,
            ),
            ("secret='x y'", "secret='***'"),
            ("Authorization: Bearer abc.def", "Authorization: Bearer ***"),
            (
                "authorization=Basic dXNlcjpwYXNz",
                "authorization=Basic ***",
            ),
            ("token_id=abc", "token_id=abc"),
            (
                "https://example.com:8443/path",
                "https://example.com:8443/path",
            ),
            ("password=", "password="),
            ("password=***", "password=***"),
            (
                r#"{"api_key": String("hunter2"), "n": Int(1)}"#,
                r#"{"api_key": String("***"), "n": Int(1)}"#,
            ),
            ("pin: Some(1234)", "pin: Some(***)"),
            (
                r#"{"password":{"value":"hunter2","n":[1]},"ok":1}"#,
                r#"{"password":***,"ok":1}"#,
            ),
            (
                // Cut short (a capped line): masked to the end.
                r#"{"password":{"value":"hun}ter2","pad":"xx"#,
                r#"{"password":***"#,
            ),
            ("secret=[1, 2] rest", "secret=*** rest"),
            ("password=\thunter2", "password=\t***"),
            ("password\t:\thunter2", "password\t:\t***"),
            (
                "Authorization:\tBasic dXNlcjpwYXNz",
                "Authorization:\tBasic ***",
            ),
            ("auth: Bearer\tabc.def", "auth: Bearer\t***"),
            ("password:\nnext line", "password:\nnext line"),
            (
                r#"payload="{\"password\":\"hunter2\",\"user\":\"bob\"}""#,
                r#"payload="{\"password\":\"***\",\"user\":\"bob\"}""#,
            ),
            (
                r#"{"password":"a\"b","n":1}"#,
                r#"{"password":"***","n":1}"#,
            ),
            (
                // An escaped data quote inside an escaped string.
                r#"x={\"password\":\"a\\\"suffix\",\"n\":1}"#,
                r#"x={\"password\":\"***\",\"n\":1}"#,
            ),
            (
                // An escaped backslash right before the closing quote.
                r#"x={\"password\":\"a\\\\\",\"n\":1}"#,
                r#"x={\"password\":\"***\",\"n\":1}"#,
            ),
        ];
        for (input, want) in cases {
            assert_eq!(scrub_text(input), want, "input {input}");
        }
    }

    #[test]
    fn scrub_text_bearer_and_api_tokens() {
        assert_eq!(
            scrub_text("sent bearer abcdef to upstream"),
            "sent bearer *** to upstream"
        );
        assert_eq!(
            scrub_text("token oxh_AAAAAAAAAAAAAAAAAAAAAAAA leaked"),
            "token oxh_*** leaked"
        );
        // Short `oxh_` strings aren't tokens.
        assert_eq!(scrub_text("oxh_short"), "oxh_short");
    }

    #[test]
    fn scrub_text_borrows_when_clean() {
        assert!(matches!(scrub_text("plain message"), Cow::Borrowed(_)));
        assert!(matches!(scrub_text("host=mqtt.local"), Cow::Borrowed(_)));
    }

    #[test]
    fn scrub_text_handles_non_ascii() {
        assert_eq!(
            scrub_text("pässword=1 🙂 password=ü"),
            "pässword=1 🙂 password=***"
        );
    }

    #[test]
    fn redact_json_masks_sensitive_keys_and_kv_shapes() {
        let mut v = json!({
            "host": "mqtt.local",
            "password": "hunter2",
            "nested": {"api_key": 1234, "ok": true},
            "fields": [
                {"key": "token", "value": {"t": "string", "v": "abc"}},
                {"key": "brightness", "value": {"t": "int", "v": 5}}
            ],
            "log_fields": [["secret", {"t": "String", "v": "s"}], ["n", {"t": "Int", "v": 1}]],
            "values": ["password", "pin"],
            "message": "connect password=hunter2",
            "token_id": "tok-1",
            "credentials": {"user": "bob", "set": true}
        });
        assert!(redact_json(&mut v));
        assert_eq!(
            v,
            json!({
                "host": "mqtt.local",
                "password": "***",
                "nested": {"api_key": "***", "ok": true},
                "fields": [
                    {"key": "token", "value": {"t": "String", "v": "***"}},
                    {"key": "brightness", "value": {"t": "int", "v": 5}}
                ],
                "log_fields": [["secret", {"t": "String", "v": "***"}], ["n", {"t": "Int", "v": 1}]],
                "values": ["password", "pin"],
                "message": "connect password=***",
                "token_id": "tok-1",
                "credentials": {"user": "***", "set": true}
            })
        );
        assert!(!redact_json(&mut v), "second pass is a no-op");
    }

    #[test]
    fn redact_json_handles_embedded_json_strings() {
        let mut v = json!({
            "payload": r#"{"password":{"value":"hunter2"},"pin":1234,"ok":1}"#,
            "plain": "[not json",
        });
        assert!(redact_json(&mut v));
        let inner: JsonValue = serde_json::from_str(v["payload"].as_str().unwrap()).unwrap();
        assert_eq!(
            inner,
            json!({"password": {"value": "***"}, "pin": "***", "ok": 1})
        );
        assert_eq!(v["plain"], "[not json");
    }

    #[test]
    fn redact_text_handles_nested_json_documents() {
        let out = redact_text(r#"{"password":{"value":"hunter2"},"n":1}"#);
        assert!(!out.contains("hunter2"), "{out}");
        let v: JsonValue = serde_json::from_str(&out).expect("still JSON");
        assert_eq!(v["n"], 1);
        // A value whose text would trip the unquoted-value scanner stays
        // valid JSON when redacted structurally.
        let out = redact_text(r#"{"service":"password=abc\"tail"}"#);
        let v: JsonValue = serde_json::from_str(&out).expect("still JSON");
        assert_eq!(v["service"], "password=***\"tail");
        assert!(matches!(redact_text(r#"{"ok":1}"#), Cow::Borrowed(_)));
        assert_eq!(redact_text("password=x"), "password=***");
    }

    #[test]
    fn redact_json_keeps_tagged_values_decodable() {
        let mut v = json!({"pin": {"t": "Int", "v": 1234}});
        assert!(redact_json(&mut v));
        assert_eq!(v, json!({"pin": {"t": "String", "v": "***"}}));
        assert!(!redact_json(&mut v));
    }

    #[test]
    fn redact_json_keeps_masked_config_view_readable() {
        let mut v = json!({"api_key": {"secret": true, "set": true, "value": "***"}});
        let before = v.clone();
        assert!(!redact_json(&mut v));
        assert_eq!(v, before);
    }

    fn secret_schema() -> std::collections::BTreeMap<String, ConfigField> {
        let text = r#"
[host]
type = "string"
[api_key]
type = "secret"
[optional_token]
type = "secret"
required = false
[broker]
type = "nested"
[broker.fields.password]
type = "secret"
[broker.fields.port]
type = "int"
default = 1883
"#;
        toml::from_str(text).unwrap()
    }

    #[test]
    fn masked_view_hides_secrets_and_reports_set_flag() {
        let schema = secret_schema();
        let mut broker = InstanceConfig::new();
        broker.insert(
            "password".into(),
            ConfigValue::Secret(SecretString::new("broker-pw")),
        );
        broker.insert("port".into(), ConfigValue::Int(1883));
        let mut cfg = InstanceConfig::new();
        cfg.insert("host".into(), ConfigValue::String("h".into()));
        cfg.insert(
            "api_key".into(),
            ConfigValue::Secret(SecretString::new("hunter2")),
        );
        cfg.insert("broker".into(), ConfigValue::Nested(broker));
        let view = masked_config_view(&schema, &cfg);
        assert_eq!(
            view,
            json!({
                "host": "h",
                "api_key": {"secret": true, "set": true, "value": "***"},
                "optional_token": {"secret": true, "set": false, "value": null},
                "broker": {
                    "password": {"secret": true, "set": true, "value": "***"},
                    "port": 1883
                }
            })
        );
        let text = view.to_string();
        assert!(!text.contains("hunter2") && !text.contains("broker-pw"));
        let mut secrets = config_secrets(&cfg);
        secrets.sort_unstable();
        assert_eq!(secrets, vec!["broker-pw", "hunter2"]);
    }

    #[test]
    fn scrub_secret_values_skips_short_secrets() {
        let out = scrub_secret_values("pw hunter2 and ab", &["hunter2", "ab"]);
        assert_eq!(out, "pw *** and ab");
        // Overlapping and nested secrets leave no fragment behind.
        assert_eq!(
            scrub_secret_values("xabcdefghx", &["abcd", "abcdefgh"]),
            "x***x"
        );
        assert_eq!(
            scrub_secret_values("abcdefghi", &["abcdef", "defghi"]),
            "***"
        );
        // A long secret reaching back over an earlier, shorter run.
        assert_eq!(
            scrub_secret_values("abcdefgh cd", &["cdef", "abcdefgh"]),
            "*** cd"
        );
        assert_eq!(
            scrub_secret_values("xbcdx abcdefgh", &["bcdx", "abcdefgh"]),
            "x*** ***"
        );
        assert_eq!(scrub_secret_values("aaaaa", &["aaaa"]), "***");
        assert_eq!(scrub_secret_values("aaaa-aaaa", &["aaaa"]), "***-***");
        let big = "a".repeat(1 << 20);
        assert_eq!(scrub_secret_values(&big, &["aaaa"]), "***");
        // A long repetitive secret against a long repetitive line stays
        // linear (the old prefix-compare loop was quadratic here).
        let long_secret = "a".repeat(512 << 10);
        assert_eq!(scrub_secret_values(&big, &[&long_secret]), "***");
        assert!(matches!(
            scrub_secret_values("clean", &["hunter2"]),
            Cow::Borrowed(_)
        ));
    }

    #[test]
    fn withhold_bytes_replaces_only_bytes() {
        let mut kvs = vec![
            KeyValue {
                key: "snapshot".into(),
                value: Value::BytesVal(vec![1, 2, 3]),
            },
            KeyValue {
                key: "on".into(),
                value: Value::BoolVal(true),
            },
        ];
        withhold_bytes_in_kvs(&mut kvs);
        let Value::JsonVal(marker) = &kvs[0].value else {
            panic!("bytes should become a json marker");
        };
        let marker: JsonValue = serde_json::from_str(marker).unwrap();
        assert_eq!(
            marker,
            json!({"withheld": "bytes", "size_bytes": 3, "required_scope": "blobs:read"})
        );
        assert!(matches!(kvs[1].value, Value::BoolVal(true)));
    }
}
