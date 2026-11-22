# ADR-0002: Native media and inference stay in-process, with strict limits

- **Status:** accepted
- **Date:** 2026-11-22
- **Deciders:** the maintainer
- **Supersedes:** none
- **Superseded by:** none
- **References:** architecture review finding H7; `ARCHITECTURE.md` "Streaming and media" and "AI / ML plugins"

## Context

Plugins describe media pipelines and inference requests; the host runs them natively (GStreamer or FFmpeg, ONNX
Runtime). That makes the daemon a confused deputy: a plugin-supplied `file://` URL, a redirect or DNS answer that
points at a private address, or a free-form codec or filter name lets a sandboxed plugin reach what the sandbox
denies. The native parsers are also FFI code, so malformed bytes can crash the process.

## Decision

Media and inference run in the daemon process, and the host validates every plugin-controlled input before native
code sees it:

- Media sources are typed (for example RTSP or HTTP with a host and port), not free-form URL strings.
- `file://` and other local-file sources are refused.
- Credentials are passed as references to host-held secrets, never as URLs with embedded user names or passwords.
- Network policy is checked on the resolved IP address and again on every redirect, not only on the host name.
- Codecs and filters come from an allowlist.
- Tensor shapes and byte sizes are validated, with overflow-checked arithmetic, before any native inference call.

## Rejected options

- **Out-of-process media and inference workers.** Stronger isolation, but a large cost in IPC, frame copying and
  operations before Phases 8–10 have even started. We may revisit this if a sandbox escape or a class of crashes in
  the native libraries shows up.
- **Deferring native media.** The camera and AI use cases depend on native pipelines; WASM cannot decode video at
  frame rate.

## Consequences

- A bug in a native parser can still crash the daemon, taking every plugin down with it. We accept that risk.
- The WIT media and inference types change from strings to typed sources and credential references before Phases
  8–10 ship.
- The validation rules above are part of the media and inference phases' definition of done.
