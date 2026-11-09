# Threat model

## Attacker
Controls the compressed bytes and the Content-Encoding header value(s) of data the application decodes (HTTP responses from untrusted servers, HTTP request bodies, uploaded blobs). Cannot change application code or configuration.

## Goals the attacker has
Memory exhaustion, CPU exhaustion, disk exhaustion (only if the caller spools output), process crash, bypassing a limit that the caller believes is active.

## In scope (spillgate must stop these)
1. Single-layer bombs (gzip, deflate, br, zstd) of any ratio.
2. Multi-layer chains, header-spam chains, identity spam.
3. Lying or absent size declarations (gzip ISIZE, zstd frame content size, zero, huge, negative-looking).
4. Streaming read-pattern games (tiny reads, huge reads, read-after-error, zero-length reads).
5. Codec disguises (header says X, payload is Y), unknown and exotic encodings.
6. Corrupt, truncated, trailing-garbage and multi-member streams.
7. Decoder panics on hostile input.
8. Decoder state/window memory inflation independent of output size (large zstd/brotli windows, giant gzip header fields).
9. Header injection through error strings (log injection, unbounded echo).
10. Limit-option misuse that silently disables protection (zero values, negatives, overflow, float NaN/Inf).

## Out of scope (documented, not solved)
- Container formats and archives (zip, tar, 7z; overlapping-entry zip bombs, path traversal).
- Input flooding of the compressed side (caller must bound compressed bytes; `MaxInput` is optional help).
- Slow-loris / connection timeouts (use net/http timeouts).
- Encrypted content (`aes128gcm`).
- Vulnerabilities inside third-party codecs beyond what the limiter can contain (memory-safety bugs); mitigated by pure-Go choice and recover, not eliminated.
- Callers that do not use spillgate, or clients that decode internally before spillgate sees the data.

## Residual risks (stated plainly in the README)
- CPU time: output and ratio limits bound work in practice, but a decoder can spend time per input byte. Mitigations: ratio, `MaxInput`, context checks between reads.
- Decoder memory (zstd/brotli window) is bounded by configured caps, not by `MaxOutput`.
- Partial data is delivered before the terminal error in streaming mode; consumers must treat any error as total failure (`DecodeAll` enforces this).

## Dependencies (br and zstd modules)
- `andybalholm/brotli` v1.2.8 (pure Go port of the reference decoder) and `klauspost/compress` v1.20.3, pinned. The core module has none.
- Known advisory: klauspost/compress GHSA-fpmh-frq8-7rj8 (CVE-2026-116591 as printed): zstd decoder panic on a crafted two-block frame, affects up to v1.20.1, fixed in v1.20.2. Mitigations in depth: pinned to a fixed version; stream decoding runs synchronously inside `Read` (concurrency 1), so the guard's recover turns any decoder panic into `internal`; a fuzz target runs against the module. A second advisory (GHSA-259r-337f-4rfw, s2 dictionary) concerns code that is not used.
- Upstream behavior worked around: the zstd library prints a debug line to stderr for every skippable frame and on some header errors; the module handles skippable frames and validates headers itself, so attacker input cannot spam stderr through the decoder.
- Memory per request: a hostile but valid header can make the decoder reserve its declared window up to the cap before any output: up to 16 MiB for brotli (default cap 2^24) and 8 MiB for zstd (default cap), measured (brotli window 24: 16.9 MB allocated; zstd window 2^23: 8.7 MB). Servers that decode many requests at once should lower the caps (`br.MaxWindowBits(22)`, `zstd.MaxWindowBytes(...)`) or limit concurrency; this is a residual risk, bounded by the cap, not by MaxOutput.
- Brotli large-window streams are not supported and are refused as `memory_limit`.
- Untested upstream: the library's reaction to a crafted compressed block (sequence section) that expands beyond its block; covered only by the limiter and by `recover` (ruzstd RUSTSEC-2026-0344 class).

## Security process (see also SECURITY.md)
- `SECURITY.md`: GitHub private vulnerability reporting, acknowledgment in 3 business days, coordinated disclosure up to 90 days, no bounty, credit on request.
- Every fixed bypass becomes a permanent conformance vector.
- Security-Reviewer pass is part of every milestone.
