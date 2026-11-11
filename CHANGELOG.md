# Changelog

All notable changes are listed here. Versions below 1.0 may still change the API.

## Unreleased

- SG-R-INP-01 is exact: looking at the byte after MaxInput (to find trailing data) is no longer `input_limit`; taking it is. A complete stream of MaxInput bytes followed by data is `corrupt`. Corpus 0.2.0 adds 17 `BND` vectors. See `docs/porting-inp-probe.md`.

## v0.1.0 - 2026-11-11

First public version. Modules: `spillgate` and `spillgate/httpx` (tag `v0.1.0`), `spillgate/br` (tag `br/v0.1.0`), `spillgate/zstd` (tag `zstd/v0.1.0`).

- Core: `Limits` with a mandatory `MaxOutput`, expansion-ratio limit, chain-length limit, optional `MaxInput`; per-layer budgets; typed, sticky errors; strict `Content-Encoding` parsing; own gzip and zlib framing over `compress/flate`.
- Optional codecs as separate modules: `br` (brotli, pure Go) and `zstd` (own frame scanner, window caps).
- `httpx`: client `RoundTripper` and server middleware for `net/http`, with status mapping for limit errors.
- Specification (`spec/SPEC.md`, 74 numbered rules) and a conformance corpus of 353 vectors.
