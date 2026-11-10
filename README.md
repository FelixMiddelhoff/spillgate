# spillgate

Decode untrusted compressed data in Go with mandatory limits. A decompression
bomb ends in a typed error instead of exhausting memory.

```go
data, err := spillgate.DecodeAll(body, []string{"gzip"}, spillgate.Limits{MaxOutput: 8 << 20})
if errors.Is(err, spillgate.ErrOutputLimit) { /* refuse, 413 */ }
```

- Content-Encoding chains: `gzip` (and `x-gzip`), `deflate`, `br`, `zstd`, `identity`.
- `MaxOutput` is required. There is no unlimited setting.
- Every layer is limited, including intermediate layers of a chain.
- Expansion ratio and chain length are limited by default.
- Unknown, malformed or too deep `Content-Encoding` headers are refused, never passed through.
- The core module has no dependencies. Brotli and zstd are separate modules.

## Install

```
go get github.com/FelixMiddelhoff/spillgate         # core: gzip, deflate, httpx
go get github.com/FelixMiddelhoff/spillgate/br      # optional: brotli
go get github.com/FelixMiddelhoff/spillgate/zstd    # optional: zstd (needs Go 1.25)
```

Core and `br` need Go 1.23. `zstd` needs Go 1.25, because the zstd library
version without a known decoder panic requires it.

## Use

A step-by-step guide for integrating it into a service, including limits, HTTP client and server wiring and how to handle each result: [docs/how-to.md](docs/how-to.md).

```go
d, err := spillgate.NewDecoder(spillgate.Limits{MaxOutput: 8 << 20},
    br.Enable(), zstd.Enable())          // optional codecs

r, err := d.Reader(resp.Body, resp.Header.Values("Content-Encoding")...)
defer r.Close()
n, err := io.Copy(dst, r)                // any error means: discard everything
```

`DecodeAll` / `ReadAll` return the whole body or an error and no data.
`Reader` streams; bytes may arrive before a later error, so treat any error as
failure of the whole body.

### Limits

| Field | Meaning | Default |
| --- | --- | --- |
| `MaxOutput` | bytes one layer may produce (required, > 0) | none |
| `MaxLayers` | longest chain (1..16) | 5 |
| `MaxRatio` | output bytes per input byte consumed by the codec | 1000 |
| `RatioGrace` | output below which the ratio is not checked | 64 KiB |
| `DisableRatioLimit` | explicit opt-out of the ratio limit | off |
| `WithMaxInput(n)` | cap on compressed bytes consumed (option) | none |

The ratio default is measured: zeros compress to about 1029:1 in the best case
for deflate, typical JSON to about 347:1. Raise `MaxRatio` for data you know to
be sparser.

Notes on the limits:

- `DecodeAll` / `ReadAll` hold the whole body in memory, so `MaxOutput` is the
  memory you are willing to spend per call. Choose a realistic value; for large
  bodies stream with `Reader` instead. On 32-bit platforms keep it far below 2 GiB.
- The ratio is evaluated after each `Read` of the codec, which for the codecs
  here delivers at most one block (about 32 KiB for deflate). `MaxOutput` and
  `MaxInput` are the hard bounds; the ratio limit catches bombs early.
- A source error is reported as `source_error` with the source's own text in
  `Cause`; that text is not shortened like header tokens are.

### Errors

Every refusal is a `*spillgate.Error` with a `Kind`; use `errors.Is` with
`ErrOutputLimit`, `ErrRatioLimit`, `ErrLayerLimit`, `ErrInputLimit`,
`ErrMemoryLimit`, `ErrUnsupportedEncoding`, `ErrMalformedEncoding`,
`ErrCorrupt`, `ErrCanceled`, `ErrSource`, `ErrInternal`, `ErrInvalidLimits`.
Errors are sticky: after a limit error every later `Read` returns the same
error, never `io.EOF`. Error text never echoes attacker data unbounded.

### net/http

```go
client := &http.Client{Transport: httpx.NewTransport(nil, decoder)}           // responses
http.Handle("/", httpx.Middleware(decoder)(handler))                         // request bodies
```

`httpx` always sends its own `Accept-Encoding`, so the standard transport never
decodes first. In a handler answer a failed body read with
`httpx.Fail(w, err)`: 413 for limits, 415 for unsupported encodings, 400 for
corrupt data.

## What it does not cover


See [docs/threat-model.md](docs/threat-model.md). In short: archives (zip, tar),
bounding the compressed input (use `WithMaxInput` or `http.MaxBytesReader`),
connection timeouts, encrypted content, and memory-safety bugs inside the
codec libraries beyond what the limits and the panic recovery contain.
Brotli and zstd windows cost memory per request up to their caps (16 MiB and
8 MiB by default); lower them with `br.MaxWindowBits` / `zstd.MaxWindowBytes`
when many requests decode at once.

## Specification and tests

The rules are language-neutral and numbered in [spec/SPEC.md](spec/SPEC.md).
[conformance/](conformance) holds 353 test vectors (bombs, malformed streams,
header attacks, lying size fields) that every implementation must pass.
The suite also covers the published advisories for decompression-limit bugs;
see [docs/cve-coverage.md](docs/cve-coverage.md). The tests include fuzzing,
differential tests against reference encoders, memory canaries and 32-bit builds.

## License

MIT, see [LICENSE](LICENSE). Report vulnerabilities as described in
[SECURITY.md](SECURITY.md).
