# How to use spillgate in your Go service

This guide is for the developers who build the service: where to put spillgate, how to choose
the limits, how to wire it into HTTP clients, servers and other data paths, and what to do
with the results. The API reference is in the package documentation; the rules behind it are
in [spec/SPEC.md](../spec/SPEC.md).

## 1. What spillgate protects you from

Any code that decompresses bytes someone else controls can be made to allocate gigabytes from a
few kilobytes (a decompression bomb), by a single layer, by a chain of encodings
(`Content-Encoding: gzip, gzip, gzip, ...`), by lying size fields, or by exotic codecs.
spillgate sits in front of the decompressor and turns each of those into a typed error with
bounded memory. It does not replace limits on the compressed size, timeouts or authentication.

The rule of thumb: **every place where your service turns compressed bytes into plain bytes must
go through spillgate**. Section 6 shows how to find those places.

## 2. Choose the limits

`Limits` has one required field and four optional ones:

| Field | What it bounds | Default |
| --- | --- | --- |
| `MaxOutput` | bytes **each layer** may produce (required) | none |
| `MaxLayers` | non-identity encodings in one chain (1..16) | 5 |
| `MaxRatio` | output bytes per input byte the decoder consumed | 1000 |
| `RatioGrace` | output size below which the ratio is not checked | 64 KiB |
| `DisableRatioLimit` | named opt-out of the ratio check | off |
| `WithMaxInput(n)` | compressed bytes taken from the source (option) | none |

### MaxOutput: the memory you are willing to spend

Think of it as "the largest legitimate body this endpoint should ever see, after decompression".
Do not use one global number:

| Data path | Starting point |
| --- | --- |
| JSON API request bodies | 1 to 10 MiB |
| HTML or JSON fetched from third parties | 8 to 32 MiB |
| File upload processed in memory (`DecodeAll`) | the largest file you accept, and no more |
| File upload streamed to disk | your storage quota per object, enforced by `MaxOutput` plus your own accounting |
| Message queue payloads | the broker's maximum message size times a small factor |

Look at the 99.9th percentile of real decoded sizes in production and add headroom. A limit that
is 100 times larger than anything legitimate only helps the attacker. `DecodeAll` and `ReadAll`
hold the whole body in memory, so `MaxOutput` is also their peak memory per call; multiply by
your concurrency.

### MaxRatio and RatioGrace

The ratio is checked per layer and end to end. The default of 1000 stops the classic bombs
(zeros compress to about 1030:1 in DEFLATE at best) while ordinary data stays far below it
(typical JSON about 350:1 at the extreme). Raise it only if a measured, legitimate data type
needs it. Brotli and zstd can reach much higher ratios on sparse data, so a service that
accepts, for example, large sparse tensors or logs full of repeated lines may need a higher
`MaxRatio` for that endpoint. Prefer raising `MaxRatio` for one endpoint to switching the check
off; `DisableRatioLimit` leaves only `MaxOutput` between you and a bomb.

`RatioGrace` exists so tiny messages are not refused for compressing well. Leave it.

### MaxLayers

Real traffic uses one layer, rarely two. The default of 5 is generous; use 2 or 3 for public
endpoints. Chains longer than 16 elements are refused whatever you set.

### MaxInput

If the compressed size is not already bounded by your HTTP server or broker (for example
`http.MaxBytesReader`, `Server.ReadTimeout`, a message size limit), add `WithMaxInput`.
spillgate bounds the output; it is not a substitute for limiting how many bytes you accept.

## 3. Wire it in

Create one `Decoder` at start-up and share it. It is immutable and safe for concurrent use.

```go
import (
    "github.com/FelixMiddelhoff/spillgate"
    "github.com/FelixMiddelhoff/spillgate/br"   // optional: brotli
    "github.com/FelixMiddelhoff/spillgate/zstd" // optional: zstd (needs Go 1.25)
)

var decoder = mustDecoder()

func mustDecoder() *spillgate.Decoder {
    d, err := spillgate.NewDecoder(
        spillgate.Limits{MaxOutput: 8 << 20, MaxLayers: 3},
        spillgate.WithMaxInput(2<<20),
        br.Enable(), zstd.Enable(),
    )
    if err != nil {
        panic(err) // invalid limits are a programming error: fail at start-up
    }
    return d
}
```

`NewDecoder` validates everything and reads no data. Invalid limits (zero `MaxOutput`, negative
values) fail here, not on the first request.

### 3.1 HTTP client

Use the `httpx` transport. It always sends its own `Accept-Encoding`, so the standard library
never decodes first, and it bounds every body, with or without `Content-Encoding`.

```go
import "github.com/FelixMiddelhoff/spillgate/httpx"

client := &http.Client{
    Transport: httpx.NewTransport(nil, decoder, "gzip", "deflate", "br", "zstd"),
    Timeout:   30 * time.Second,
}
resp, err := client.Get(url)
if err != nil {
    // includes ErrUnsupportedEncoding / ErrMalformedEncoding / ErrLayerLimit:
    // the response headers were refused before any body byte was read
    return handleDecodeErr(err)
}
defer resp.Body.Close()
body, err := io.ReadAll(resp.Body) // limit errors appear here
if err != nil {
    return handleDecodeErr(err)
}
```

Offer in `Accept-Encoding` only what your decoder supports (the optional modules must be
enabled on it). The decoded response has `Content-Encoding` and `Content-Length` removed,
`ContentLength` set to -1 and `Uncompressed` true. If you already wrap the transport (tracing,
retries), put `httpx.Transport` closest to the network.

### 3.2 HTTP server: request bodies

```go
mux := http.NewServeMux()
mux.HandleFunc("/ingest", func(w http.ResponseWriter, r *http.Request) {
    body, err := io.ReadAll(r.Body) // already decoded and bounded
    if err != nil {
        httpx.Fail(w, err) // 413 / 415 / 400 with a fixed text, no attacker data
        return
    }
    process(body)
})
http.ListenAndServe(":8080", httpx.Middleware(decoder)(mux))
```

The middleware refuses an unsupported, malformed or too deep `Content-Encoding` with 415, 400 or
413 before your handler runs. Limit errors that appear while reading are returned by `r.Body`;
the handler must pass them to `httpx.Fail` (or `httpx.StatusFor` if you write your own
response). If the handler has already started writing the response, the status can no longer
change: read the body first, respond second. Keep `http.MaxBytesReader` or
`Server.MaxHeaderBytes` for the compressed size.

### 3.3 Any other source: files, S3 objects, queues, gRPC

`Reader` takes any `io.Reader` and the encodings as received:

```go
r, err := decoder.Reader(obj, "gzip") // obj: an S3 GetObject body, a file, a message payload
if err != nil { return handleDecodeErr(err) } // header problems: nothing was read
defer r.Close()                                // does not close obj
n, err := io.Copy(dst, r)
if err != nil { dst.Discard(); return handleDecodeErr(err) }
```

For content stored with a known encoding (a `.gz` object) pass the encoding yourself:
`decoder.Reader(f, "gzip")`. Pass `nil` or no encodings for plain data that should still be
bounded.

### 3.4 Whole body versus streaming

- `DecodeAll` / `Decoder.ReadAll`: simplest, returns the complete body or an error and **no
  data**. Peak memory is the decoded size, at most `MaxOutput`.
- `Reader`: streaming. **Bytes can be delivered before a later error.** Whatever you did with
  them (written to a file, sent to a parser, stored in a database) must be undone or discarded
  when an error comes. Write to a temporary file and rename on success; give parsers a way to
  abort; never commit a partial body.

### 3.5 Cancellation

`decoder.ReaderContext(ctx, src, encodings...)` and `ReadAllContext` stop at the next read once
the context ends, with `ErrCanceled` (and the context's own error reachable through
`errors.Is`). It cannot interrupt a read of your source that is already blocked; use deadlines
on the connection for that.

### 3.6 Your own codec (snappy, lz4, ...)

Register it explicitly on the decoder with `spillgate.WithCodec(name, codec)`. It runs behind the
same limiter, so even a careless codec cannot exceed `MaxOutput`. Do not register built-in
names. See the `Codec` documentation for the contract.

## 4. Handle the results

Every refusal is a `*spillgate.Error`. Use `errors.Is` with the sentinels, or
`errors.As` to read `Kind`, `Layer` and `Limit`.

```go
func handleDecodeErr(err error) error {
    var e *spillgate.Error
    if !errors.As(err, &e) {
        return err // not a decoding error: your source, your code
    }
    switch e.Kind {
    case spillgate.KindOutputLimit, spillgate.KindRatioLimit,
        spillgate.KindLayerLimit, spillgate.KindInputLimit:
        metrics.DecodeRefused.WithLabelValues(e.Kind.String()).Inc()
        log.Warn("decompression bomb suspected", "kind", e.Kind, "layer", e.Layer, "limit", e.Limit)
    case spillgate.KindCorrupt, spillgate.KindUnsupportedEncoding, spillgate.KindMalformedEncoding:
        metrics.DecodeRefused.WithLabelValues(e.Kind.String()).Inc()
    case spillgate.KindSource, spillgate.KindCanceled:
        // the transport or the caller ended it; not an attack signal
    case spillgate.KindMemoryLimit, spillgate.KindInternal:
        log.Error("decoder problem", "kind", e.Kind, "layer", e.Layer) // look at these
    }
    return err
}
```

### What each outcome means and what to do

| Kind | Meaning | Server answers | Client side | Log / metric |
| --- | --- | --- | --- | --- |
| `output_limit` | the data decodes to more than `MaxOutput` | 413 | treat the response as failed, do not retry | warn, count; a spike is an attack or a limit that is too low |
| `ratio_limit` | expansion over `MaxRatio` | 413 | failed, do not retry | warn, count; check if a legitimate data type needs a higher ratio |
| `layer_limit` | more layers or elements than allowed | 413 (or 400) | failed, do not retry | warn, count |
| `input_limit` | more compressed bytes than `MaxInput` | 413 | failed, do not retry | warn, count |
| `unsupported_encoding` | a valid token the decoder cannot handle (`compress`, `dcz`, `aes128gcm`, ...) | 415 | failed; nothing was decoded | info; shows clients using something you do not offer |
| `malformed_encoding` | the header breaks the strict grammar | 400 | failed | info, bounded text only |
| `corrupt` | the stream is invalid, truncated or has trailing data | 400 | may retry once if the connection was cut; a repeat is a bad server | info |
| `memory_limit` | brotli or zstd stream needs a larger window than the cap | 413 | failed, do not retry | warn; check the cap if legitimate traffic hits it |
| `source_error` | your reader (network, disk) failed | 5xx or 400 | retry according to your usual policy | the cause is the original error (`Unwrap`) |
| `canceled` | the context ended | no response needed | no retry by itself | debug |
| `internal` | a codec broke its contract or panicked | 500 | failed | **error and alert**: please report it (see `SECURITY.md`) |
| `invalid_limits` | bad configuration | - | - | fails at `NewDecoder`, never during traffic |

General rules:

1. **Any error means the whole body is unusable**, including the bytes you already received.
2. **Never retry a limit error.** The same input gives the same result and costs the same work.
3. **Do not echo error details to the caller.** `httpx.Fail` uses fixed texts. The library's own
   messages contain at most 32 bytes of attacker data, quoted and escaped, but your logs and
   responses are your decision; log the `Kind`, `Layer` and `Limit` and a request ID, not the body.
4. **Treat repeated limit errors from one client as abuse**: rate-limit or block by the same rules
   you use for other malformed input. One `ratio_limit` can be an accident; thousands from one
   address are not.
5. **Alert on `internal` and on `memory_limit`** rather than on the limit errors you expect.

### Tuning after launch

Run for a few days with the limits at their intended values and count refusals per endpoint. If
legitimate traffic is refused, raise the specific limit for that endpoint by the smallest amount
that fixes it and write down why. Do not switch limits off to make an alert go away.

## 5. Test your integration

1. **Build a bomb and see it refused.** The conformance corpus has ready inputs
   ([conformance/](../conformance)); or in a test, 1 GiB of zeros compressed with gzip is about
   1 MiB, e.g. with `io.Copy(gzipWriter, zeroReader{n})`.

   ```go
   func TestEndpointRefusesBombs(t *testing.T) {
       srv := httptest.NewServer(httpx.Middleware(decoder)(handler))
       defer srv.Close()
       req, _ := http.NewRequest("POST", srv.URL, bytes.NewReader(gzipBomb(t, 1<<30)))
       req.Header.Set("Content-Encoding", "gzip")
       resp, err := http.DefaultClient.Do(req)
       if err != nil { t.Fatal(err) }
       if resp.StatusCode != http.StatusRequestEntityTooLarge {
           t.Fatalf("status %d, want 413", resp.StatusCode)
       }
   }
   ```
2. **Test every ingress.** Each endpoint and each background consumer gets one bomb test, one test
   with `Content-Encoding: gzip, gzip, gzip, gzip, gzip, gzip, gzip`, and one with an unknown
   encoding (`Content-Encoding: compress`).
3. **Check memory.** Run the bomb test with `GOMEMLIMIT` set low in a subprocess, or assert on
   `runtime.MemStats` before and after.
4. **Test the partial-data rule.** Make the handler's downstream step fail midway and check that
   nothing from the failed body is committed.

## 6. Find and fix the places that decompress today

Search your code base and dependencies for the paths that turn compressed bytes into data:

```
grep -rnE 'gzip\.NewReader|zlib\.NewReader|flate\.NewReader|brotli\.NewReader|zstd\.NewReader|zstd\.Decode|ioutil.ReadAll\(.*gzip' .
```

and, in frameworks, for things that decode for you: gzip request middleware, gRPC compressors
(`grpc.UseCompressor`, `encoding/gzip` registration), `http.Transport` with
`DisableCompression: false` and no explicit `Accept-Encoding` (Go then decodes responses with
no limit), SDK clients that wrap `http.Client`, S3/GCS client helpers that decompress objects,
log shippers, archive extractors. For each: replace the decoder with spillgate, or wrap it so
the library never sees unbounded data. If a third-party client builds its own transport, hand it
`httpx.NewTransport(...)` instead of its default.

## 7. Pitfalls

- **Decoding in two places.** If a proxy, middleware or SDK decodes before spillgate, spillgate
  sees plain data and only bounds it; the bomb has already been expanded. Make sure the first
  decoder in the path is spillgate.
- **Reading the body twice.** After a decode error the reader is spent. Do not fall back to
  "just read it plainly".
- **Using `Reader` and ignoring the error of the last `Read`.** `io.Copy` and `io.ReadAll` return
  it; manual loops must check it.
- **A huge `MaxOutput` "to be safe".** It makes the guard useless. Size it from data.
- **`DisableRatioLimit` as a first reaction.** See the tuning section.
- **Unbounded concurrency.** Each in-flight request may hold up to `MaxOutput` bytes with
  `DecodeAll`, and brotli/zstd add their window (up to 16 MiB and 8 MiB by default; lower them
  with `br.MaxWindowBits` and `zstd.MaxWindowBytes` for busy servers).
- **Treating `identity` as safe.** An unencoded body is bounded as well; that is deliberate.

## 8. Checklist before you ship

- [ ] One shared `Decoder`, created at start-up, limits chosen per data path from real sizes.
- [ ] Every ingress (HTTP, queue, file, gRPC, SDK) goes through spillgate; no other decoder runs before it.
- [ ] The compressed size is bounded separately (`MaxBytesReader`, broker limit or `WithMaxInput`).
- [ ] Streaming consumers discard or roll back partial data on any error.
- [ ] Limit errors map to 413, unsupported encodings to 415, malformed or corrupt data to 400.
- [ ] Metrics per `Kind`; alerts on `internal` and `memory_limit`; refusals visible per endpoint.
- [ ] No retries of limit errors; no echoing of attacker-supplied text.
- [ ] Bomb, deep-chain and unknown-encoding tests exist for every ingress and run in CI.
- [ ] You know who gets the report if `internal` appears (see [SECURITY.md](../SECURITY.md)).
