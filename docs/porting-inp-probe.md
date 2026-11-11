# Porting note: the byte after MaxInput (SG-R-INP-01, corpus 0.2.0)

Audience: the Python, JS/TS, Rust and Java ports. Implement this exactly; the corpus 0.2.0 vectors `SG-V-BND-0041` to `SG-V-BND-0057` check it.

## The rule

With MaxInput = M, a codec that TAKES byte number M+1 (the probe) is `input_limit`. Looking at it is not a violation. SG-R-INP-02 stays: never request more than M+1 bytes from the source in total.

1. Fetching the probe into your buffer, or showing it to the codec as look-ahead, never causes `input_limit`. Only the count of bytes the codec has consumed matters.
2. If that count would exceed M, the result is `input_limit`. Check it at the end of EVERY codec step (every call into the codec's read), even if the codec does not ask for more. It overrides what the codec returned in that step (data, EOF or corrupt). A codec that needs byte M+1 to finish (stream cut at the limit, source goes on) takes it and ends in `input_limit`, not `corrupt`. Only if the SOURCE really ends is the stream truncated (`corrupt`).
3. After a complete stream, a codec that sees bytes behind it reports them under its own rules (`corrupt` for gzip, deflate/zlib, brotli, zstd) and does NOT take the first of them, even when that byte is the probe.
4. Identity (and an identity-only chain) consumes everything it passes: one byte beyond M is `input_limit`, after exactly M bytes were delivered.
5. Only layer 1 has MaxInput. Inner layers are unlimited.

## How the Go reference does it

- `inputMeter` keeps `fetched` (from the source, capped at M+1) and `consumed` (handed to the codec). It is the strict view used for identity: it never hands out the probe.
- Codecs get a second view, `codecSource`. `ReadByte` and `Read` may hand out the probe. `Read` never returns the probe together with earlier bytes: it is cut off and comes alone in the next call, so a codec that fills a read-ahead buffer is not charged for a byte it never uses. `UnreadByte` gives the probe back (it works only for the probe, and refuses otherwise): `consumed` goes down by one.
- The layer guard calls `checkTaken()` right after every codec read: `consumed > M` gives `input_limit`.
- Codecs that find trailing data call `UnreadByte` before they return `corrupt`: gzip (first byte after a member is not `0x1f`), deflate/zlib (any byte after the end), zstd (first byte after a frame cannot start a frame: not `0x28`, not `0x50..0x5f`), brotli (the library reports "excessive input": give the probe back).

A port without `UnreadByte` can do the same with a peek API on its buffer: peek shows the probe without counting it, take counts it. The codec calls peek to look for trailing data; the end-of-step check uses the take count.

Known edge, same in every port: if the probe could itself begin another structure (gzip `0x1f`, zstd `0x28`/`0x50..0x5f`), the codec takes it, because it cannot know the source ends without asking for byte M+2, which SG-R-INP-02 forbids. That gives `input_limit` for M = L and `corrupt` for M = L+1.

## Worked examples

Let a valid gzip stream be L = 40 bytes.

1. Stream + one byte `0x00`, M = 40. The decoder fetches 41 bytes. Gzip finishes the member (40 consumed), reads the next byte (the probe, consumed 41), sees it is not `0x1f`, gives it back (consumed 40) and returns `corrupt`. End-of-step check: 40 <= 40, so the result is `corrupt`. (Old behaviour: `input_limit`.) With M = 41 the result is also `corrupt`.
2. The same stream, M = 39, source holds 100 bytes. Gzip needs byte 40 of the stream: it is the probe, consumed becomes 40 > 39 at the end of the step (or the next read fails), so `input_limit`. If the source ends after 39 bytes, the next read is EOF and the result is `corrupt` (truncated).
3. Identity body of 41 bytes, M = 40. Identity passes 40 bytes to the caller; asking for the 41st is `input_limit` after exactly 40 delivered. A body of exactly 40 bytes is `ok`.

Brotli variant of example 1: the library reads up to 32 KiB in one call. The wrapper hands it the first 40 bytes only; when the library asks again (to check for trailing data) it gets the probe alone, reports "excessive input", and the wrapper gives the probe back. Result `corrupt`.
