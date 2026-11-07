# Conformance generators

The conformance corpus (`conformance/manifest.json`) describes large inputs by a generator specification instead of a file. Generation is deterministic and independent of any compression library, so every implementation, in any language, can reproduce the bytes and check them against the SHA-256 in the manifest. The Go implementation is `internal/corpus`.

A spec is `{"kind": "...", "params": {...}}`.

## Building blocks

**Bit packing.** DEFLATE fields are written starting at the least significant bit of each byte. Huffman codes are written most significant bit first.

**Data(seed, size).** xorshift64 over 64-bit unsigned arithmetic: `state = seed * 0x9e3779b97f4a7c15 + 1`; for each output byte: `state ^= state << 13; state ^= state >> 7; state ^= state << 17; byte = (state >> 24) & 0xff`. The bytes do not compress.

**StoredDeflate(data).** Stored blocks of at most 65535 bytes each: one header byte (BFINAL in bit 0, BTYPE 00), LEN and NLEN (little-endian), then the bytes. The last block has BFINAL set. Empty data is one empty final block.

**ZerosDeflate(matches).** One dynamic Huffman block that decodes to `1 + 258 * matches` zero bytes at about 1032:1:

| Field | Value |
|-------|-------|
| BFINAL, BTYPE | 1, 2 (dynamic) |
| HLIT, HDIST, HCLEN | 29, 1, 14 |
| code-length code lengths, order 16 17 18 0 8 7 9 6 10 5 11 4 12 3 13 2 14 1 | 0 0 1 0 0 0 0 0 0 0 0 0 0 0 0 2 0 2 |
| literal/length lengths | symbol 0: 2, symbol 256: 2, symbol 285: 1, all others 0 |
| distance lengths | symbol 0: 1, symbol 1: 1 |
| data | literal 0 (`10`), then `matches` times: length symbol 285 (`0`) and distance symbol 0 (`0`), then end of block (`11`) |

The literal/length and distance code lengths are written with the code-length alphabet: symbol 18 = `0` (7 extra bits, repeat count minus 11), symbol 1 = `10`, symbol 2 = `11`. The sequence is: 2; zero run 138; zero run 117; 2; zero run 28; 1; then the distance lengths 1, 1.

**gzip member.** Header `1f 8b 08 00 00 00 00 00 00 ff`, the raw DEFLATE stream, CRC-32 and size modulo 2^32 (both little-endian) of the decoded data. Optional header fields (FEXTRA, FNAME, FCOMMENT, FHCRC) follow RFC 1952.

**zlib stream.** Header `78 01`, the raw DEFLATE stream, Adler-32 of the decoded data (big-endian).

## Kinds

| Kind | Params | Result |
|------|--------|--------|
| `zeros` | `codec` (`gzip`, `zlib`, `raw`), `matches` | ZerosDeflate wrapped by the codec; decodes to `1 + 258 * matches` zeros |
| `data` | `codec`, `seed`, `size` | StoredDeflate of Data(seed, size) wrapped by the codec |
| `wrap` | `codec`, `times`, `inner` (a spec) | the output of `inner`, wrapped `times` times in a stored stream of `codec` |

`raw` means no wrapper (a raw DEFLATE stream).
