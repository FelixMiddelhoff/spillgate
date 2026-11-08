package main

import (
	"bytes"
	"fmt"

	"github.com/FelixMiddelhoff/spillgate/internal/corpus"
)

// Vectors for the optional codecs. They carry the tag needs-br or needs-zstd,
// so an implementation without that codec skips them (conformance/SCHEMA.md).

func u64(n uint64) *uint64 { return &n }
func u32(n uint32) *uint32 { return &n }

func defineBrotli(b *builder) {
	tags := func(more ...string) []string { return append([]string{"brotli", "needs-br"}, more...) }

	b.addGenerated("BOMB", "large", vector{
		Description: "brotli bomb of 1 GiB in under a kilobyte (ratio above 1,000,000:1) against a 1 MiB output limit",
		Rules:       ids("SG-R-LAY-02", "SG-R-LAY-03", "SG-R-LAY-04", "SG-R-CDC-01", "SG-I-01", "SG-I-02"),
		Tags:        tags("bomb"),
		Encodings:   []string{"br"},
		Limits:      noRatio(1 << 20),
		Expect:      readError("output_limit", 1, 1<<20),
	}, corpus.ZerosOf("br", 1<<30, 24))

	b.addGenerated("BOMB", "large", vector{
		Description: "the same brotli bomb against MaxRatio 100: a ratio error, far from the threshold",
		Rules:       ids("SG-R-RAT-01", "SG-R-RAT-05", "SG-I-02"),
		Tags:        tags("bomb", "ratio"),
		Encodings:   []string{"br"},
		Limits:      map[string]any{"max_output": 1 << 22, "max_ratio": 100, "ratio_grace": 1},
		Expect:      readErrorAtMost("ratio_limit", 1, 1<<22),
	}, corpus.ZerosOf("br", 1<<30, 24))

	for _, size := range []int64{2122, 25801} {
		for _, limit := range []int64{size - 1, size, size + 1} {
			v := vector{
				Description: fmt.Sprintf("brotli zeros stream of %d bytes with MaxOutput %d", size, limit),
				Rules:       ids("SG-R-LAY-02", "SG-R-LAY-03", "SG-R-LAY-04", "SG-I-01", "SG-I-02", "SG-I-09"),
				Tags:        tags("boundary"),
				Encodings:   []string{"br"},
				Limits:      noRatio(limit),
			}
			if limit < size {
				v.Expect = readError("output_limit", 1, limit)
			} else {
				v.Expect = okZeros(size)
			}
			b.addGenerated("BND", "small", v, corpus.ZerosOf("br", size, 16))
		}
	}

	// Window sizes: the format allows 2^10 .. 2^24; the default cap is 2^24.
	data := corpus.Data(7, 100)
	for _, wbits := range []int{10, 16, 17, 22, 24} {
		b.addGenerated("WIN", "small", vector{
			Description: fmt.Sprintf("brotli stream with window bits %d is accepted under the default cap", wbits),
			Rules:       ids("SG-R-CDC-04"),
			Tags:        tags("window", "ok"),
			Encodings:   []string{"br"},
			Limits:      generous,
			Expect:      okData(data),
		}, corpus.StoredWindow("br", 7, 100, wbits))
	}
	const cap1MiB = 1 << 20 // allows window bits up to 20: 2^20-16 <= 1 MiB < 2^21-16
	for _, wbits := range []int{10, 20, 21, 24} {
		v := vector{
			Description: fmt.Sprintf("brotli stream with window bits %d under a memory cap of 1 MiB", wbits),
			Rules:       ids("SG-R-CDC-04", "SG-I-08"),
			Tags:        tags("window"),
			Encodings:   []string{"br"},
			Limits:      generous,
			Options:     map[string]any{"memory_cap": cap1MiB},
		}
		if wbits <= 20 {
			v.Expect = okData(data)
			v.Tags = append(v.Tags, "ok")
		} else {
			v.Expect = readError("memory_limit", 1, 0)
		}
		b.addGenerated("WIN", "small", v, corpus.StoredWindow("br", 7, 100, wbits))
	}
	b.addFile("WIN", vector{
		Description: "a stream starting with the reserved large-window marker is refused as a memory request, not read as data",
		Rules:       ids("SG-R-CDC-04", "SG-I-06"),
		Tags:        tags("window", "cve"),
		Refs:        []string{"RUSTSEC-2026-0455"},
		Encodings:   []string{"br"},
		Limits:      generous,
		Expect:      readError("memory_limit", 1, 0),
	}, corpus.BrotliLargeWindowPrefix())

	// Malformed streams.
	stored := corpus.BrotliStored(data, 16)
	for _, n := range []int{0, 1, 2, len(stored) / 2, len(stored) - 1} {
		b.addFile("MAL", vector{
			Description: fmt.Sprintf("brotli stream truncated to %d of %d bytes", n, len(stored)),
			Rules:       ids("SG-R-CDC-06", "SG-I-05"),
			Tags:        tags("malformed"),
			Encodings:   []string{"br"},
			Limits:      generous,
			Expect:      corruptStream(1),
		}, stored[:n])
	}
	for _, tc := range []struct {
		desc string
		tail []byte
	}{
		{"one zero byte", []byte{0}}, {"512 zero bytes", make([]byte, 512)}, {"text", []byte("garbage")},
	} {
		b.addFile("MAL", vector{
			Description: "brotli stream followed by " + tc.desc,
			Rules:       ids("SG-R-CDC-04", "SG-I-06"),
			Tags:        tags("malformed"),
			Encodings:   []string{"br"},
			Limits:      generous,
			Expect:      corruptStream(1),
		}, append(bytes.Clone(stored), tc.tail...))
	}

	// Chains with other codecs, and the header spellings.
	b.addFile("CHAIN", vector{
		Description: "brotli applied first, then gzip",
		Rules:       ids("SG-R-HDR-12", "SG-R-CDC-01"),
		Tags:        tags("chain"),
		Encodings:   []string{"br, gzip"},
		Limits:      generous,
		Expect:      okData(data),
	}, corpus.GzipStored(stored))
	b.addFile("CHAIN", vector{
		Description: "gzip applied first, then brotli",
		Rules:       ids("SG-R-HDR-12", "SG-R-CDC-01"),
		Tags:        tags("chain"),
		Encodings:   []string{"gzip, br"},
		Limits:      generous,
		Expect:      okData(data),
	}, corpus.BrotliStored(corpus.GzipStored(data), 16))
	for _, enc := range []string{"br", "BR", " br ", "br,"} {
		b.addFile("HDR", vector{
			Description: fmt.Sprintf("accepted header with the optional codec: %q", enc),
			Rules:       ids("SG-R-HDR-05", "SG-R-HDR-08", "SG-R-HDR-14"),
			Tags:        tags("header"),
			Encodings:   []string{enc},
			Limits:      generous,
			Expect:      okData(data),
		}, stored)
	}
}

func defineZstd(b *builder) {
	tags := func(more ...string) []string { return append([]string{"zstd", "needs-zstd"}, more...) }
	data := corpus.Data(8, 100)

	b.addGenerated("BOMB", "large", vector{
		Description: "zstd bomb of 1 GiB in 32 KiB (ratio 32768:1) against a 1 MiB output limit",
		Rules:       ids("SG-R-LAY-02", "SG-R-LAY-03", "SG-R-LAY-04", "SG-R-CDC-01", "SG-I-01", "SG-I-02"),
		Tags:        tags("bomb"),
		Encodings:   []string{"zstd"},
		Limits:      noRatio(1 << 20),
		Expect:      readError("output_limit", 1, 1<<20),
	}, corpus.ZerosOf("zstd", 1<<30, 23))

	b.addGenerated("BOMB", "large", vector{
		Description: "the same zstd bomb against MaxRatio 100: a ratio error, far from the threshold",
		Rules:       ids("SG-R-RAT-01", "SG-R-RAT-05", "SG-I-02"),
		Tags:        tags("bomb", "ratio"),
		Encodings:   []string{"zstd"},
		Limits:      map[string]any{"max_output": 1 << 22, "max_ratio": 100, "ratio_grace": 1},
		Expect:      readErrorAtMost("ratio_limit", 1, 1<<22),
	}, corpus.ZerosOf("zstd", 1<<30, 23))

	for _, size := range []int64{2, 25801} {
		for _, limit := range []int64{size - 1, size, size + 1} {
			v := vector{
				Description: fmt.Sprintf("zstd zeros stream of %d bytes with MaxOutput %d", size, limit),
				Rules:       ids("SG-R-LAY-02", "SG-R-LAY-03", "SG-R-LAY-04", "SG-I-01", "SG-I-02", "SG-I-09"),
				Tags:        tags("boundary"),
				Encodings:   []string{"zstd"},
				Limits:      noRatio(limit),
			}
			if limit < size {
				v.Expect = readError("output_limit", 1, limit)
			} else {
				v.Expect = okZeros(size)
			}
			b.addGenerated("BND", "small", v, corpus.ZerosOf("zstd", size, 17))
		}
	}

	// Windows: the default cap is 8 MiB (8388608 bytes).
	raw := corpus.ZstdRawBlocks(data, corpus.ZstdBlockMax, true)
	frame := func(h corpus.ZstdHeader) []byte { return append(h.Bytes(), raw...) }
	window := func(desc string, h corpus.ZstdHeader, options map[string]any, expect expect) {
		v := vector{
			Description: desc,
			Rules:       ids("SG-R-CDC-05", "SG-I-08"),
			Tags:        tags("window"),
			Encodings:   []string{"zstd"},
			Limits:      generous,
			Options:     options,
			Expect:      expect,
		}
		b.addFile("WIN", v, frame(h))
	}
	for _, log := range []uint{10, 17, 22, 23} {
		window(fmt.Sprintf("zstd window 2^%d is accepted under the default cap", log), corpus.ZstdHeader{WindowLog: log}, nil, okData(data))
	}
	for _, log := range []uint{24, 30, 41} {
		window(fmt.Sprintf("zstd window 2^%d is above the default cap of 8 MiB", log), corpus.ZstdHeader{WindowLog: log}, nil, readError("memory_limit", 1, 0))
	}
	window("zstd window 4 MiB + 3.5 MiB (mantissa 7) is below the cap", corpus.ZstdHeader{WindowLog: 22, Mantissa: 7}, nil, okData(data))
	window("zstd window 8 MiB + 1 MiB (mantissa 1) is above the cap", corpus.ZstdHeader{WindowLog: 23, Mantissa: 1}, nil, readError("memory_limit", 1, 0))
	cap1MiB := map[string]any{"memory_cap": 1 << 20}
	window("zstd window 2^20 under a memory cap of 1 MiB", corpus.ZstdHeader{WindowLog: 20}, cap1MiB, okData(data))
	window("zstd window 2^21 under a memory cap of 1 MiB", corpus.ZstdHeader{WindowLog: 21}, cap1MiB, readError("memory_limit", 1, 0))

	// A single-segment frame has no window descriptor: its window is its declared content size.
	single := func(size uint64) corpus.ZstdHeader {
		return corpus.ZstdHeader{SingleSegment: true, ContentSize: u64(size)}
	}
	exact := append(single(8<<20).Bytes(), corpus.ZstdRLEBlocks(8<<20, corpus.ZstdBlockMax, 0, true)...)
	b.addFile("WIN", vector{
		Description: "single-segment frame with a declared and real content size of exactly 8 MiB",
		Rules:       ids("SG-R-CDC-05", "SG-R-CDC-07"),
		Tags:        tags("window", "ok"),
		Encodings:   []string{"zstd"},
		Limits:      generous,
		Expect:      okZeros(8 << 20),
	}, exact)
	for _, size := range []uint64{8<<20 + 1, 1 << 32, 1 << 63} {
		window(fmt.Sprintf("single-segment frame declaring %d bytes: the implied window is above the cap", size), single(size), nil, readError("memory_limit", 1, 0))
	}
	window("single-segment frame declaring 1 MiB + 1 under a memory cap of 1 MiB", single(1<<20+1), cap1MiB, readError("memory_limit", 1, 0))

	// Invalid frames.
	bad := func(desc string, stream []byte, rules ...string) {
		b.addFile("MAL", vector{
			Description: desc,
			Rules:       append(ids("SG-I-05", "SG-I-06"), rules...),
			Tags:        tags("malformed"),
			Encodings:   []string{"zstd"},
			Limits:      generous,
			Expect:      corruptStream(1),
		}, stream)
	}
	bad("a frame that needs dictionary 7", frame(corpus.ZstdHeader{WindowLog: 17, DictionaryID: u32(7)}), "SG-R-CDC-05")
	window("a dictionary id field holding 0 means no dictionary", corpus.ZstdHeader{WindowLog: 17, DictionaryID: u32(0)}, nil, okData(data))
	bad("reserved bit set in the frame header descriptor", frame(corpus.ZstdHeader{WindowLog: 17, ReservedBit: true}), "SG-R-CDC-05")
	header17 := corpus.ZstdHeader{WindowLog: 17}.Bytes()
	bad("reserved block type 3", append(bytes.Clone(header17), 0x07, 0x00, 0x00, 'x'), "SG-R-CDC-05")
	oversize := uint32(corpus.ZstdBlockMax+1)<<3 | 1
	bad("raw block of 128 KiB + 1 bytes", append(bytes.Clone(header17), byte(oversize), byte(oversize>>8), byte(oversize>>16), 'x'), "SG-R-CDC-05")
	bad("checksum flag set but the checksum is missing", append(corpus.ZstdHeader{WindowLog: 17, Checksum: true}.Bytes(), raw...), "SG-R-CDC-05", "SG-R-CDC-06")

	stored := corpus.ZstdStored(data, 17)
	for _, n := range []int{0, 1, 3, 4, 5, 6, 7, len(stored) / 2, len(stored) - 1} {
		bad(fmt.Sprintf("zstd frame truncated to %d of %d bytes", n, len(stored)), stored[:n], "SG-R-CDC-06")
	}
	for _, tc := range []struct {
		desc string
		tail []byte
	}{
		{"one zero byte", []byte{0}}, {"512 zero bytes", make([]byte, 512)}, {"text", []byte("garbage")},
		{"half a magic number", []byte{0x28, 0xB5}}, {"a magic number without a header", []byte{0x28, 0xB5, 0x2F, 0xFD}},
	} {
		bad("zstd frame followed by "+tc.desc, append(bytes.Clone(stored), tc.tail...), "SG-R-CDC-05")
	}
	bad("a skippable frame that claims 4 GiB with nothing behind it", []byte{0x50, 0x2A, 0x4D, 0x18, 0xff, 0xff, 0xff, 0xff, 1, 2, 3}, "SG-R-CDC-05", "SG-R-CDC-06")
	bad("empty input for zstd", nil, "SG-R-CDC-06")

	// Skippable frames count as input only.
	skippable := func(desc string, stream []byte, want expect) {
		b.addFile("MULTI", vector{
			Description: desc,
			Rules:       ids("SG-R-CDC-05"),
			Tags:        tags("multiframe"),
			Encodings:   []string{"zstd"},
			Limits:      generous,
			Expect:      want,
		}, stream)
	}
	skippable("skippable frames before, between and after real frames", bytes.Join([][]byte{
		corpus.ZstdSkippable(5), stored, corpus.ZstdSkippable(0), stored, corpus.ZstdSkippable(300),
	}, nil), okData(append(bytes.Clone(data), data...)))
	skippable("only skippable frames is a valid, empty stream", bytes.Join([][]byte{corpus.ZstdSkippable(3), corpus.ZstdSkippable(9)}, nil), okData(nil))
	skippable("10000 skippable frames of 8 bytes then data", append(bytes.Repeat(corpus.ZstdSkippable(0), 10000), stored...), okData(data))

	// Several frames share one output budget.
	frame1k := corpus.ZstdZeros(1000, 17)
	three := bytes.Join([][]byte{frame1k, frame1k, frame1k}, nil)
	for _, limit := range []int64{2999, 3000, 3001} {
		v := vector{
			Description: fmt.Sprintf("three zstd frames of 1000 bytes share one output budget: MaxOutput %d", limit),
			Rules:       ids("SG-R-CDC-05", "SG-R-LAY-01", "SG-R-LAY-03", "SG-I-01"),
			Tags:        tags("multiframe", "boundary"),
			Encodings:   []string{"zstd"},
			Limits:      noRatio(limit),
		}
		if limit < 3000 {
			v.Expect = readError("output_limit", 1, limit)
		} else {
			v.Expect = okZeros(3000)
		}
		b.addFile("MULTI", v, three)
	}

	// Chains and header spellings.
	b.addFile("CHAIN", vector{
		Description: "zstd applied first, then gzip",
		Rules:       ids("SG-R-HDR-12", "SG-R-CDC-01"),
		Tags:        tags("chain"),
		Encodings:   []string{"zstd, gzip"},
		Limits:      generous,
		Expect:      okData(data),
	}, corpus.GzipStored(stored))
	b.addFile("CHAIN", vector{
		Description: "gzip applied first, then zstd",
		Rules:       ids("SG-R-HDR-12", "SG-R-CDC-01"),
		Tags:        tags("chain"),
		Encodings:   []string{"gzip, zstd"},
		Limits:      generous,
		Expect:      okData(data),
	}, corpus.ZstdStored(corpus.GzipStored(data), 17))
	for _, enc := range []string{"zstd", "ZSTD", " zstd ", ",zstd"} {
		b.addFile("HDR", vector{
			Description: fmt.Sprintf("accepted header with the optional codec: %q", enc),
			Rules:       ids("SG-R-HDR-05", "SG-R-HDR-08", "SG-R-HDR-14"),
			Tags:        tags("header"),
			Encodings:   []string{enc},
			Limits:      generous,
			Expect:      okData(data),
		}, stored)
	}
}
