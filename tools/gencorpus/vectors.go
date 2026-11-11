package main

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/FelixMiddelhoff/spillgate/internal/corpus"
)

// Helpers for writing vectors compactly. Every expectation below comes from
// the rules of spec/SPEC.md and is stated by hand.

func i64(n int64) *int64 { return &n }

func okData(data []byte) expect {
	return expect{Outcome: "ok", Length: i64(int64(len(data))), SHA256: corpus.SHA256Hex(data)}
}

func okZeros(n int64) expect {
	return expect{Outcome: "ok", Length: i64(n), SHA256: corpus.ZerosSHA256Hex(n)}
}

// readError expects an error during reading after exactly `delivered` bytes.
func readError(outcome string, layer int, delivered int64) expect {
	return expect{Outcome: outcome, Phase: "read", Layer: layer, DeliveredExactly: i64(delivered)}
}

// readErrorAtMost expects an error during reading after at most `bound` bytes.
func readErrorAtMost(outcome string, layer int, bound int64) expect {
	return expect{Outcome: outcome, Phase: "read", Layer: layer, DeliveredAtMost: i64(bound)}
}

// corruptStream expects `corrupt` during reading, with no particular amount delivered.
func corruptStream(layer int) expect {
	return expect{Outcome: "corrupt", Phase: "read", Layer: layer}
}

// refused expects the decoder to refuse at construction, before reading.
func refused(outcome string) expect {
	return expect{Outcome: outcome, Phase: "construct"}
}

// noRatio is the usual limit set of the corpus: a MaxOutput and no ratio check.
func noRatio(maxOutput int64) map[string]any {
	return map[string]any{"max_output": maxOutput, "max_ratio": "none"}
}

// with copies m and sets the given key/value pairs.
func with(m map[string]any, kv ...any) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		out[k] = v
	}
	for i := 0; i < len(kv); i += 2 {
		out[kv[i].(string)] = kv[i+1]
	}
	return out
}

func ids(list ...string) []string { return list }

// generous is a limit set that never interferes.
var generous = noRatio(1 << 30)

// codecs maps the generator codec names to the Content-Encoding they carry.
var codecs = []struct{ gen, encoding, label string }{
	{"gzip", "gzip", "gzip"},
	{"zlib", "deflate", "zlib"},
	{"raw", "deflate", "raw deflate"},
}

func defineVectors(b *builder) {
	defineBombs(b)
	defineBoundaries(b)
	defineChains(b)
	defineHeaders(b)
	defineLies(b)
	defineMalformed(b)
	defineMultiMember(b)
	defineInputLimit(b)
	defineInputLimitOnTheSource(b)
	defineInputLimitMore(b)
	defineLimitValues(b)
	defineRatio(b)
	defineRatioMore(b)
	defineBrotli(b)
	defineZstd(b)
	defineInputProbe(b) // last: its BND ids follow the existing ones
}

// ---- BOMB ------------------------------------------------------------------

func defineBombs(b *builder) {
	const gigabyteMatches = 4_161_000 // decodes to 1 + 258*4161000, about 1 GiB
	for _, c := range codecs {
		b.addGenerated("BOMB", "large", vector{
			Description: c.label + " bomb of about 1 GiB against a 1 MiB output limit stops at the limit with a typed error",
			Rules:       ids("SG-R-LAY-02", "SG-R-LAY-03", "SG-R-LAY-04", "SG-R-CDC-01", "SG-I-01", "SG-I-02"),
			Tags:        []string{"bomb"},
			Encodings:   []string{c.encoding},
			Limits:      noRatio(1 << 20),
			Expect:      readError("output_limit", 1, 1<<20),
		}, corpus.Zeros(c.gen, gigabyteMatches))

		b.addGenerated("BOMB", "large", vector{
			Description: c.label + " bomb at the best DEFLATE ratio (about 1032:1) against MaxRatio 100 is a ratio error long before the output limit (factor 10 margin)",
			Rules:       ids("SG-R-RAT-01", "SG-R-RAT-05", "SG-I-02"),
			Tags:        []string{"bomb", "ratio"},
			Encodings:   []string{c.encoding},
			Limits:      map[string]any{"max_output": 1 << 30, "max_ratio": 100},
			Expect:      readErrorAtMost("ratio_limit", 1, 8<<20),
		}, corpus.Zeros(c.gen, gigabyteMatches))

		b.addGenerated("BOMB", "small", vector{
			Description: c.label + " bomb of 258 KB against a 10000-byte limit",
			Rules:       ids("SG-R-LAY-02", "SG-R-LAY-03", "SG-I-01"),
			Tags:        []string{"bomb"},
			Encodings:   []string{c.encoding},
			Limits:      noRatio(10000),
			Expect:      readError("output_limit", 1, 10000),
		}, corpus.Zeros(c.gen, 1000))
	}

	const okMatches = 260_000
	b.addGenerated("BOMB", "large", vector{
		Description: "a 64 MiB zeros stream is fine when the limit allows it and the ratio check is off",
		Rules:       ids("SG-R-RAT-04", "SG-R-LAY-03", "SG-R-RDR-01"),
		Tags:        []string{"bomb", "ok"},
		Encodings:   []string{"gzip"},
		Limits:      generous,
		Expect:      okZeros(corpus.ZerosDecodedSize(okMatches)),
	}, corpus.Zeros("gzip", okMatches))

	b.addGenerated("BOMB", "large", vector{
		Description: "nested bomb: a harmless stored gzip layer around a 256 MiB gzip bomb; the inner layer hits the limit",
		Rules:       ids("SG-R-LAY-01", "SG-R-LAY-02", "SG-I-01"),
		Tags:        []string{"bomb", "chain"},
		Encodings:   []string{"gzip", "gzip"},
		Limits:      noRatio(1 << 20),
		Expect:      readError("output_limit", 2, 1<<20),
	}, corpus.Wrap("gzip", 1, corpus.Zeros("gzip", 1<<20)))

	b.addGenerated("BOMB", "large", vector{
		Description: "nested bomb across codecs: zlib around a gzip bomb, header lists gzip then deflate",
		Rules:       ids("SG-R-LAY-01", "SG-R-LAY-02", "SG-R-HDR-12", "SG-I-01"),
		Tags:        []string{"bomb", "chain"},
		Encodings:   []string{"gzip, deflate"},
		Limits:      noRatio(1 << 20),
		Expect:      readError("output_limit", 2, 1<<20),
	}, corpus.Wrap("zlib", 1, corpus.Zeros("gzip", 1<<20)))
}

// ---- BND -------------------------------------------------------------------

// defineBoundaries tests limit-1, limit and limit+1 for every codec, identity
// and a stored stream.
func defineBoundaries(b *builder) {
	for _, matches := range []int64{1, 100} {
		size := corpus.ZerosDecodedSize(matches)
		for _, c := range codecs {
			for _, limit := range []int64{size - 1, size, size + 1} {
				v := vector{
					Description: fmt.Sprintf("%s zeros stream of %d bytes with MaxOutput %d", c.label, size, limit),
					Rules:       ids("SG-R-LAY-02", "SG-R-LAY-03", "SG-R-LAY-04", "SG-I-01", "SG-I-02", "SG-I-09"),
					Tags:        []string{"boundary"},
					Encodings:   []string{c.encoding},
					Limits:      noRatio(limit),
				}
				if limit < size {
					v.Expect = readError("output_limit", 1, limit)
				} else {
					v.Expect = okZeros(size)
				}
				b.addGenerated("BND", "small", v, corpus.Zeros(c.gen, matches))
			}
		}
	}

	body := corpus.Data(1, 1000)
	for _, enc := range [][]string{nil, {"identity"}} {
		for _, limit := range []int64{999, 1000, 1001} {
			v := vector{
				Description: fmt.Sprintf("identity body of 1000 bytes (header %q) with MaxOutput %d", enc, limit),
				Rules:       ids("SG-R-CDC-10", "SG-R-LAY-03", "SG-I-01", "SG-I-02"),
				Tags:        []string{"boundary", "identity"},
				Encodings:   enc,
				Limits:      noRatio(limit),
			}
			if limit < 1000 {
				v.Expect = readError("output_limit", 1, limit)
			} else {
				v.Expect = okData(body)
			}
			b.addFile("BND", v, body)
		}
	}

	b.addFile("BND", vector{
		Description: "an empty identity body with the smallest possible limit",
		Rules:       ids("SG-R-LAY-03", "SG-R-CDC-10"),
		Tags:        []string{"boundary", "identity"},
		Limits:      noRatio(1),
		Expect:      okData(nil),
	}, nil)

	stored := corpus.GzipStored(body)
	for _, limit := range []int64{999, 1000, 1001} {
		v := vector{
			Description: fmt.Sprintf("stored gzip stream of 1000 bytes with MaxOutput %d", limit),
			Rules:       ids("SG-R-LAY-03", "SG-R-CDC-02", "SG-I-01"),
			Tags:        []string{"boundary"},
			Encodings:   []string{"gzip"},
			Limits:      noRatio(limit),
		}
		if limit < 1000 {
			v.Expect = readError("output_limit", 1, limit)
		} else {
			v.Expect = okData(body)
		}
		b.addFile("BND", v, stored)
	}
}

// ---- CHAIN -----------------------------------------------------------------

func defineChains(b *builder) {
	data := corpus.Data(11, 500)
	repeated := func(name string, n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = name
		}
		return out
	}
	nested := func(n int) corpus.Spec { return corpus.Wrap("gzip", n-1, corpus.Stored("gzip", 11, 500)) }

	for depth := 1; depth <= 5; depth++ {
		b.addGenerated("CHAIN", "small", vector{
			Description: fmt.Sprintf("%d nested gzip layers, header lists gzip %d times (default MaxLayers 5)", depth, depth),
			Rules:       ids("SG-R-HDR-11", "SG-R-HDR-12", "SG-R-LAY-01"),
			Tags:        []string{"chain"},
			Encodings:   repeated("gzip", depth),
			Limits:      generous,
			Expect:      okData(data),
		}, nested(depth))
	}
	b.addGenerated("CHAIN", "small", vector{
		Description: "6 gzip layers exceed the default MaxLayers of 5; refused before any read",
		Rules:       ids("SG-R-HDR-11", "SG-R-HDR-09", "SG-I-07"),
		Tags:        []string{"chain", "cve"},
		Refs:        []string{"CVE-2026-61541", "CVE-2025-66418"},
		Encodings:   repeated("gzip", 6),
		Limits:      generous,
		Expect:      refused("layer_limit"),
	}, nested(6))
	b.addGenerated("CHAIN", "small", vector{
		Description: "3 layers with MaxLayers 2",
		Rules:       ids("SG-R-HDR-11", "SG-I-07"),
		Tags:        []string{"chain"},
		Encodings:   repeated("gzip", 3),
		Limits:      with(generous, "max_layers", 2),
		Expect:      refused("layer_limit"),
	}, nested(3))
	b.addGenerated("CHAIN", "small", vector{
		Description: "16 layers with MaxLayers 16 (the hard maximum and the element cap) are accepted",
		Rules:       ids("SG-R-HDR-06", "SG-R-HDR-11", "SG-R-LIM-03"),
		Tags:        []string{"chain"},
		Encodings:   repeated("gzip", 16),
		Limits:      with(generous, "max_layers", 16),
		Expect:      okData(data),
	}, nested(16))
	b.addGenerated("CHAIN", "small", vector{
		Description: "17 elements exceed the hard element cap even with MaxLayers 16",
		Rules:       ids("SG-R-HDR-06", "SG-I-07"),
		Tags:        []string{"chain", "cve"},
		Refs:        []string{"CVE-2026-61541", "CVE-2025-66418"},
		Encodings:   repeated("gzip", 17),
		Limits:      with(generous, "max_layers", 16),
		Expect:      refused("layer_limit"),
	}, nested(17))

	mixed := corpus.GzipStored(corpus.ZlibStored(corpus.GzipStored(corpus.ZlibStored(corpus.GzipStored(data)))))
	b.addFile("CHAIN", vector{
		Description: "mixed chain gzip, deflate, gzip, deflate, gzip applied in this order",
		Rules:       ids("SG-R-HDR-12", "SG-R-HDR-14"),
		Tags:        []string{"chain"},
		Encodings:   []string{"gzip, deflate, gzip, deflate, gzip"},
		Limits:      generous,
		Expect:      okData(data),
	}, mixed)

	zlibOverGzip := corpus.ZlibStored(corpus.GzipStored(data))
	b.addFile("CHAIN", vector{
		Description: "wrong order: the stream is zlib around gzip but the header lists deflate first",
		Rules:       ids("SG-R-HDR-12", "SG-I-06"),
		Tags:        []string{"chain"},
		Encodings:   []string{"deflate, gzip"},
		Limits:      generous,
		Expect:      corruptStream(1),
	}, zlibOverGzip)

	random := corpus.Data(21, 1000)
	b.addFile("CHAIN", vector{
		Description: "an intermediate layer larger than MaxOutput is refused although the final data fits",
		Rules:       ids("SG-R-LAY-01", "SG-I-01"),
		Tags:        []string{"chain", "intermediate"},
		Encodings:   []string{"gzip", "gzip"},
		Limits:      noRatio(1005),
		Expect:      readErrorAtMost("output_limit", 1, 1005),
	}, corpus.GzipStored(corpus.GzipStored(random)))
}

// ---- HDR -------------------------------------------------------------------

func defineHeaders(b *builder) {
	data := corpus.Data(31, 100)
	gz, zl := corpus.GzipStored(data), corpus.ZlibStored(data)
	both := corpus.ZlibStored(corpus.GzipStored(data))

	accept := func(rule string, enc []string, stream []byte, desc string) {
		b.addFile("HDR", vector{
			Description: "accepted header: " + desc,
			Rules:       ids(rule, "SG-R-HDR-14"),
			Tags:        []string{"header"},
			Encodings:   enc,
			Limits:      generous,
			Expect:      okData(data),
		}, stream)
	}
	reject := func(rule, outcome string, enc []string, desc string, extra map[string]any) {
		limits := generous
		if extra != nil {
			limits = with(generous, flatten(extra)...)
		}
		b.addFile("HDR", vector{
			Description: "refused header: " + desc,
			Rules:       ids(rule, "SG-R-API-03", "SG-I-06"),
			Tags:        []string{"header"},
			Encodings:   enc,
			Limits:      limits,
			Expect:      refused(outcome),
		}, gz)
	}

	// Accepted presentations of the same chain (SG-R-HDR-14).
	for _, tc := range []struct {
		rule string
		enc  []string
		desc string
	}{
		{"SG-R-HDR-05", []string{"GZIP"}, "upper case"},
		{"SG-R-HDR-05", []string{"GzIp"}, "mixed case"},
		{"SG-R-HDR-07", []string{"x-gzip"}, "x-gzip alias"},
		{"SG-R-HDR-07", []string{"X-GZIP"}, "upper case x-gzip alias"},
		{"SG-R-HDR-03", []string{" gzip "}, "spaces around the name"},
		{"SG-R-HDR-03", []string{"\tgzip\t"}, "tabs around the name"},
		{"SG-R-HDR-03", []string{"gzip,"}, "trailing comma"},
		{"SG-R-HDR-03", []string{",gzip"}, "leading comma"},
		{"SG-R-HDR-03", []string{",,gzip,,"}, "doubled commas"},
		{"SG-R-HDR-03", []string{"", " gzip"}, "empty first field value"},
		{"SG-R-HDR-03", []string{"gzip", ""}, "empty last field value"},
		{"SG-R-HDR-10", []string{"identity, gzip"}, "identity before gzip"},
		{"SG-R-HDR-10", []string{"gzip, identity"}, "identity after gzip"},
		{"SG-R-HDR-10", []string{"identity", "gzip", "identity"}, "identity around gzip in three field values"},
		{"SG-R-HDR-10", []string{"IDENTITY,gzip"}, "upper case identity"},
		{"SG-R-HDR-10", []string{"gzip", "identity", "identity"}, "trailing identities"},
		{"SG-R-HDR-01", []string{"gzip", ""}, "several field values"},
	} {
		accept(tc.rule, tc.enc, gz, tc.desc)
	}
	// 15 identities plus gzip is exactly the 16-element cap.
	accept("SG-R-HDR-06", []string{strings.Repeat("identity,", 15) + "gzip"}, gz, "15 identities and gzip, exactly at the element cap")
	accept("SG-R-HDR-05", []string{"deflate"}, zl, "deflate")
	accept("SG-R-HDR-05", []string{"DEFLATE"}, zl, "upper case deflate")
	accept("SG-R-HDR-12", []string{"gzip, deflate"}, both, "gzip then deflate in one value")
	accept("SG-R-HDR-12", []string{"gzip", "deflate"}, both, "gzip then deflate in two values")
	accept("SG-R-HDR-12", []string{"gzip, ", "deflate"}, both, "two values with an empty element")
	accept("SG-R-HDR-07", []string{"x-gzip,DEFLATE"}, both, "alias and upper case in a chain")

	// Empty chains decode the body as it is (identity), still bounded.
	for _, enc := range [][]string{nil, {""}, {","}, {"identity"}, {" , "}} {
		b.addFile("HDR", vector{
			Description: fmt.Sprintf("header %q is the empty chain: the body passes through unchanged", enc),
			Rules:       ids("SG-R-HDR-01", "SG-R-HDR-03", "SG-R-CDC-10"),
			Tags:        []string{"header", "identity"},
			Encodings:   enc,
			Limits:      generous,
			Expect:      okData(data),
		}, data)
	}

	// Malformed headers (SG-R-HDR-02..04).
	for _, tc := range []struct{ value, desc string }{
		{"gzip;q=1", "parameter"},
		{"gzip ; q=1", "parameter with spaces"},
		{`"gzip"`, "double quotes"},
		{"'gzip'", "single quotes"},
		{"g zip", "space inside the name"},
		{strings.Repeat("a", 33), "name of 33 bytes"},
		{"gzip\u0000", "NUL after the name"},
		{"gz\u0000ip", "NUL inside the name"},
		{"gzip\r", "carriage return"},
		{"gzip\n", "line feed"},
		{"gzip\r\nX-Evil: 1", "CRLF header injection"},
		{"gzip\u000b", "vertical tab"},
		{"gzip ", "non-breaking space"},
		{"gzip\u007f", "DEL"},
		{"gzipé", "non-ASCII letter"},
		{"gзip", "Cyrillic homoglyph in the name"},
		{"Kelvin", "Kelvin sign"},
		{"gzip!", "exclamation mark"},
		{"gzip(1)", "parentheses"},
		{";", "only a semicolon"},
		{"_gzip", "underscore first"},
		{".gzip", "dot first"},
		{"-gzip", "dash first"},
		{"gzip/1", "slash"},
		{"gzip;q=1, deflate", "bad element then good one"},
		{"deflate, gzip;q=1", "good element then bad one"},
		{strings.Repeat(" ", 1025) + "gzip", "header longer than 1024 bytes"},
	} {
		reject("SG-R-HDR-04", "malformed_encoding", []string{tc.value}, tc.desc, nil)
	}
	first := strings.Repeat(" ", 596) + "gzip" // 600 bytes
	accept("SG-R-HDR-02", []string{first, strings.Repeat(" ", 423)}, gz, "two values, 1024 bytes with the joining comma")
	reject("SG-R-HDR-02", "malformed_encoding", []string{first, strings.Repeat(" ", 424)}, "two values, 1025 bytes with the joining comma", nil)

	// Unsupported encodings (SG-R-HDR-08, SG-R-HDR-09).
	for _, name := range []string{
		"compress", "x-compress", "dcb", "dcz", "aes128gcm", "snappy", "deflate64", "lz4", "bzip2", "xz",
		"gzip2", "gzipp", "a.b", "a_b", "123",
	} {
		reject("SG-R-HDR-08", "unsupported_encoding", []string{name}, name+" is not supported", nil)
	}
	for _, header := range []string{"gzip, snappy", "snappy, gzip", "gzip, snappy, deflate"} {
		reject("SG-R-HDR-09", "unsupported_encoding", []string{header}, "one unsupported element poisons the chain: "+header, nil)
	}

	// Element cap (SG-R-HDR-06): 17 elements.
	reject("SG-R-HDR-06", "layer_limit", []string{strings.Repeat("gzip,", 16) + "gzip"}, "17 gzip elements", nil)
	reject("SG-R-HDR-06", "layer_limit", []string{strings.Repeat("identity,", 16) + "gzip"}, "16 identities and gzip: identity spam cannot dodge the cap", nil)
	reject("SG-R-HDR-06", "layer_limit", []string{strings.Repeat("identity,", 17)}, "17 identity elements", nil)

	// Evaluation order (section 4): length, grammar, element count, support, layer count.
	reject("SG-R-HDR-02", "malformed_encoding", []string{strings.Repeat("gzip,", 220)}, "evaluation order: length beats element count (1100 bytes, 220 elements)", nil)
	reject("SG-R-HDR-04", "malformed_encoding", []string{strings.Repeat("gzip,", 20) + "bad;token"}, "evaluation order: grammar beats element count", nil)
	reject("SG-R-HDR-06", "layer_limit", []string{strings.Repeat("nope,", 16) + "nope"}, "evaluation order: element count beats unsupported", nil)
	reject("SG-R-HDR-08", "unsupported_encoding", []string{"gzip,gzip,gzip,nope"}, "evaluation order: unsupported beats layer count (MaxLayers 2)", map[string]any{"max_layers": 2})
	reject("SG-R-HDR-11", "layer_limit", []string{"gzip,gzip,gzip"}, "evaluation order: layer count comes last (MaxLayers 2)", map[string]any{"max_layers": 2})
}

// flatten turns a map into key, value, key, value for with().
func flatten(m map[string]any) []any {
	var out []any
	for k, v := range m {
		out = append(out, k, v)
	}
	return out
}

// ---- LIE -------------------------------------------------------------------

// defineLies tests streams whose gzip ISIZE field lies about the size.
func defineLies(b *builder) {
	data := corpus.Data(41, 5000)
	declared := []uint32{0, 1, 4999, 5000, 5001, 1 << 31, 1<<32 - 1}

	for _, size := range declared {
		stream := corpus.GzipStored(data)
		binary.LittleEndian.PutUint32(stream[len(stream)-4:], size)

		b.addFile("LIE", vector{
			Description: fmt.Sprintf("ISIZE says %d, the real size is 5000, MaxOutput 2500: the declared size never changes the allowance", size),
			Rules:       ids("SG-R-CDC-07", "SG-R-LAY-08", "SG-R-LAY-07", "SG-I-04"),
			Tags:        []string{"lying-size", "cve"},
			Refs:        []string{"GHSA-rcw4-f5rp-g42v"},
			Encodings:   []string{"gzip"},
			Limits:      noRatio(2500),
			Expect:      readError("output_limit", 1, 2500),
		}, stream)

		v := vector{
			Description: fmt.Sprintf("ISIZE says %d, the real size is 5000, generous limit", size),
			Rules:       ids("SG-R-CDC-02", "SG-R-CDC-07", "SG-I-04"),
			Tags:        []string{"lying-size"},
			Encodings:   []string{"gzip"},
			Limits:      generous,
		}
		if size == 5000 {
			v.Expect = okData(data)
		} else {
			v.Expect = corruptStream(1)
		}
		b.addFile("LIE", v, stream)
	}
}

// ---- MAL -------------------------------------------------------------------

func defineMalformed(b *builder) {
	data := corpus.Data(51, 100)
	gz := corpus.GzipStored(data)
	zl := corpus.ZlibStored(data)
	raw := corpus.StoredDeflate(data)

	corrupt := func(enc string, desc string, stream []byte, rules ...string) {
		b.addFile("MAL", vector{
			Description: desc,
			Rules:       append(ids("SG-I-05", "SG-I-06"), rules...),
			Tags:        []string{"malformed"},
			Encodings:   []string{enc},
			Limits:      generous,
			Expect:      corruptStream(1),
		}, stream)
	}
	valid := func(enc string, desc string, stream []byte, want []byte, rules ...string) {
		b.addFile("MAL", vector{
			Description: desc,
			Rules:       rules,
			Tags:        []string{"malformed", "ok"},
			Encodings:   []string{enc},
			Limits:      generous,
			Expect:      okData(want),
		}, stream)
	}
	mutate := func(src []byte, index int, value byte) []byte {
		out := bytes.Clone(src)
		out[index] = value
		return out
	}
	appendTo := func(src []byte, tail ...byte) []byte { return append(bytes.Clone(src), tail...) }

	// gzip: truncation at every interesting offset.
	for _, n := range []int{0, 1, 2, 3, 9, 10, 11, len(gz) / 2, len(gz) - 9, len(gz) - 8, len(gz) - 1} {
		corrupt("gzip", fmt.Sprintf("gzip stream truncated to %d of %d bytes", n, len(gz)), gz[:n], "SG-R-CDC-06")
	}
	// gzip: bad header.
	for _, tc := range []struct {
		desc  string
		index int
		value byte
	}{
		{"first magic byte wrong", 0, 0x1e}, {"second magic byte wrong", 1, 0x8c},
		{"method 0", 2, 0}, {"method 7", 2, 7}, {"method 9", 2, 9},
		{"reserved flag bit 5", 3, 0x20}, {"reserved flag bit 6", 3, 0x40}, {"reserved flag bit 7", 3, 0x80},
		{"all reserved flag bits", 3, 0xe0}, {"header CRC flag set but no CRC present", 3, 0x02},
	} {
		corrupt("gzip", "gzip header: "+tc.desc, mutate(gz, tc.index, tc.value), "SG-R-CDC-02")
	}
	// gzip: trailer.
	end := len(gz)
	corrupt("gzip", "gzip CRC-32 first byte flipped", mutate(gz, end-8, gz[end-8]^1), "SG-R-CDC-02")
	corrupt("gzip", "gzip CRC-32 last byte flipped", mutate(gz, end-5, gz[end-5]^0x80), "SG-R-CDC-02")
	// gzip: bytes after the member.
	for _, tc := range []struct {
		desc string
		tail []byte
	}{
		{"one zero byte", []byte{0}}, {"512 zero bytes of padding", make([]byte, 512)},
		{"half a magic number", []byte{0x1f}}, {"a magic number without the rest", []byte{0x1f, 0x8b}},
		{"text", []byte("trailing garbage")}, {"a newline", []byte{'\n'}},
		{"a truncated second member header", gz[:9]}, {"a truncated second member body", gz[:len(gz)-3]},
	} {
		corrupt("gzip", "gzip member followed by "+tc.desc, appendTo(gz, tc.tail...), "SG-R-CDC-02")
	}
	// gzip: header fields.
	name511 := bytes.Repeat([]byte("n"), 511)
	name512 := bytes.Repeat([]byte("n"), 512)
	valid("gzip", "gzip FNAME of 511 bytes plus terminator (512, the maximum)", corpus.GzipStoredWith(corpus.GzipHeader{Name: name511}, data), data, "SG-R-CDC-02")
	valid("gzip", "gzip FCOMMENT of 511 bytes plus terminator", corpus.GzipStoredWith(corpus.GzipHeader{Comment: name511}, data), data, "SG-R-CDC-02")
	valid("gzip", "gzip FEXTRA of 65535 bytes", corpus.GzipStoredWith(corpus.GzipHeader{Extra: bytes.Repeat([]byte("e"), 65535)}, data), data, "SG-R-CDC-02", "SG-R-MEM-01")
	valid("gzip", "gzip header with a correct header CRC", corpus.GzipStoredWith(corpus.GzipHeader{HeaderCRC: true}, data), data, "SG-R-CDC-02")
	valid("gzip", "gzip header with every optional field", corpus.GzipStoredWith(corpus.GzipHeader{Name: []byte("f.txt"), Comment: []byte("c"), Extra: []byte("xy"), HeaderCRC: true}, data), data, "SG-R-CDC-02")
	corrupt("gzip", "gzip FNAME of 512 bytes (513 with the terminator)", corpus.GzipStoredWith(corpus.GzipHeader{Name: name512}, data), "SG-R-CDC-02")
	corrupt("gzip", "gzip FCOMMENT of 512 bytes", corpus.GzipStoredWith(corpus.GzipHeader{Comment: name512}, data), "SG-R-CDC-02")
	badCRC := corpus.GzipStoredWith(corpus.GzipHeader{HeaderCRC: true}, data)
	corrupt("gzip", "gzip header CRC flipped", mutate(badCRC, 10, badCRC[10]^1), "SG-R-CDC-02")
	// gzip: foreign input.
	corrupt("gzip", "empty input for gzip", nil, "SG-R-CDC-06")
	corrupt("gzip", "text for gzip", []byte("hello"), "SG-R-CDC-02")
	corrupt("gzip", "zlib bytes for gzip", zl, "SG-R-CDC-02")

	// zlib.
	for _, n := range []int{0, 1, 2, 3, len(zl) / 2, len(zl) - 5, len(zl) - 4, len(zl) - 1} {
		corrupt("deflate", fmt.Sprintf("zlib stream truncated to %d of %d bytes", n, len(zl)), zl[:n], "SG-R-CDC-03", "SG-R-CDC-06")
	}
	for i := 1; i <= 4; i++ {
		corrupt("deflate", fmt.Sprintf("zlib Adler-32 byte %d from the end flipped", i), mutate(zl, len(zl)-i, zl[len(zl)-i]^0x10), "SG-R-CDC-03")
	}
	corrupt("deflate", "zlib with a preset dictionary (FDICT set)", append([]byte{0x78, 0x20, 1, 2, 3, 4}, raw...), "SG-R-CDC-03")
	corrupt("deflate", "zlib followed by a zero byte", appendTo(zl, 0), "SG-R-CDC-03")
	corrupt("deflate", "zlib followed by text", appendTo(zl, []byte("garbage")...), "SG-R-CDC-03")
	corrupt("deflate", "gzip bytes for deflate", gz, "SG-R-CDC-03")
	corrupt("deflate", "empty input for deflate", nil, "SG-R-CDC-06")

	// raw deflate (auto-detected) and its strict variant.
	valid("deflate", "raw deflate without the zlib wrapper is accepted by default", raw, data, "SG-R-CDC-03")
	valid("deflate", "raw max-ratio deflate block is accepted by default", corpus.ZerosDeflate(10), make([]byte, corpus.ZerosDecodedSize(10)), "SG-R-CDC-03")
	b.addFile("MAL", vector{
		Description: "strict_zlib rejects raw deflate",
		Rules:       ids("SG-R-CDC-03", "SG-I-06"),
		Tags:        []string{"malformed", "option"},
		Encodings:   []string{"deflate"},
		Limits:      generous,
		Options:     map[string]any{"strict_zlib": true},
		Expect:      corruptStream(1),
	}, raw)
	b.addFile("MAL", vector{
		Description: "strict_zlib still accepts zlib",
		Rules:       ids("SG-R-CDC-03"),
		Tags:        []string{"malformed", "option", "ok"},
		Encodings:   []string{"deflate"},
		Limits:      generous,
		Options:     map[string]any{"strict_zlib": true},
		Expect:      okData(data),
	}, zl)
	for _, n := range []int{0, 1, 2, 50, len(raw) - 1} {
		corrupt("deflate", fmt.Sprintf("raw deflate truncated to %d of %d bytes", n, len(raw)), raw[:n], "SG-R-CDC-03", "SG-R-CDC-06")
	}
	corrupt("deflate", "raw deflate followed by a zero byte", appendTo(raw, 0), "SG-R-CDC-03")

	// A raw stream that starts like a zlib header fails closed in both modes.
	collision := append([]byte{0x08, 0x1d, 0x00, 0xe2, 0xff}, bytes.Repeat([]byte("q"), 29)...)
	collision = append(collision, 0x01, 0x00, 0x00, 0xff, 0xff)
	corrupt("deflate", "raw deflate that looks like a zlib header is treated as zlib and fails, never misread as data", collision, "SG-R-CDC-03")
	b.addFile("MAL", vector{
		Description: "the same stream with strict_zlib",
		Rules:       ids("SG-R-CDC-03", "SG-I-06"),
		Tags:        []string{"malformed", "option"},
		Encodings:   []string{"deflate"},
		Limits:      generous,
		Options:     map[string]any{"strict_zlib": true},
		Expect:      corruptStream(1),
	}, collision)
}

// ---- MULTI -----------------------------------------------------------------

func defineMultiMember(b *builder) {
	a, c := corpus.Data(61, 600), corpus.Data(62, 600)
	middle := corpus.Data(63, 600)
	three := bytes.Join([][]byte{corpus.GzipStored(a), corpus.GzipStored(middle), corpus.GzipStored(c)}, nil)
	all := bytes.Join([][]byte{a, middle, c}, nil)

	b.addFile("MULTI", vector{
		Description: "three concatenated gzip members decode as one stream",
		Rules:       ids("SG-R-CDC-02", "SG-R-RDR-01"),
		Tags:        []string{"multimember"},
		Encodings:   []string{"gzip"},
		Limits:      generous,
		Expect:      okData(all),
	}, three)
	b.addFile("MULTI", vector{
		Description: "an empty member in the middle changes nothing",
		Rules:       ids("SG-R-CDC-02"),
		Tags:        []string{"multimember"},
		Encodings:   []string{"gzip"},
		Limits:      generous,
		Expect:      okData(append(bytes.Clone(a), c...)),
	}, bytes.Join([][]byte{corpus.GzipStored(a), corpus.GzipStored(nil), corpus.GzipStored(c)}, nil))
	for _, limit := range []int64{1799, 1800, 1801} {
		v := vector{
			Description: fmt.Sprintf("three members of 600 bytes share one output budget: MaxOutput %d", limit),
			Rules:       ids("SG-R-CDC-02", "SG-R-LAY-01", "SG-R-LAY-03", "SG-I-01"),
			Tags:        []string{"multimember", "boundary"},
			Encodings:   []string{"gzip"},
			Limits:      noRatio(limit),
		}
		if limit < 1800 {
			v.Expect = readError("output_limit", 1, limit)
		} else {
			v.Expect = okData(all)
		}
		b.addFile("MULTI", v, three)
	}
	b.addFile("MULTI", vector{
		Description: "many empty members cannot be used to dodge the limits: 2000 empty members then data",
		Rules:       ids("SG-R-CDC-02", "SG-R-RDR-03"),
		Tags:        []string{"multimember"},
		Encodings:   []string{"gzip"},
		Limits:      generous,
		Expect:      okData(a),
	}, append(bytes.Repeat(corpus.GzipStored(nil), 2000), corpus.GzipStored(a)...))
}

// ---- INP -------------------------------------------------------------------

func defineInputLimit(b *builder) {
	data := corpus.Data(71, 500)
	gz := corpus.GzipStored(data)
	for _, cap := range []int64{int64(len(gz)), int64(len(gz)) - 1} {
		v := vector{
			Description: fmt.Sprintf("stored gzip stream of %d bytes with MaxInput %d", len(gz), cap),
			Rules:       ids("SG-R-INP-01", "SG-R-INP-02"),
			Tags:        []string{"input-limit"},
			Encodings:   []string{"gzip"},
			Limits:      with(generous, "max_input", cap),
		}
		if cap >= int64(len(gz)) {
			v.Expect = okData(data)
		} else {
			v.Expect = readErrorAtMost("input_limit", 1, int64(len(data)))
		}
		b.addFile("INP", v, gz)
	}

	body := corpus.Data(72, 100)
	for _, cap := range []int64{100, 99} {
		v := vector{
			Description: fmt.Sprintf("identity body of 100 bytes with MaxInput %d", cap),
			Rules:       ids("SG-R-INP-01", "SG-R-CDC-10"),
			Tags:        []string{"input-limit", "identity"},
			Limits:      with(generous, "max_input", cap),
		}
		if cap >= 100 {
			v.Expect = okData(body)
		} else {
			v.Expect = readError("input_limit", 1, 99)
		}
		b.addFile("INP", v, body)
	}

	twice := corpus.GzipStored(corpus.GzipStored(data))
	for _, cap := range []int64{int64(len(twice)), int64(len(twice)) - 1} {
		v := vector{
			Description: fmt.Sprintf("two gzip layers, source of %d bytes, MaxInput %d: the cap counts the source, not the inner layer's output", len(twice), cap),
			Rules:       ids("SG-R-INP-01"),
			Tags:        []string{"input-limit", "chain"},
			Encodings:   []string{"gzip", "gzip"},
			Limits:      with(generous, "max_input", cap),
		}
		if cap >= int64(len(twice)) {
			v.Expect = okData(data)
		} else {
			v.Expect = readErrorAtMost("input_limit", 1, int64(len(data)))
		}
		b.addFile("INP", v, twice)
	}
}

// defineInputLimitOnTheSource tests that MaxInput counts what the caller's
// source delivers even when the first layer expands its input a lot. The
// source is a gzip compression of a stored gzip stream of 100000 zeros. The
// compressed bytes are frozen in testdata/input-limit-source.gz: the standard
// library compressor changes its output between Go versions (it did in 1.27), a
// generator that called it would change the corpus. TestInputLimitSourceIsFrozen
// checks the file still decodes to the stream described here.
func defineInputLimitOnTheSource(b *builder) {
	zeros := make([]byte, 100000)
	inner := corpus.GzipStored(zeros) // about 100 KB, mostly zeros
	source := inputLimitSource

	for _, cap := range []int64{int64(len(source)), int64(len(source)) - 1} {
		v := vector{
			Description: fmt.Sprintf("a %d-byte source expands to a %d-byte first layer; MaxInput %d counts the source, not the layer", len(source), len(inner), cap),
			Rules:       ids("SG-R-INP-01", "SG-R-INP-02"),
			Tags:        []string{"input-limit", "chain"},
			Encodings:   []string{"gzip", "gzip"},
			Limits:      with(generous, "max_input", cap),
		}
		if cap >= int64(len(source)) {
			v.Expect = okZeros(int64(len(zeros)))
		} else {
			v.Expect = readErrorAtMost("input_limit", 1, int64(len(zeros)))
		}
		b.addFile("INP", v, source)
	}
}

// ---- LIM -------------------------------------------------------------------

// defineLimitValues tests the validation of the limit parameters themselves.
// Explicit zeros for MaxLayers, MaxRatio and RatioGrace are not used because a
// binding may not be able to tell zero from "unset" (SG-R-LIM-03).
func defineLimitValues(b *builder) {
	data := corpus.Data(81, 50)
	gz := corpus.GzipStored(data)

	invalid := func(desc, rule string, limits map[string]any) {
		b.addFile("LIM", vector{
			Description: desc,
			Rules:       ids(rule, "SG-R-LIM-08", "SG-R-API-03"),
			Tags:        []string{"limits"},
			Encodings:   []string{"gzip"},
			Limits:      limits,
			Expect:      refused("invalid_limits"),
		}, gz)
	}
	invalid("MaxOutput is required: unset is invalid", "SG-R-LIM-01", map[string]any{})
	invalid("MaxOutput of zero is invalid, not unlimited", "SG-R-LIM-01", map[string]any{"max_output": 0})
	invalid("MaxLayers 17 is above the hard maximum", "SG-R-LIM-03", with(generous, "max_layers", 17))
	invalid("negative MaxLayers", "SG-R-LIM-03", with(generous, "max_layers", -1))
	invalid("negative MaxRatio", "SG-R-LIM-04", map[string]any{"max_output": 1000, "max_ratio": -1})
	invalid("MaxRatio above 2^31-1", "SG-R-LIM-04", map[string]any{"max_output": 1000, "max_ratio": int64(2147483648)})
	invalid("MaxInput of zero is invalid, not unlimited", "SG-R-LIM-06", with(generous, "max_input", 0))

	valid := func(desc string, rules []string, limits map[string]any, stream []byte, want []byte) {
		b.addFile("LIM", vector{
			Description: desc,
			Rules:       rules,
			Tags:        []string{"limits", "ok"},
			Encodings:   []string{"gzip"},
			Limits:      limits,
			Expect:      okData(want),
		}, stream)
	}
	valid("MaxOutput of 2^63-1 works without overflow (given as a string)", ids("SG-R-LIM-02"), map[string]any{"max_output": "9223372036854775807", "max_ratio": "none"}, gz, data)
	valid("MaxLayers 16 is valid", ids("SG-R-LIM-03"), with(generous, "max_layers", 16), gz, data)
	valid("MaxRatio 2^31-1 is valid", ids("SG-R-LIM-04"), map[string]any{"max_output": 1 << 20, "max_ratio": 2147483647}, gz, data)
	valid("MaxOutput of 1 byte is valid and enough for a 1-byte body", ids("SG-R-LIM-01", "SG-R-LAY-03"), noRatio(1),
		corpus.GzipStored([]byte{7}), []byte{7})
}

// ---- RAT -------------------------------------------------------------------

func defineRatio(b *builder) {
	body := corpus.Data(91, 10000)
	b.addFile("RAT", vector{
		Description: "stored data (ratio about 1) with MaxRatio 100 and the ratio checked from the first byte",
		Rules:       ids("SG-R-RAT-01", "SG-R-RAT-05"),
		Tags:        []string{"ratio", "ok"},
		Encodings:   []string{"gzip"},
		Limits:      map[string]any{"max_output": 1 << 20, "max_ratio": 100, "ratio_grace": 1},
		Expect:      okData(body),
	}, corpus.GzipStored(body))

	b.addGenerated("RAT", "small", vector{
		Description: "a 258 KB zeros stream stays under a RatioGrace of 1 MiB and is not ratio-checked",
		Rules:       ids("SG-R-RAT-01", "SG-R-RAT-05"),
		Tags:        []string{"ratio", "grace", "ok"},
		Encodings:   []string{"gzip"},
		Limits:      map[string]any{"max_output": 1 << 24, "max_ratio": 100, "ratio_grace": 1 << 20},
		Expect:      okZeros(corpus.ZerosDecodedSize(1000)),
	}, corpus.Zeros("gzip", 1000))

	b.addGenerated("RAT", "small", vector{
		Description: "the same stream with a RatioGrace of 1000 bytes is ratio-limited",
		Rules:       ids("SG-R-RAT-01", "SG-R-RAT-05"),
		Tags:        []string{"ratio", "grace"},
		Encodings:   []string{"gzip"},
		Limits:      map[string]any{"max_output": 1 << 24, "max_ratio": 100, "ratio_grace": 1000},
		Expect:      readErrorAtMost("ratio_limit", 1, 1<<20),
	}, corpus.Zeros("gzip", 1000))

	b.addGenerated("RAT", "small", vector{
		Description: "the ratio opt-out switches only the ratio check off; the output limit still applies",
		Rules:       ids("SG-R-RAT-04", "SG-R-LAY-03"),
		Tags:        []string{"ratio", "opt-out"},
		Encodings:   []string{"gzip"},
		Limits:      noRatio(100000),
		Expect:      readError("output_limit", 1, 100000),
	}, corpus.Zeros("gzip", 1000))
}

// ---- more INP and RAT ------------------------------------------------------

// defineInputLimitMore repeats the exact MaxInput boundary for the other
// framings and for streams of several members, and adds a bomb that the input
// cap stops although the output limit would allow it.
func defineInputLimitMore(b *builder) {
	data := corpus.Data(73, 400)
	streams := []struct {
		label    string
		encoding string
		stream   []byte
	}{
		{"zlib stored", "deflate", corpus.ZlibStored(data)},
		{"raw deflate stored", "deflate", corpus.StoredDeflate(data)},
	}
	for _, s := range streams {
		for _, cap := range []int64{int64(len(s.stream)), int64(len(s.stream)) - 1} {
			v := vector{
				Description: fmt.Sprintf("%s stream of %d bytes with MaxInput %d", s.label, len(s.stream), cap),
				Rules:       ids("SG-R-INP-01", "SG-R-INP-02"),
				Tags:        []string{"input-limit"},
				Encodings:   []string{s.encoding},
				Limits:      with(generous, "max_input", cap),
			}
			if cap >= int64(len(s.stream)) {
				v.Expect = okData(data)
			} else {
				v.Expect = readErrorAtMost("input_limit", 1, int64(len(data)))
			}
			b.addFile("INP", v, s.stream)
		}
	}

	// Two gzip members: the cap covers both together.
	both := append(corpus.GzipStored(data), corpus.GzipStored(data)...)
	for _, cap := range []int64{int64(len(both)), int64(len(both)) - 1} {
		v := vector{
			Description: fmt.Sprintf("two gzip members, %d bytes together, MaxInput %d: one cap for the whole source", len(both), cap),
			Rules:       ids("SG-R-INP-01", "SG-R-CDC-02"),
			Tags:        []string{"input-limit", "multi-member"},
			Encodings:   []string{"gzip"},
			Limits:      with(generous, "max_input", cap),
		}
		if cap >= int64(len(both)) {
			v.Expect = okData(append(append([]byte{}, data...), data...))
		} else {
			v.Expect = readErrorAtMost("input_limit", 1, int64(2*len(data)))
		}
		b.addFile("INP", v, both)
	}

	one := corpus.GzipStored(data)
	b.addFile("INP", vector{
		Description: "MaxInput 1 stops a gzip stream after the first byte",
		Rules:       ids("SG-R-INP-01", "SG-R-INP-02"),
		Tags:        []string{"input-limit"},
		Encodings:   []string{"gzip"},
		Limits:      with(generous, "max_input", 1),
		Expect:      readError("input_limit", 1, 0),
	}, one)

	b.addGenerated("INP", "small", vector{
		Description: "a 258 KB zeros stream with MaxInput 100 and a generous output limit: the input cap, not the output limit, ends it",
		Rules:       ids("SG-R-INP-01", "SG-R-INP-02"),
		Tags:        []string{"input-limit", "bomb"},
		Encodings:   []string{"gzip"},
		Limits:      with(noRatio(1<<30), "max_input", 100),
		Expect:      readErrorAtMost("input_limit", 1, 1<<20),
	}, corpus.Zeros("gzip", 1000))
}

// defineRatioMore covers the ratio limit for every DEFLATE framing, a nested
// layer, the boundary of MaxRatio itself and the tight settings.
func defineRatioMore(b *builder) {
	for _, c := range []struct{ label, encoding, gen string }{
		{"zlib", "deflate", "zlib"},
		{"raw deflate", "deflate", "raw"},
	} {
		b.addGenerated("RAT", "small", vector{
			Description: c.label + " zeros at about 1000:1 against MaxRatio 100 and a RatioGrace of 1000 bytes is a ratio error",
			Rules:       ids("SG-R-RAT-01", "SG-R-RAT-05", "SG-I-02"),
			Tags:        []string{"ratio"},
			Encodings:   []string{c.encoding},
			Limits:      map[string]any{"max_output": 1 << 24, "max_ratio": 100, "ratio_grace": 1000},
			Expect:      readErrorAtMost("ratio_limit", 1, 1<<20),
		}, corpus.Zeros(c.gen, 1000))
	}

	b.addGenerated("RAT", "small", vector{
		Description: "the layer ratio is judged per layer: a stored gzip layer around a zeros stream, the inner layer exceeds MaxRatio 100",
		Rules:       ids("SG-R-RAT-01", "SG-R-RAT-02", "SG-R-LAY-01"),
		Tags:        []string{"ratio", "chain"},
		Encodings:   []string{"gzip", "gzip"},
		Limits:      map[string]any{"max_output": 1 << 24, "max_ratio": 100, "ratio_grace": 1000},
		Expect:      readErrorAtMost("ratio_limit", 2, 1<<20),
	}, corpus.Wrap("gzip", 1, corpus.Zeros("gzip", 1000)))

	b.addGenerated("RAT", "small", vector{
		Description: "the same zeros stream with MaxRatio 2000 (above its ratio of about 1030) decodes completely",
		Rules:       ids("SG-R-RAT-01", "SG-R-RAT-05"),
		Tags:        []string{"ratio", "ok"},
		Encodings:   []string{"gzip"},
		Limits:      map[string]any{"max_output": 1 << 24, "max_ratio": 2000, "ratio_grace": 1000},
		Expect:      okZeros(corpus.ZerosDecodedSize(1000)),
	}, corpus.Zeros("gzip", 1000))

	data := corpus.Data(92, 5000)
	b.addFile("RAT", vector{
		Description: "stored deflate data (ratio about 1) with MaxRatio 1 and the ratio checked from the first byte is fine",
		Rules:       ids("SG-R-RAT-01", "SG-R-RAT-05"),
		Tags:        []string{"ratio", "ok"},
		Encodings:   []string{"deflate"},
		Limits:      map[string]any{"max_output": 1 << 20, "max_ratio": 1, "ratio_grace": 1},
		Expect:      okData(data),
	}, corpus.ZlibStored(data))
}

// inputLimitSource is the frozen gzip stream used by defineInputLimitOnTheSource.
//
//go:embed testdata/input-limit-source.gz
var inputLimitSource []byte

// ---- BND: the byte after MaxInput (corpus 0.2.0) ---------------------------

// defineInputProbe covers SG-R-INP-01 as written: a codec LOOKING at the byte
// after MaxInput (to find trailing data after a complete stream) does not
// violate it; only TAKING that byte does. For every codec: a valid stream of L
// bytes plus trailing bytes is corrupt (trailing data under the codec's own
// rules) with MaxInput L as well as with MaxInput L+1, and with many trailing
// bytes. For identity, which takes everything it passes, L+1 bytes with
// MaxInput L is input_limit.
func defineInputProbe(b *builder) {
	data := corpus.Data(91, 300)
	streams := []struct {
		label, encoding string
		tags            []string
		rule            string
		stream          []byte
	}{
		{"gzip", "gzip", nil, "SG-R-CDC-02", corpus.GzipStored(data)},
		{"zlib", "deflate", nil, "SG-R-CDC-03", corpus.ZlibStored(data)},
		{"raw deflate", "deflate", nil, "SG-R-CDC-03", corpus.StoredDeflate(data)},
		{"brotli", "br", []string{"brotli", "needs-br"}, "SG-R-CDC-04", corpus.BrotliStored(data, 16)},
		{"zstd", "zstd", []string{"zstd", "needs-zstd"}, "SG-R-CDC-05", corpus.ZstdStored(data, 17)},
	}
	for _, s := range streams {
		L := int64(len(s.stream))
		cases := []struct {
			tail     []byte
			maxInput int64
			desc     string
		}{
			{[]byte{0}, L, "one trailing zero byte, MaxInput %d = stream size: the codec only looks at the byte beyond the limit, so the result is corrupt (trailing data), not input_limit"},
			{[]byte{0}, L + 1, "one trailing zero byte, MaxInput %d = stream size + 1 (control): corrupt (trailing data)"},
			{make([]byte, 1000), L, "1000 trailing zero bytes, MaxInput %d = stream size: corrupt (trailing data); the source is asked for no more than MaxInput+1 bytes"},
		}
		for _, c := range cases {
			b.addFile("BND", vector{
				Description: fmt.Sprintf("%s stream of %d bytes plus ", s.label, L) + fmt.Sprintf(c.desc, c.maxInput),
				Rules:       ids("SG-R-INP-01", "SG-R-INP-02", s.rule),
				Tags:        append([]string{"boundary", "input-limit", "trailing"}, s.tags...),
				Encodings:   []string{s.encoding},
				Limits:      with(generous, "max_input", c.maxInput),
				Expect:      corruptStream(1),
			}, append(bytes.Clone(s.stream), c.tail...))
		}
	}

	body := corpus.Data(92, 100)
	b.addFile("BND", vector{
		Description: "identity body of 101 bytes with MaxInput 100 (control): identity takes every byte it passes, so the 101st is input_limit",
		Rules:       ids("SG-R-INP-01", "SG-R-INP-02", "SG-R-CDC-10"),
		Tags:        []string{"boundary", "input-limit", "identity"},
		Limits:      with(generous, "max_input", 100),
		Expect:      readError("input_limit", 1, 100),
	}, append(bytes.Clone(body), 0))
	b.addFile("BND", vector{
		Description: "identity body of 1100 bytes with MaxInput 100 (control): input_limit after exactly 100 bytes",
		Rules:       ids("SG-R-INP-01", "SG-R-INP-02", "SG-R-CDC-10"),
		Tags:        []string{"boundary", "input-limit", "identity"},
		Encodings:   []string{"identity"},
		Limits:      with(generous, "max_input", 100),
		Expect:      readError("input_limit", 1, 100),
	}, append(bytes.Clone(body), make([]byte, 1000)...))
}
