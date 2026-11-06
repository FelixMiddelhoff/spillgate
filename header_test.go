package spillgate

import (
	"errors"
	"math/rand"
	"slices"
	"strings"
	"testing"
	"unicode"
)

// supportsGzipAndDeflate is the codec set of the core module.
func supportsGzipAndDeflate(name string) bool { return name == "gzip" || name == "deflate" }

// supportsAll is a codec set with the optional codecs available as well.
func supportsAll(name string) bool {
	return supportsGzipAndDeflate(name) || name == "br" || name == "zstd"
}

func parse(values ...string) ([]string, error) {
	return parseContentEncoding(values, supportsAll, DefaultMaxLayers)
}

func TestParseAcceptedHeaders(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		want   []string // decoding order
	}{
		// Covers: SG-R-HDR-01
		{"no header at all", nil, nil},
		{"single encoding", []string{"gzip"}, []string{"gzip"}},
		// Covers: SG-R-HDR-12
		{"decoding order is reversed", []string{"gzip, br"}, []string{"br", "gzip"}},
		{"three layers", []string{"gzip, deflate, zstd"}, []string{"zstd", "deflate", "gzip"}},
		{"same encoding twice", []string{"gzip, gzip"}, []string{"gzip", "gzip"}},
		// Covers: SG-R-HDR-03
		{"empty field value is the empty chain", []string{""}, nil},
		{"whitespace only", []string{" \t "}, nil},
		{"only commas", []string{",,,"}, nil},
		{"comma and spaces", []string{" , ,\t,"}, nil},
		{"leading comma", []string{",gzip"}, []string{"gzip"}},
		{"trailing comma", []string{"gzip,"}, []string{"gzip"}},
		{"doubled comma", []string{"gzip,,br"}, []string{"br", "gzip"}},
		{"spaces and tabs around elements", []string{" \tgzip\t , br "}, []string{"br", "gzip"}},
		// Covers: SG-R-HDR-05
		{"upper case", []string{"GZIP"}, []string{"gzip"}},
		{"mixed case", []string{"GzIp, bR"}, []string{"br", "gzip"}},
		// Covers: SG-R-HDR-07
		{"x-gzip is gzip", []string{"x-gzip"}, []string{"gzip"}},
		{"X-GZIP is gzip", []string{"X-GZIP, br"}, []string{"br", "gzip"}},
		// Covers: SG-R-HDR-10
		{"identity alone", []string{"identity"}, nil},
		{"identity first", []string{"identity, gzip"}, []string{"gzip"}},
		{"identity last", []string{"gzip, identity"}, []string{"gzip"}},
		{"identity in the middle", []string{"gzip, identity, br"}, []string{"br", "gzip"}},
		{"IDENTITY", []string{"IDENTITY"}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parse(tc.values...)
			if err != nil {
				t.Fatalf("parse(%q) = %v", tc.values, err)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("parse(%q) = %q, want %q", tc.values, got, tc.want)
			}
		})
	}
}

func TestParseMalformedHeaders(t *testing.T) {
	long33 := strings.Repeat("a", 33)
	tests := []struct {
		name  string
		value string
	}{
		// Covers: SG-R-HDR-04
		{"parameter", "gzip;q=1"},
		{"parameter with space", "gzip ; q=1"},
		{"quoted", `"gzip"`},
		{"single quotes", "'gzip'"},
		{"slash", "gzip/1"},
		{"underscore start", "_gzip"},
		{"dot start", ".gzip"},
		{"dash start", "-gzip"},
		{"space inside", "g zip"},
		{"token of 33 bytes", long33},
		{"NUL", "gzip\x00"},
		{"NUL inside", "gz\x00ip"},
		{"carriage return", "gzip\r"},
		{"line feed", "gzip\nbr"},
		{"CRLF injection", "gzip\r\nX-Evil: 1"},
		{"vertical tab", "gzip\v"},
		{"form feed", "\fgzip"},
		{"non-breaking space", "gzip "},
		{"DEL", "gzip\x7f"},
		{"high byte", "gzip\xff"},
		{"UTF-8 letter", "gzipé"},
		{"Cyrillic homoglyph", "gзip"},
		{"Kelvin sign", "Kelvin"},
		{"exclamation mark", "gzip!"},
		{"parenthesis", "gzip(1)"},
		{"semicolon only", ";"},
		// A valid element after the broken one does not rescue the header.
		{"bad element then good", "gzip;q=1, br"},
		{"good element then bad", "br, gzip;q=1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parse(tc.value)
			if !errors.Is(err, ErrMalformedEncoding) {
				t.Fatalf("parse(%q) = %v, want malformed_encoding", tc.value, err)
			}
		})
	}
}

// Covers: SG-R-HDR-04
func TestParseTokenLengthBoundary(t *testing.T) {
	supportedLong := func(name string) bool { return len(name) == 32 }
	if _, err := parseContentEncoding([]string{strings.Repeat("a", 32)}, supportedLong, 5); err != nil {
		t.Fatalf("32-byte token should be accepted: %v", err)
	}
	if _, err := parseContentEncoding([]string{strings.Repeat("a", 33)}, supportedLong, 5); !errors.Is(err, ErrMalformedEncoding) {
		t.Fatalf("33-byte token: %v", err)
	}
}

// Covers: SG-R-HDR-08 SG-R-HDR-09 SG-I-06
func TestParseUnsupportedEncodings(t *testing.T) {
	for _, name := range []string{
		"compress", "x-compress", "dcb", "dcz", "aes128gcm", "snappy", "deflate64", "lz4", "bzip2", "xz",
		"gzip2", "gzipp", "br2", "zstd1", "123", "a.b", "a_b", "a-b",
	} {
		_, err := parse(name)
		if !errors.Is(err, ErrUnsupportedEncoding) {
			t.Errorf("parse(%q) = %v, want unsupported_encoding", name, err)
		}
		// One unsupported element poisons the whole chain, wherever it stands.
		for _, header := range []string{"gzip, " + name, name + ", gzip", "gzip, " + name + ", br"} {
			if _, err := parse(header); !errors.Is(err, ErrUnsupportedEncoding) {
				t.Errorf("parse(%q) = %v, want unsupported_encoding", header, err)
			}
		}
	}
}

// Covers: SG-R-HDR-08
func TestParseOptionalCodecsFollowTheCodecSet(t *testing.T) {
	if _, err := parseContentEncoding([]string{"br"}, supportsGzipAndDeflate, 5); !errors.Is(err, ErrUnsupportedEncoding) {
		t.Fatalf("br without the br codec: %v", err)
	}
	if _, err := parseContentEncoding([]string{"zstd"}, supportsGzipAndDeflate, 5); !errors.Is(err, ErrUnsupportedEncoding) {
		t.Fatalf("zstd without the zstd codec: %v", err)
	}
	if _, err := parseContentEncoding([]string{"br, zstd"}, supportsAll, 5); err != nil {
		t.Fatalf("both codecs available: %v", err)
	}
}

// Covers: SG-R-HDR-02 SG-I-07
func TestParseHeaderLengthBoundary(t *testing.T) {
	// 1024 bytes in total: 1023 spaces would be fine, plus a name makes it exact.
	exact := strings.Repeat(" ", maxHeaderLength-len("gzip")) + "gzip"
	if _, err := parse(exact); err != nil {
		t.Fatalf("header of exactly %d bytes: %v", len(exact), err)
	}
	if _, err := parse(" " + exact); !errors.Is(err, ErrMalformedEncoding) {
		t.Fatalf("header of %d bytes: %v", len(exact)+1, err)
	}
	// The joining comma counts toward the length: 1023 bytes of values plus
	// the comma fit exactly, 1024 bytes of values plus the comma do not.
	first := strings.Repeat(" ", 600-len("gzip")) + "gzip"
	if _, err := parse(first, strings.Repeat(" ", 423)); err != nil {
		t.Fatalf("two values, 1024 bytes with the joining comma: %v", err)
	}
	if _, err := parse(first, strings.Repeat(" ", 424)); !errors.Is(err, ErrMalformedEncoding) {
		t.Fatalf("two values, 1025 bytes with the joining comma: %v", err)
	}
}

// Covers: SG-R-HDR-02 SG-I-07
func TestParseHugeHeadersAreRejectedCheaply(t *testing.T) {
	huge := strings.Repeat("gzip,", 10000)
	if _, err := parse(huge); !errors.Is(err, ErrMalformedEncoding) {
		t.Fatalf("10000 tokens: %v", err)
	}
	many := make([]string, 1000)
	for i := range many {
		many[i] = "gzip"
	}
	if _, err := parse(many...); !errors.Is(err, ErrMalformedEncoding) {
		t.Fatalf("1000 header lines: %v", err)
	}
}

// Covers: SG-R-HDR-06 SG-R-HDR-10 SG-I-07
func TestParseElementCap(t *testing.T) {
	list := func(name string, n int) string { return strings.TrimSuffix(strings.Repeat(name+",", n), ",") }
	supportsIdentityOnly := func(string) bool { return false }

	if _, err := parseContentEncoding([]string{list("identity", maxElements)}, supportsIdentityOnly, 5); err != nil {
		t.Fatalf("16 identity elements: %v", err)
	}
	// Identity spam must not dodge the cap (Zapros / urllib3 class).
	err := func() error {
		_, err := parseContentEncoding([]string{list("identity", maxElements+1)}, supportsIdentityOnly, 5)
		return err
	}()
	if !errors.Is(err, ErrLayerLimit) {
		t.Fatalf("17 identity elements: %v", err)
	}
	if _, err := parseContentEncoding([]string{list("gzip", maxElements+1)}, supportsGzipAndDeflate, 16); !errors.Is(err, ErrLayerLimit) {
		t.Fatalf("17 gzip elements even with MaxLayers 16: %v", err)
	}
	// Empty elements do not count.
	if _, err := parseContentEncoding([]string{strings.Repeat(",", 500) + "gzip"}, supportsGzipAndDeflate, 5); err != nil {
		t.Fatalf("empty elements counted: %v", err)
	}
}

// Covers: SG-R-HDR-11 SG-I-07
func TestParseLayerLimit(t *testing.T) {
	five := "gzip,gzip,gzip,gzip,gzip"
	six := five + ",gzip"
	if got, err := parseContentEncoding([]string{five}, supportsGzipAndDeflate, 5); err != nil || len(got) != 5 {
		t.Fatalf("five layers: %v %v", got, err)
	}
	if _, err := parseContentEncoding([]string{six}, supportsGzipAndDeflate, 5); !errors.Is(err, ErrLayerLimit) {
		t.Fatalf("six layers: %v", err)
	}
	if _, err := parseContentEncoding([]string{"gzip"}, supportsGzipAndDeflate, 1); err != nil {
		t.Fatalf("one layer with MaxLayers 1: %v", err)
	}
	if _, err := parseContentEncoding([]string{"gzip,gzip"}, supportsGzipAndDeflate, 1); !errors.Is(err, ErrLayerLimit) {
		t.Fatalf("two layers with MaxLayers 1: %v", err)
	}
	// identity does not count as a layer.
	if _, err := parseContentEncoding([]string{"identity,gzip,identity"}, supportsGzipAndDeflate, 1); err != nil {
		t.Fatalf("identity counted as a layer: %v", err)
	}
}

// The fixed evaluation order decides the outcome class when a header has
// several faults.
// Covers: SG-R-HDR-02 SG-R-HDR-04 SG-R-HDR-06 SG-R-HDR-08 SG-R-HDR-11
func TestParseEvaluationOrder(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		maxL   int
		want   error
	}{
		{"length beats grammar", []string{strings.Repeat("a;", 600)}, 5, ErrMalformedEncoding},
		{"grammar beats element count", []string{strings.Repeat("gzip,", 20) + "bad;token"}, 5, ErrMalformedEncoding},
		{"element count beats unsupported", []string{strings.Repeat("nope,", 17)}, 5, ErrLayerLimit},
		{"unsupported beats layer count", []string{"gzip,gzip,gzip,nope"}, 2, ErrUnsupportedEncoding},
		{"layer count last", []string{"gzip,gzip,gzip"}, 2, ErrLayerLimit},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseContentEncoding(tc.values, supportsAll, tc.maxL)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

// Covers: SG-R-HDR-14
func TestParseEquivalentPresentationsGiveTheSameResult(t *testing.T) {
	canonical, err := parse("gzip, br, deflate")
	if err != nil {
		t.Fatal(err)
	}
	for _, values := range [][]string{
		{"gzip,br,deflate"},
		{"gzip", "br", "deflate"},
		{"gzip, br", "deflate"},
		{"gzip", "br, deflate"},
		{" GZIP ,\tBr , DEFLATE "},
		{",gzip,,br,,deflate,"},
		{"", "gzip", "", "br", "", "deflate", ""},
		{"x-gzip, br, deflate"},
		{"identity, gzip, identity, br, deflate"},
	} {
		got, err := parse(values...)
		if err != nil || !slices.Equal(got, canonical) {
			t.Errorf("parse(%q) = %q, %v; want %q", values, got, err, canonical)
		}
	}
}

// Randomly re-present the same list; the result must not change. Seeded.
// Covers: SG-R-HDR-14
func TestParseRandomPresentationsAreEquivalent(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	pool := []string{"gzip", "deflate", "br", "zstd", "x-gzip", "identity"}
	for range 3000 {
		names := make([]string, rng.Intn(6))
		for i := range names {
			names[i] = pool[rng.Intn(len(pool))]
		}
		want, wantErr := parse(strings.Join(names, ","))

		got, gotErr := parse(scramble(rng, names)...)
		if (wantErr == nil) != (gotErr == nil) || !slices.Equal(got, want) {
			t.Fatalf("names %q: canonical (%q, %v) != scrambled (%q, %v)", names, want, wantErr, got, gotErr)
		}
	}
}

// scramble renders names as several header values with random case, spacing
// and empty elements.
func scramble(rng *rand.Rand, names []string) []string {
	var values []string
	current := ""
	spaces := []string{"", " ", "\t", "  \t "}
	for _, name := range names {
		if rng.Intn(2) == 0 {
			name = strings.ToUpper(name)
		}
		current += spaces[rng.Intn(len(spaces))] + name + spaces[rng.Intn(len(spaces))]
		if rng.Intn(3) == 0 {
			current += ","
		}
		if rng.Intn(3) == 0 { // start a new header line
			values = append(values, current)
			current = ""
		} else if current != "" && !strings.HasSuffix(current, ",") {
			current += ","
		}
		if rng.Intn(4) == 0 {
			current += ","
		}
	}
	return append(values, current)
}

// Error messages must stay bounded and free of control characters whatever
// the attacker sends.
// Covers: SG-R-HDR-13
func TestErrorMessagesAreBoundedAndEscaped(t *testing.T) {
	hostile := []string{
		"gzip\r\nX-Injected: yes",
		"\x1b[31mred\x1b[0m",
		strings.Repeat("A", 1000),
		strings.Repeat("\x00", 40),
		"nope line-separator",
		"\xff\xfe\xfd",
		strings.Repeat("é", 100),
	}
	for _, h := range hostile {
		_, err := parse(h)
		if err == nil {
			t.Fatalf("hostile header %q accepted", h)
		}
		msg := err.Error()
		if len(msg) > 400 {
			t.Errorf("message of %d bytes for %q", len(msg), h)
		}
		for _, r := range msg {
			if unicode.IsControl(r) || r == ' ' || r == ' ' {
				t.Errorf("message %q contains control character %U", msg, r)
			}
		}
		if strings.Contains(msg, strings.Repeat("A", 33)) {
			t.Errorf("message echoes more than %d bytes of attacker text", maxQuotedBytes)
		}
	}

	// Unsupported but well-formed names are echoed, quoted.
	_, err := parse("snappy")
	if err == nil || !strings.Contains(err.Error(), `"snappy"`) {
		t.Fatalf("expected quoted name in %v", err)
	}
}

func TestQuoteUntrustedTruncates(t *testing.T) {
	got := quoteUntrusted(strings.Repeat("x", 100))
	if want := `"` + strings.Repeat("x", maxQuotedBytes) + `"...`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if got := quoteUntrusted("ok"); got != `"ok"` {
		t.Fatalf("got %q", got)
	}
}

func TestParseDoesNotModifyItsInput(t *testing.T) {
	values := []string{" GZIP , br "}
	before := slices.Clone(values)
	if _, err := parse(values...); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(values, before) {
		t.Fatalf("input modified: %q", values)
	}
}
