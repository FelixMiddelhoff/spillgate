package spillgate

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// Boundary tests found by mutation testing: each pins a comparison at its
// edge, where a flipped operator used to survive the suite.

// Lower-casing touches exactly A..Z and nothing next to them.
//
// Covers: SG-R-HDR-05
func TestToLowerASCIIBoundaries(t *testing.T) {
	tests := map[string]string{
		"AZaz09-._":  "azaz09-._",
		"@[`{":       "@[`{", // the characters next to A, Z, a, z
		"ABCXYZ":     "abcxyz",
		"MiXeD-Case": "mixed-case",
	}
	for in, want := range tests {
		if got := toLowerASCII(in); got != want {
			t.Errorf("toLowerASCII(%q) = %q, want %q", in, got, want)
		}
	}
}

// A token may start with any letter or digit at the edges of each range and
// with nothing just outside of them.
//
// Covers: SG-R-HDR-04
func TestTokenAlphabetEdges(t *testing.T) {
	for _, c := range []byte{'a', 'z', 'A', 'Z', '0', '9'} {
		if !isAlphanumeric(c) {
			t.Errorf("%q must be alphanumeric", c)
		}
	}
	for _, c := range []byte{'`', '{', '@', '[', '/', ':', 0, 0x7f, 0x80} {
		if isAlphanumeric(c) {
			t.Errorf("%q must not be alphanumeric", c)
		}
	}
	supported := func(name string) bool { return name == "az09" }
	if layers, err := parseContentEncoding([]string{"AZ09"}, func(n string) bool { return n == "az09" }, 5); err != nil || len(layers) != 1 {
		t.Errorf("AZ09: %v %v", layers, err)
	}
	if _, err := parseContentEncoding([]string{"az09"}, supported, 5); err != nil {
		t.Errorf("az09: %v", err)
	}
}

// Error text shows at most maxQuotedBytes of attacker text, and says so only
// when it cut.
//
// Covers: SG-R-HDR-13
func TestQuoteUntrustedCutsAfterTheLimit(t *testing.T) {
	exact := strings.Repeat("x", maxQuotedBytes)
	if got := quoteUntrusted(exact); got != `"`+exact+`"` {
		t.Errorf("exactly %d bytes were altered: %s", maxQuotedBytes, got)
	}
	over := exact + "y"
	if got := quoteUntrusted(over); got != `"`+exact+`"...` {
		t.Errorf("%d bytes not cut right: %s", len(over), got)
	}
}

// The layer and the limit appear in the message only when they are set.
func TestErrorMessageOmitsZeroLayerAndLimit(t *testing.T) {
	plain := (&Error{Kind: KindCorrupt}).Error()
	if strings.Contains(plain, "layer") || strings.Contains(plain, "limit") {
		t.Errorf("zero Layer/Limit shown: %q", plain)
	}
	set := (&Error{Kind: KindOutputLimit, Layer: 1, Limit: 1}).Error()
	if !strings.Contains(set, "layer 1") || !strings.Contains(set, "limit 1") {
		t.Errorf("Layer 1 / Limit 1 missing: %q", set)
	}
}

// MaxLayers is accepted up to the hard maximum and refused above it; zero
// means the default.
//
// Covers: SG-R-LIM-03
func TestMaxLayersEdges(t *testing.T) {
	for n, ok := range map[int]bool{-1: false, 0: true, 1: true, HardMaxLayers: true, HardMaxLayers + 1: false} {
		err := Limits{MaxOutput: 1, MaxLayers: n}.Validate()
		if (err == nil) != ok {
			t.Errorf("MaxLayers %d: err = %v, want ok=%v", n, err, ok)
		}
	}
}

// After Close a codec reader fails every Read instead of decoding on.
//
// Covers: SG-R-RDR-06
func TestCodecReadersFailAfterClose(t *testing.T) {
	gz := bytes.NewReader(GzipStoredForTest([]byte("data")))
	for name, codec := range map[string]Codec{"gzip": gzipCodec{}, "deflate": deflateCodec{}} {
		src := io.Reader(gz)
		if name == "deflate" {
			src = bytes.NewReader([]byte{0x78, 0x01, 0x01, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01})
		}
		r, err := codec.NewReader(src.(Source))
		if err != nil {
			t.Fatal(err)
		}
		r.(io.Closer).Close()
		if n, err := r.Read(make([]byte, 8)); n != 0 || err == nil || errors.Is(err, io.EOF) {
			t.Errorf("%s: Read after Close = (%d, %v)", name, n, err)
		}
	}
}

// GzipStoredForTest builds a gzip stream with one stored block without
// importing the corpus package, which depends on this one.
func GzipStoredForTest(data []byte) []byte {
	out := []byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255}
	n := len(data)
	out = append(out, 1, byte(n), byte(n>>8), ^byte(n), ^byte(n>>8))
	out = append(out, data...)
	crc := uint32(0xffffffff)
	for _, b := range data {
		crc ^= uint32(b)
		for i := 0; i < 8; i++ {
			crc = crc>>1 ^ (0xedb88320 & -(crc & 1))
		}
	}
	crc = ^crc
	return append(out, byte(crc), byte(crc>>8), byte(crc>>16), byte(crc>>24), byte(n), byte(n>>8), 0, 0)
}
