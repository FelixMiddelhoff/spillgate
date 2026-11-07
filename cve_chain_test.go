package spillgate

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// Advisories about Content-Encoding chains: Zapros CVE-2026-61541, urllib3
// CVE-2025-66418, curl CVE-2022-32206 and CVE-2023-23916, undici
// CVE-2026-22036. The common mistake: no bound on the number of layers, or a
// bound that is applied per header line and not to the whole header.

var chainLimits = Limits{MaxOutput: 1 << 20, DisableRatioLimit: true}

// nestedGzip returns data wrapped n times in gzip.
func nestedGzip(t *testing.T, data []byte, n int) []byte {
	t.Helper()
	for range n {
		data = gzipBytes(t, data)
	}
	return data
}

// CVE-2026-61541 (Zapros) and CVE-2025-66418 (urllib3): a hostile server lists
// ever more encodings. Five layers are fine, the sixth is refused before the
// source is touched.
//
// Covers: SG-R-HDR-11 SG-R-HDR-09 SG-R-API-03 SG-I-07
func TestCVE_2026_61541_And_2025_66418_UnboundedChain(t *testing.T) {
	data := sampleData(300)

	got, err := DecodeAll(bytes.NewReader(nestedGzip(t, data, 5)), repeatedLines("gzip", 5), chainLimits)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("five layers: %v", err)
	}
	for _, depth := range []int{6, 7, 16, 17, 100} {
		r, err := Decode(untouchedSource(t), repeatedLines("gzip", depth), chainLimits)
		if !errors.Is(err, ErrLayerLimit) || r != nil {
			t.Errorf("%d layers: got (%v, %v), want layer_limit", depth, r, err)
		}
	}

	// A caller who raises MaxLayers to the hard maximum still cannot go beyond 16 elements.
	raised := chainLimits
	raised.MaxLayers = HardMaxLayers
	if _, err := Decode(untouchedSource(t), repeatedLines("gzip", 17), raised); !errors.Is(err, ErrLayerLimit) {
		t.Errorf("17 elements with MaxLayers 16: %v", err)
	}
	raised.MaxLayers = HardMaxLayers + 1
	if _, err := Decode(untouchedSource(t), []string{"gzip"}, raised); !errors.Is(err, ErrInvalidLimits) {
		t.Errorf("MaxLayers 17: %v", err)
	}
}

// Whatever the spelling of the layers, they all count.
//
// Covers: SG-R-HDR-05 SG-R-HDR-07 SG-R-HDR-10 SG-R-HDR-11
func TestCVE_2025_66418_EverySpellingCounts(t *testing.T) {
	for name, header := range map[string]string{
		"upper case":         strings.Repeat("GZIP,", 6),
		"x-gzip alias":       strings.Repeat("x-gzip,", 6),
		"spaces and tabs":    strings.Repeat(" gzip \t,", 6),
		"mixed gzip/deflate": "gzip, deflate, gzip, deflate, gzip, deflate",
	} {
		if _, err := Decode(untouchedSource(t), []string{header}, chainLimits); !errors.Is(err, ErrLayerLimit) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// identity is not a layer, but it counts toward the element cap.
	exact := strings.Repeat("identity,", 15) + "gzip" // 16 elements
	if _, err := Decode(bytes.NewReader(gzipBytes(t, nil)), []string{exact}, chainLimits); err != nil {
		t.Errorf("16 elements: %v", err)
	}
	spam := strings.Repeat("identity,", 16) + "gzip" // 17 elements
	if _, err := Decode(untouchedSource(t), []string{spam}, chainLimits); !errors.Is(err, ErrLayerLimit) {
		t.Errorf("17 elements: %v", err)
	}
}

// CVE-2022-32206 and CVE-2023-23916 (curl): the second fix existed because the
// first cap applied per header line, so many lines evaded it. spillgate joins
// all field values first, so the cap sees the whole chain.
//
// Covers: SG-R-HDR-01 SG-R-HDR-02 SG-R-HDR-06 SG-R-HDR-14 SG-I-07
func TestCVE_2023_23916_CapAppliesToAllHeaderLinesTogether(t *testing.T) {
	data := sampleData(200)

	for name, lines := range map[string][]string{
		"six lines of one token":           repeatedLines("gzip", 6),
		"three lines of two tokens":        repeatedLines("gzip, gzip", 3),
		"two lines of three tokens":        repeatedLines("gzip, gzip, gzip", 2),
		"six lines with x-gzip and spaces": repeatedLines(" x-gzip ", 6),
	} {
		if _, err := Decode(untouchedSource(t), lines, chainLimits); !errors.Is(err, ErrLayerLimit) {
			t.Errorf("%s: %v", name, err)
		}
	}

	// The same five layers presented as one line or as five lines give the same result.
	stream := nestedGzip(t, data, 5)
	for name, lines := range map[string][]string{
		"one line":   {"gzip, gzip, gzip, gzip, gzip"},
		"five lines": repeatedLines("gzip", 5),
		"mixed":      {"gzip", "gzip, gzip", "", "gzip, gzip,"},
	} {
		got, err := DecodeAll(bytes.NewReader(stream), lines, chainLimits)
		if err != nil || !bytes.Equal(got, data) {
			t.Errorf("%s: %v", name, err)
		}
	}

	// A thousand empty lines are the empty chain; a thousand lines of "gzip," are far past the length cap.
	body := sampleData(50)
	got, err := DecodeAll(bytes.NewReader(body), repeatedLines("", 1000), chainLimits)
	if err != nil || !bytes.Equal(got, body) {
		t.Errorf("1000 empty lines: %v", err)
	}
	if _, err := Decode(untouchedSource(t), repeatedLines("gzip,", 1000), chainLimits); !errors.Is(err, ErrMalformedEncoding) {
		t.Errorf("1000 lines of gzip,: %v", err)
	}
}

// CVE-2026-22036 (undici): the header size limit allowed thousands of links.
// spillgate refuses an over-long header outright and a long list of tokens by
// the element cap, whichever comes first.
//
// Covers: SG-R-HDR-02 SG-R-HDR-06 SG-I-07
func TestCVE_2026_22036_ThousandsOfLinks(t *testing.T) {
	// 2000 tokens are 10000 bytes: over the 1024-byte header cap.
	if _, err := Decode(untouchedSource(t), []string{strings.Repeat("gzip,", 2000)}, chainLimits); !errors.Is(err, ErrMalformedEncoding) {
		t.Errorf("2000 tokens: %v", err)
	}
	// 204 tokens fit into 1024 bytes and hit the element cap.
	if _, err := Decode(untouchedSource(t), []string{strings.Repeat("gzip,", 204)}, chainLimits); !errors.Is(err, ErrLayerLimit) {
		t.Errorf("204 tokens: %v", err)
	}
	// Padding with whitespace does not hide the tokens.
	if _, err := Decode(untouchedSource(t), []string{strings.Repeat("gzip , ", 50)}, chainLimits); !errors.Is(err, ErrLayerLimit) {
		t.Errorf("50 padded tokens: %v", err)
	}
}
