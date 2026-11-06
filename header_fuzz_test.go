package spillgate

import (
	"errors"
	"slices"
	"testing"
	"unicode"
)

// FuzzParseContentEncoding feeds arbitrary header values to the parser and
// checks the properties that must hold for every input: no panic, a closed
// set of outcomes, bounded and clean error messages, bounded results, and the
// equivalence of one comma-joined value and several values (SG-R-HDR-14).
//
// Covers: SG-I-05 SG-I-06 SG-I-07 SG-R-HDR-13 SG-R-HDR-14
func FuzzParseContentEncoding(f *testing.F) {
	for _, seed := range [][2]string{
		{"gzip", "br"}, {"", ""}, {",", ","}, {"gzip;q=1", "x"}, {"GZIP\r\n", "deflate"},
		{"identity,identity,identity", "gzip"}, {"\x00", "\xff"}, {"compress", "x-gzip"},
	} {
		f.Add(seed[0], seed[1])
	}

	f.Fuzz(func(t *testing.T, a, b string) {
		two, errTwo := parseContentEncoding([]string{a, b}, supportsAll, DefaultMaxLayers)
		joined, errJoined := parseContentEncoding([]string{a + "," + b}, supportsAll, DefaultMaxLayers)

		if (errTwo == nil) != (errJoined == nil) || !slices.Equal(two, joined) {
			t.Fatalf("presentations differ: (%q, %v) vs (%q, %v)", two, errTwo, joined, errJoined)
		}
		if errTwo == nil {
			checkAcceptedChain(t, two)
			return
		}
		checkRejection(t, errTwo)
	})
}

func checkAcceptedChain(t *testing.T, layers []string) {
	t.Helper()
	if len(layers) > DefaultMaxLayers {
		t.Fatalf("%d layers accepted, limit %d", len(layers), DefaultMaxLayers)
	}
	for _, name := range layers {
		if !supportsAll(name) {
			t.Fatalf("unsupported layer %q accepted", name)
		}
	}
}

func checkRejection(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrMalformedEncoding) && !errors.Is(err, ErrUnsupportedEncoding) && !errors.Is(err, ErrLayerLimit) {
		t.Fatalf("unexpected error class: %v", err)
	}
	msg := err.Error()
	if len(msg) > 400 {
		t.Fatalf("message of %d bytes", len(msg))
	}
	for _, r := range msg {
		if unicode.IsControl(r) {
			t.Fatalf("control character %U in message %q", r, msg)
		}
	}
}
