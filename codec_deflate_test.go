package spillgate

import (
	"bytes"
	"compress/flate"
	"errors"
	"io"
	"strings"
	"testing"
)

// Covers: SG-R-CDC-03
func TestIsZlibHeader(t *testing.T) {
	// withCheck completes cmf with the FCHECK bits that make the pair valid.
	withCheck := func(cmf byte, flevelAndDict byte) byte {
		base := uint16(cmf)<<8 | uint16(flevelAndDict)
		return flevelAndDict | byte(zlibCheckModulus-base%zlibCheckModulus)%zlibCheckModulus
	}
	tests := []struct {
		name     string
		cmf, flg byte
		want     bool
	}{
		{"typical 78 9c", 0x78, 0x9c, true},
		{"typical 78 01", 0x78, 0x01, true},
		{"typical 78 da", 0x78, 0xda, true},
		{"small window", 0x08, 0x1d, true},
		{"CINFO 7 constructed", 0x78, withCheck(0x78, 0x40), true},
		{"CM 15 is reserved", 0x7f, withCheck(0x7f, 0), false},
		{"CM 0", 0x70, withCheck(0x70, 0), false},
		{"CINFO 8 is not allowed", 0x88, withCheck(0x88, 0), false},
		{"CINFO 15 is not allowed", 0xf8, withCheck(0xf8, 0), false},
		{"FCHECK off by one", 0x78, 0x9d, false},
		{"FCHECK off by 31 stays valid", 0x78, 0x9c - 31, true},
		{"gzip magic", 0x1f, 0x8b, false},
		{"zeros", 0, 0, false},
		{"ones", 0xff, 0xff, false},
	}
	for _, tc := range tests {
		if got := isZlibHeader(tc.cmf, tc.flg); got != tc.want {
			t.Errorf("%s: isZlibHeader(%#x, %#x) = %v, want %v", tc.name, tc.cmf, tc.flg, got, tc.want)
		}
	}
}

// Covers: SG-R-CDC-03
func TestDeflateAcceptsZlibAndRawByDefault(t *testing.T) {
	for _, size := range []int{0, 1, 100, 4096, 70000} {
		data := sampleData(size)
		requireDecodes(t, zlibBytes(t, data), "deflate", data)
		requireDecodes(t, rawDeflateBytes(t, data), "deflate", data)
	}
}

// Covers: SG-R-CDC-03
func TestDeflateStrictModeOnlyAcceptsZlib(t *testing.T) {
	data := sampleData(1000)
	requireDecodes(t, zlibBytes(t, data), "deflate", data, WithStrictZlib())
	requireCorrupt(t, rawDeflateBytes(t, data), "deflate", WithStrictZlib())
	requireCorrupt(t, nil, "deflate", WithStrictZlib())
}

// Covers: SG-R-CDC-03
func TestDeflateRejectsPresetDictionaries(t *testing.T) {
	// 0x78 0x20: valid zlib header with FDICT set; then a dictionary id and data.
	stream := append([]byte{0x78, 0x20, 1, 2, 3, 4}, rawDeflateBytes(t, []byte("data"))...)
	requireCorrupt(t, stream, "deflate")
	requireCorrupt(t, stream, "deflate", WithStrictZlib())

	// The reason matters: a garbage dictionary id must not merely happen to
	// fail later as a decoding error.
	_, err := decodeOne(stream, "deflate")
	if err == nil || !strings.Contains(err.Error(), "dictionar") {
		t.Fatalf("expected a preset-dictionary error, got %v", err)
	}
}

// Covers: SG-R-CDC-03
func TestDeflateChecksTheAdlerSum(t *testing.T) {
	good := zlibBytes(t, sampleData(500))
	for i := 1; i <= zlibTrailerSize; i++ {
		stream := bytes.Clone(good)
		stream[len(stream)-i] ^= 0x10
		requireCorrupt(t, stream, "deflate")
	}
}

// Covers: SG-R-CDC-03 SG-R-CDC-06
func TestDeflateEveryTruncationIsCorrupt(t *testing.T) {
	data := sampleData(300)
	for label, stream := range map[string][]byte{"zlib": zlibBytes(t, data), "raw": rawDeflateBytes(t, data)} {
		for n := range len(stream) {
			if _, err := decodeOne(stream[:n], "deflate"); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("%s truncated to %d bytes: %v", label, n, err)
			}
		}
	}
}

// Covers: SG-R-CDC-03
func TestDeflateBytesAfterTheStreamAreCorrupt(t *testing.T) {
	data := sampleData(100)
	for label, stream := range map[string][]byte{"zlib": zlibBytes(t, data), "raw": rawDeflateBytes(t, data)} {
		for _, trailing := range [][]byte{{0}, make([]byte, 100), []byte("garbage"), zlibBytes(t, data)} {
			requireCorrupt(t, append(bytes.Clone(stream), trailing...), "deflate")
		}
		_ = label
	}
}

// Every single-bit change of a zlib stream is harmless or corruption.
// Covers: SG-R-CDC-03 SG-I-05
func TestZlibEverySingleBitFlip(t *testing.T) {
	data := sampleData(200)
	good := zlibBytes(t, data)
	for bit := range len(good) * 8 {
		stream := bytes.Clone(good)
		stream[bit/8] ^= 1 << (bit % 8)

		got, err := decodeOne(stream, "deflate")
		switch {
		case err == nil && bytes.Equal(got, data):
		case errors.Is(err, ErrCorrupt) && got == nil:
		default:
			t.Fatalf("bit %d: got (%d bytes, %v)", bit, len(got), err)
		}
	}
}

// Raw deflate has no checksum, so a flipped bit may change the data; the only
// requirement is a clean result: success or corruption, nothing else.
// Covers: SG-R-CDC-03 SG-I-05
func TestRawDeflateEverySingleBitFlip(t *testing.T) {
	good := rawDeflateBytes(t, sampleData(200))
	for bit := range len(good) * 8 {
		stream := bytes.Clone(good)
		stream[bit/8] ^= 1 << (bit % 8)

		if _, err := decodeOne(stream, "deflate"); err != nil && !errors.Is(err, ErrCorrupt) {
			t.Fatalf("bit %d: %v", bit, err)
		}
	}
}

// A raw deflate stream whose first two bytes happen to look like a zlib header
// is treated as zlib and then fails; it is never misread as data.
// Covers: SG-R-CDC-03 SG-I-06
func TestRawDeflateThatLooksLikeZlibFailsClosed(t *testing.T) {
	payload := bytes.Repeat([]byte("q"), 29)
	// Non-final stored block (0x08: BFINAL 0, BTYPE 00, padding bit set),
	// LEN = 29, NLEN = ^29, payload, then an empty final stored block.
	stream := append([]byte{0x08, 0x1d, 0x00, 0xe2, 0xff}, payload...)
	stream = append(stream, 0x01, 0x00, 0x00, 0xff, 0xff)

	// Prove the vector is valid raw deflate and really starts like zlib.
	raw, err := io.ReadAll(flate.NewReader(bytes.NewReader(stream)))
	if err != nil || !bytes.Equal(raw, payload) {
		t.Fatalf("vector is not valid raw deflate: %v", err)
	}
	if !isZlibHeader(stream[0], stream[1]) {
		t.Fatal("vector does not look like a zlib header")
	}

	requireCorrupt(t, stream, "deflate")
	requireCorrupt(t, stream, "deflate", WithStrictZlib())
}

// Covers: SG-R-CDC-03 SG-R-CDC-06
func TestDeflateEmptyAndForeignInput(t *testing.T) {
	requireCorrupt(t, nil, "deflate")
	requireCorrupt(t, []byte{0x78}, "deflate")
	requireCorrupt(t, []byte("hello, this is not deflate"), "deflate")
	requireCorrupt(t, gzipBytes(t, sampleData(20)), "deflate") // header says deflate, bytes are gzip
}
