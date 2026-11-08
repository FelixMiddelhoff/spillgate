package corpus

import (
	"bytes"
	"encoding/json"
	"testing"
)

// The brotli and zstd constructions are proven valid by decoding them with the
// real decoders in the br and zstd modules. These tests pin the exact bytes, so
// that an edit that changes a stream (and with it every manifest hash) is
// caught here first, and check the structure that does not need a decoder.

func TestBrotliAndZstdGoldenHashes(t *testing.T) {
	golden := map[string]string{
		"brotli zeros 25801 w16":  SHA256Hex(BrotliZeros(25801, 16)),
		"brotli zeros 1 GiB w24":  SHA256Hex(BrotliZeros(1<<30, 24)),
		"brotli stored 100 w16":   SHA256Hex(BrotliStored(Data(7, 100), 16)),
		"brotli large window":     SHA256Hex(BrotliLargeWindowPrefix()),
		"zstd zeros 25801 w17":    SHA256Hex(ZstdZeros(25801, 17)),
		"zstd zeros 1 GiB w23":    SHA256Hex(ZstdZeros(1<<30, 23)),
		"zstd stored 100 w17":     SHA256Hex(ZstdStored(Data(8, 100), 17)),
		"zstd skippable 5":        SHA256Hex(ZstdSkippable(5)),
		"zstd header single 8MiB": SHA256Hex(ZstdHeader{SingleSegment: true, ContentSize: u64(8 << 20)}.Bytes()),
	}
	want := map[string]string{
		"brotli zeros 25801 w16":  "2769a2090b234336419044f8ca5658bbecb7a2aa082a2a133aacb7b15e1e417f",
		"brotli zeros 1 GiB w24":  "8b74d70d688e26ac705a0f94931fbcfe51741abc78cda5ff6eb2857b3464011b",
		"brotli stored 100 w16":   "118391f17b6e18fd9ad5d2ec1315d087445b64eb40443300a90b2314a0c330e7",
		"brotli large window":     "84fc05949dc1e486652a4ed316afb6434e9437eb30b714594a1d0b4205776602",
		"zstd zeros 25801 w17":    "bb49608719755466301602fe6d347992d0c04db59938feb1c7fb8b38d3af5a46",
		"zstd zeros 1 GiB w23":    "307e7b01efe2d1a936c60a2da6fd80b6f20f04030ff13c5d12ec411d3371b280",
		"zstd stored 100 w17":     "a6fdda266d1aaae28273f70fd7de9d8ff8f6580ef5ae2a26d1f9998681460299",
		"zstd skippable 5":        "d1714c153011e3a739448d0b2cba4e65bae19d18534dcef2c83aa3904f9bbf81",
		"zstd header single 8MiB": "e58f88208e60913bc066ef8ac1ca76b5e5732d81d702a58ce947d17a14c855e8",
	}
	for name, got := range golden {
		if got != want[name] {
			t.Errorf("%s: hash changed to %s", name, got)
		}
	}
}

func u64(n uint64) *uint64 { return &n }
func u32(n uint32) *uint32 { return &n }

func TestZstdHeaderBytes(t *testing.T) {
	magic := []byte{0x28, 0xB5, 0x2F, 0xFD}
	tests := []struct {
		name string
		h    ZstdHeader
		want []byte // after the magic number
	}{
		{"window 2^17", ZstdHeader{WindowLog: 17}, []byte{0x00, 7 << 3}},
		{"window 2^10 with mantissa 5", ZstdHeader{WindowLog: 10, Mantissa: 5}, []byte{0x00, 5}},
		{"checksum flag", ZstdHeader{WindowLog: 10, Checksum: true}, []byte{0x04, 0}},
		{"reserved bit", ZstdHeader{WindowLog: 10, ReservedBit: true}, []byte{0x08, 0}},
		{"dictionary id", ZstdHeader{WindowLog: 10, DictionaryID: u32(0x01020304)}, []byte{0x03, 0, 4, 3, 2, 1}},
		{"single segment, 1-byte size", ZstdHeader{SingleSegment: true, ContentSize: u64(200)}, []byte{0x20, 200}},
		{"single segment, 2-byte size", ZstdHeader{SingleSegment: true, ContentSize: u64(300)}, []byte{0x60, 44, 0}},
		{"single segment, 4-byte size", ZstdHeader{SingleSegment: true, ContentSize: u64(70000)}, []byte{0xA0, 0x70, 0x11, 0x01, 0x00}},
		{"single segment, 8-byte size", ZstdHeader{SingleSegment: true, ContentSize: u64(1 << 40)}, []byte{0xE0, 0, 0, 0, 0, 0, 1, 0, 0}},
		{"window plus 4-byte size", ZstdHeader{WindowLog: 10, ContentSize: u64(10)}, []byte{0x80, 0, 10, 0, 0, 0}},
	}
	for _, tc := range tests {
		if got := tc.h.Bytes(); !bytes.Equal(got, append(bytes.Clone(magic), tc.want...)) {
			t.Errorf("%s: % x, want % x", tc.name, got, append(bytes.Clone(magic), tc.want...))
		}
	}
}

func TestZstdBlocks(t *testing.T) {
	// One RLE block of 5 bytes, last: header = 5<<3 | 1<<1 | 1 = 0x2B.
	if got := ZstdRLEBlocks(5, ZstdBlockMax, 7, true); !bytes.Equal(got, []byte{0x2B, 0x00, 0x00, 7}) {
		t.Errorf("RLE block: % x", got)
	}
	// 200000 bytes need two blocks, only the last is marked last.
	got := ZstdRLEBlocks(200000, ZstdBlockMax, 0, true)
	if len(got) != 8 || got[0]&1 != 0 || got[4]&1 != 1 {
		t.Errorf("two RLE blocks: % x", got)
	}
	// Not the last block of the frame.
	if got := ZstdRLEBlocks(5, ZstdBlockMax, 0, false); got[0]&1 != 0 {
		t.Errorf("block marked last: % x", got)
	}
	// Raw block of "ab": header = 2<<3 | 0<<1 | 1 = 0x11.
	if got := ZstdRawBlocks([]byte("ab"), ZstdBlockMax, true); !bytes.Equal(got, []byte{0x11, 0, 0, 'a', 'b'}) {
		t.Errorf("raw block: % x", got)
	}
	// Empty data is one empty last raw block.
	if got := ZstdRawBlocks(nil, ZstdBlockMax, true); !bytes.Equal(got, []byte{0x01, 0, 0}) {
		t.Errorf("empty raw block: % x", got)
	}
	// Small windows limit the block size.
	if h := (ZstdHeader{WindowLog: 10}); h.blockMax() != 1024 {
		t.Errorf("blockMax = %d", h.blockMax())
	}
	if h := (ZstdHeader{SingleSegment: true}); h.blockMax() != ZstdBlockMax {
		t.Errorf("blockMax single segment = %d", h.blockMax())
	}
	if got := ZstdSkippable(3); !bytes.Equal(got, []byte{0x50, 0x2A, 0x4D, 0x18, 3, 0, 0, 0, 0, 0, 0}) {
		t.Errorf("skippable: % x", got)
	}
}

func TestBrotliStructure(t *testing.T) {
	// A zeros stream of n bytes: about 12 bytes per 16 MiB meta-block, so it stays tiny.
	if got := len(BrotliZeros(1<<30, 24)); got > 1000 {
		t.Errorf("1 GiB of zeros takes %d bytes", got)
	}
	// The window bits are the first 1, 4 or 7 bits of the stream.
	for _, tc := range []struct {
		wbits int
		width uint // bits of the WBITS field
		field byte
	}{{16, 1, 0x0}, {24, 4, 0xF}, {18, 4, 0x3}, {17, 7, 0x01}, {10, 7, 0x21}, {15, 7, 0x71}} {
		mask := byte(1)<<tc.width - 1
		if got := BrotliStored(nil, tc.wbits)[0] & mask; got != tc.field {
			t.Errorf("window bits %d: field %#x, want %#x", tc.wbits, got, tc.field)
		}
	}
	if BrotliLargeWindowPrefix()[0] != 0x11 {
		t.Error("large-window marker byte")
	}
	// The remainder rule: a size just above a multiple of 2^24 is split so no
	// meta-block is smaller than the minimum.
	a, b := BrotliZeros(1<<24+5, 16), BrotliZeros(1<<24+brotliMinCommandBytes, 16)
	if len(a) == 0 || len(b) == 0 || len(a) < len(BrotliZeros(1<<24, 16)) {
		t.Error("remainder handling lost a meta-block")
	}
}

func TestBrotliPanicsOnImpossibleWindows(t *testing.T) {
	for _, wbits := range []int{9, 25, 0, -1} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("window bits %d did not panic", wbits)
				}
			}()
			BrotliStored(nil, wbits)
		}()
	}
}

func TestGenerateBrotliAndZstd(t *testing.T) {
	data := Data(3, 500)
	for name, tc := range map[string]struct {
		spec Spec
		want []byte
	}{
		"br zeros":   {ZerosOf("br", 30000, 16), BrotliZeros(30000, 16)},
		"zstd zeros": {ZerosOf("zstd", 30000, 17), ZstdZeros(30000, 17)},
		"br data":    {StoredWindow("br", 3, 500, 18), BrotliStored(data, 18)},
		"zstd data":  {StoredWindow("zstd", 3, 500, 20), ZstdStored(data, 20)},
		"br wrap":    {WrapWindow("br", 2, 16, StoredWindow("zstd", 3, 500, 17)), BrotliStored(BrotliStored(ZstdStored(data, 17), 16), 16)},
	} {
		got, err := Generate(tc.spec)
		if err != nil || !bytes.Equal(got, tc.want) {
			t.Errorf("%s: err=%v equal=%v", name, err, bytes.Equal(got, tc.want))
		}
	}

	for name, spec := range map[string]Spec{
		"br without window":        ZerosOf("br", 100, 0),
		"br window too big":        ZerosOf("br", 100, 25),
		"zstd without window":      ZerosOf("zstd", 100, 0),
		"zstd window too big":      ZerosOf("zstd", 100, 42),
		"br data without window":   Stored("br", 1, 10),
		"zstd data without window": Stored("zstd", 1, 10),
		"unknown wrap codec":       {Kind: "wrap", Params: json.RawMessage(`{"codec":"lz4","times":1,"inner":{"kind":"data","params":{"codec":"gzip","seed":1,"size":1}}}`)},
	} {
		if _, err := Generate(spec); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}
