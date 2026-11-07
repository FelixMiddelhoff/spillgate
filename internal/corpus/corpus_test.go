package corpus

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"testing"
)

// The corpus constructions are checked against the standard library's
// decoders, which are independent of this repository's own decoding code.

// countZeros reads r to the end and returns the number of bytes and whether
// all of them were zero.
func countZeros(t *testing.T, r io.Reader) (n int64, allZero bool) {
	t.Helper()
	allZero = true
	buf := make([]byte, 1<<16)
	for {
		m, err := r.Read(buf)
		n += int64(m)
		for _, b := range buf[:m] {
			if b != 0 {
				allZero = false
			}
		}
		if err == io.EOF {
			return n, allZero
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestZerosDeflateDecodesToExactlyTheStatedZeros(t *testing.T) {
	for _, matches := range []int64{0, 1, 2, 3, 10, 100, 1000, 100000} {
		n, allZero := countZeros(t, flate.NewReader(bytes.NewReader(ZerosDeflate(matches))))
		if n != ZerosDecodedSize(matches) || !allZero {
			t.Errorf("matches=%d: got %d bytes (all zero: %v), want %d", matches, n, allZero, ZerosDecodedSize(matches))
		}
	}
}

// The construction really reaches the best ratio DEFLATE allows.
func TestZerosDeflateReachesTheMaximumRatio(t *testing.T) {
	const matches = 1 << 20
	stream := ZerosDeflate(matches)
	ratio := float64(ZerosDecodedSize(matches)) / float64(len(stream))
	if ratio < 1030 || ratio > 1033 {
		t.Fatalf("ratio %.2f, want about 1032", ratio)
	}
}

func TestZerosWrappersPassTheStandardLibraryChecksums(t *testing.T) {
	for _, matches := range []int64{0, 1, 77, 5000} {
		gz, err := gzip.NewReader(bytes.NewReader(GzipZeros(matches)))
		if err != nil {
			t.Fatal(err)
		}
		if n, ok := countZeros(t, gz); n != ZerosDecodedSize(matches) || !ok {
			t.Errorf("gzip matches=%d: %d bytes, zero=%v", matches, n, ok)
		}

		zr, err := zlib.NewReader(bytes.NewReader(ZlibZeros(matches)))
		if err != nil {
			t.Fatal(err)
		}
		if n, ok := countZeros(t, zr); n != ZerosDecodedSize(matches) || !ok {
			t.Errorf("zlib matches=%d: %d bytes, zero=%v", matches, n, ok)
		}
	}
}

func TestStoredDeflateRoundTrips(t *testing.T) {
	for _, size := range []int{0, 1, 100, 65534, 65535, 65536, 65537, 200000} {
		data := Data(7, size)
		got, err := io.ReadAll(flate.NewReader(bytes.NewReader(StoredDeflate(data))))
		if err != nil || !bytes.Equal(got, data) {
			t.Errorf("size %d: err=%v equal=%v", size, err, bytes.Equal(got, data))
		}
	}
}

func TestStoredWrappersPassTheStandardLibraryChecksums(t *testing.T) {
	data := Data(3, 70000)
	gz, err := gzip.NewReader(bytes.NewReader(GzipStored(data)))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(gz); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("gzip: %v", err)
	}
	zr, err := zlib.NewReader(bytes.NewReader(ZlibStored(data)))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(zr); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("zlib: %v", err)
	}
}

func TestGzipHeaderFieldsAreWellFormed(t *testing.T) {
	data := Data(9, 300)
	member := GzipStoredWith(GzipHeader{
		Extra: []byte("xy"), Name: []byte("n.txt"), Comment: []byte("c"), HeaderCRC: true,
	}, data)
	gz, err := gzip.NewReader(bytes.NewReader(member))
	if err != nil {
		t.Fatal(err)
	}
	if gz.Name != "n.txt" || gz.Comment != "c" || !bytes.Equal(gz.Extra, []byte("xy")) {
		t.Fatalf("header: %q %q %q", gz.Name, gz.Comment, gz.Extra)
	}
	if got, err := io.ReadAll(gz); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("body: %v", err)
	}
}

func TestDataIsDeterministicAndVaries(t *testing.T) {
	if !bytes.Equal(Data(1, 500), Data(1, 500)) {
		t.Fatal("not deterministic")
	}
	if bytes.Equal(Data(1, 500), Data(2, 500)) {
		t.Fatal("seeds give the same data")
	}
	if !bytes.Equal(Data(1, 100), Data(1, 500)[:100]) {
		t.Fatal("a shorter request must be a prefix")
	}
}

// Golden hashes pin the constructions: if an edit changes any generated
// stream, the manifest hashes would silently change with it. These fail first.
func TestGoldenHashes(t *testing.T) {
	golden := map[string]string{
		"zeros gzip m=100":  SHA256Hex(GzipZeros(100)),
		"zeros zlib m=100":  SHA256Hex(ZlibZeros(100)),
		"zeros raw m=100":   SHA256Hex(ZerosDeflate(100)),
		"stored gzip 1000":  SHA256Hex(GzipStored(Data(1, 1000))),
		"stored zlib 1000":  SHA256Hex(ZlibStored(Data(1, 1000))),
		"stored raw 1000":   SHA256Hex(StoredDeflate(Data(1, 1000))),
		"data seed 1 x 100": SHA256Hex(Data(1, 100)),
	}
	want := map[string]string{
		"zeros gzip m=100":  "b4e19a5bf632ccfdf6d885be346458f93b336502d137369843307fcb509de143",
		"zeros zlib m=100":  "7be833e5253ae2bdd6c979dc97ab88a15905b957e18021e10bd00dc58027b690",
		"zeros raw m=100":   "f99410f1ccd44385ca0a4bd2b4981c55780b489f60dbc6d31b76144ecba2935d",
		"stored gzip 1000":  "31aec15b9957111f38267cbe6e37fc77d0477ca5173f3fe8a7bdfdf9dae2e649",
		"stored zlib 1000":  "c9ef53b099ea7f4ec0f5e01853c94009ac8f075b4d99b468c7b918fe50fdc93a",
		"stored raw 1000":   "1ceaf72ab16e3d88c877ddd05b9e700b20b116b8310a43b15e9e79459157ce9e",
		"data seed 1 x 100": "32bdf0cdeaac8559e3e13674a4afa7c5d183e67fa6627d62652150274be79eb0",
	}
	for name, got := range golden {
		if got != want[name] {
			t.Errorf("%s: hash changed to %s", name, got)
		}
	}
}

func TestGenerateBuildsWhatTheSpecDescribes(t *testing.T) {
	data := Data(5, 1234)

	stream, err := Generate(Stored("gzip", 5, 1234))
	if err != nil || !bytes.Equal(stream, GzipStored(data)) {
		t.Fatalf("stored gzip: %v", err)
	}
	stream, err = Generate(Zeros("zlib", 50))
	if err != nil || !bytes.Equal(stream, ZlibZeros(50)) {
		t.Fatalf("zeros zlib: %v", err)
	}
	stream, err = Generate(Zeros("raw", 50))
	if err != nil || !bytes.Equal(stream, ZerosDeflate(50)) {
		t.Fatalf("zeros raw: %v", err)
	}

	wrapped, err := Generate(Wrap("gzip", 3, Stored("raw", 5, 1234)))
	if err != nil {
		t.Fatal(err)
	}
	want := StoredDeflate(data)
	for range 3 {
		want = GzipStored(want)
	}
	if !bytes.Equal(wrapped, want) {
		t.Fatal("wrap: output differs from three manual wrappers")
	}
}

func TestGenerateRejectsBadSpecs(t *testing.T) {
	for name, spec := range map[string]Spec{
		"unknown kind":      {Kind: "nope", Params: json.RawMessage(`{}`)},
		"unknown codec":     Zeros("lz4", 1),
		"unknown data kind": Stored("lz4", 1, 1),
		"unknown wrap":      Wrap("lz4", 1, Stored("gzip", 1, 1)),
		"bad inner":         Wrap("gzip", 1, Spec{Kind: "nope", Params: json.RawMessage(`{}`)}),
		"bad zeros params":  {Kind: "zeros", Params: json.RawMessage(`[1]`)},
		"bad data params":   {Kind: "data", Params: json.RawMessage(`"x"`)},
		"bad wrap params":   {Kind: "wrap", Params: json.RawMessage(`5`)},
	} {
		if _, err := Generate(spec); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestZerosSHA256MatchesTheDirectHash(t *testing.T) {
	for _, n := range []int64{0, 1, 1 << 20, 1<<20 + 5, 3 << 20} {
		direct := sha256.Sum256(make([]byte, n))
		if got := ZerosSHA256Hex(n); got != fmt.Sprintf("%x", direct) {
			t.Errorf("n=%d: %s != %x", n, got, direct)
		}
	}
}
