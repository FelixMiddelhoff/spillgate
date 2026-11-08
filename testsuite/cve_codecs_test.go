package testsuite

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/FelixMiddelhoff/spillgate"
	"github.com/FelixMiddelhoff/spillgate/br"
	"github.com/FelixMiddelhoff/spillgate/internal/corpus"
	"github.com/FelixMiddelhoff/spillgate/zstd"
)

// Advisory tests that need the real brotli and zstd codecs. The class-level
// versions with fake codecs are in the core module (cve_*_test.go); here the
// same mistakes are tried against the real thing.

func allCodecs(t testing.TB, limits spillgate.Limits) *spillgate.Decoder {
	t.Helper()
	d, err := spillgate.NewDecoder(limits, br.Enable(), zstd.Enable())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func kind(err error) string {
	var e *spillgate.Error
	if errors.As(err, &e) {
		return e.Kind.String()
	}
	if err == nil || err == io.EOF {
		return "ok"
	}
	return "other: " + err.Error()
}

// bomb describes a 1 GiB stream in one of the five codecs.
type bomb struct {
	name     string
	encoding string
	spec     corpus.Spec
}

func bombs() []bomb {
	return []bomb{
		{"gzip", "gzip", corpus.Zeros("gzip", 4_161_000)},
		{"zlib", "deflate", corpus.Zeros("zlib", 4_161_000)},
		{"raw deflate", "deflate", corpus.Zeros("raw", 4_161_000)},
		{"brotli", "br", corpus.ZerosOf("br", 1<<30, 24)},
		{"zstd", "zstd", corpus.ZerosOf("zstd", 1<<30, 23)},
	}
}

func stream(t testing.TB, b bomb) []byte {
	t.Helper()
	data, err := corpus.Generate(b.spec)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// CVE-2026-42587 (Netty): a limit that worked for gzip and not for br, zstd or
// snappy. Here the real decoders of all five codecs end the same way.
//
// Covers: SG-R-CDC-01 SG-R-LAY-02 SG-R-LAY-04 SG-R-API-02 SG-I-01 SG-I-02
func TestCVE_2026_42587_RealCodecsAreBoundedAlike(t *testing.T) {
	outputCap := spillgate.Limits{MaxOutput: 1 << 20, DisableRatioLimit: true}
	ratioCap := spillgate.Limits{MaxOutput: 1 << 30, MaxRatio: 100, RatioGrace: 1}

	for _, b := range bombs() {
		data := stream(t, b)

		whole, err := allCodecs(t, outputCap).ReadAll(bytes.NewReader(data), b.encoding)
		if kind(err) != "output_limit" || whole != nil {
			t.Errorf("%s: ReadAll = (%d bytes, %v), want output_limit and no data", b.name, len(whole), err)
		}

		r, err := allCodecs(t, outputCap).Reader(bytes.NewReader(data), b.encoding)
		if err != nil {
			t.Fatal(err)
		}
		delivered, err := io.Copy(io.Discard, r)
		if delivered != 1<<20 || kind(err) != "output_limit" {
			t.Errorf("%s: streamed (%d, %v), want exactly 1 MiB then output_limit", b.name, delivered, err)
		}

		if _, err := allCodecs(t, ratioCap).ReadAll(bytes.NewReader(data), b.encoding); kind(err) != "ratio_limit" {
			t.Errorf("%s under MaxRatio 100: %v", b.name, err)
		}
	}
}

// CVE-2025-58057 (Netty BrotliDecoder): the decoder kept pulling and
// accumulating output without a bound. Reading a brotli bomb byte by byte, in
// big blocks or in mixed sizes ends at the limit with memory proportional to
// the window, not to the expansion.
//
// Covers: SG-R-RDR-01 SG-R-MEM-02 SG-I-08 SG-I-09
func TestCVE_2025_58057_BrotliStreamingHasBoundedMemory(t *testing.T) {
	data := stream(t, bomb{spec: corpus.ZerosOf("br", 1<<30, 24)})
	for _, pattern := range [][]int{{1}, {4096}, {8 << 20}, {1, 7, 4096, 3, 100000}} {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)

		r, _ := allCodecs(t, spillgate.Limits{MaxOutput: 4 << 20, DisableRatioLimit: true}).Reader(bytes.NewReader(data), "br")
		buffers := make([][]byte, len(pattern)) // one buffer per size, so the test itself allocates little
		for i, size := range pattern {
			buffers[i] = make([]byte, size)
		}
		var delivered int64
		var err error
		for i := 0; err == nil; i++ {
			var n int
			n, err = r.Read(buffers[i%len(buffers)])
			delivered += int64(n)
		}
		runtime.ReadMemStats(&after)

		if delivered != 4<<20 || kind(err) != "output_limit" {
			t.Errorf("pattern %v: (%d, %v)", pattern, delivered, err)
		}
		// The 16 MiB ring buffer of the declared window, the largest test buffer (8 MiB) and slack.
		if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 16<<20+8<<20+4<<20 {
			t.Errorf("pattern %v: allocated %d bytes", pattern, allocated)
		}
	}
}

// RUSTSEC-2026-0455 (actix-http): a large-window brotli request of about 850
// bytes made the server grow by a gigabyte. The stream is refused as a memory
// request before decoding, and a normal window is still limited by the output
// limit like everything else.
//
// Covers: SG-R-CDC-04 SG-I-08
func TestRUSTSEC_2026_0455_LargeWindowBrotli(t *testing.T) {
	d := allCodecs(t, spillgate.Limits{MaxOutput: 1 << 20, DisableRatioLimit: true})
	_, err := d.ReadAll(bytes.NewReader(corpus.BrotliLargeWindowPrefix()), "br")
	if kind(err) != "memory_limit" {
		t.Fatalf("large window: %v", err)
	}
	_, err = d.ReadAll(bytes.NewReader(corpus.BrotliZeros(1<<30, 24)), "br")
	if kind(err) != "output_limit" {
		t.Fatalf("window 2^24: %v", err)
	}
}

// Avro and ulikunitz/xz (CVE-2025-58058): a header makes the decoder reserve
// memory for a window before any data is read. For zstd and brotli a frame
// that asks for more than the cap is refused with no allocation, a frame that
// asks for the cap exactly is allowed, and a frame that asks for a huge window
// but delivers a few bytes costs about the cap and no more.
//
// Covers: SG-R-CDC-04 SG-R-CDC-05 SG-I-08
func TestCVE_2025_58058_WindowFromTheHeader(t *testing.T) {
	d := allCodecs(t, spillgate.Limits{MaxOutput: 1 << 20, DisableRatioLimit: true})
	hello := corpus.ZstdRawBlocks([]byte("hello"), corpus.ZstdBlockMax, true)
	frame := func(h corpus.ZstdHeader) []byte { return append(h.Bytes(), hello...) }

	allocatedBy := func(fn func()) uint64 {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		fn()
		runtime.ReadMemStats(&after)
		return after.TotalAlloc - before.TotalAlloc
	}

	// 100 frames in a row, each asking for a window of 2^30 bytes: all refused, nothing reserved.
	refusals := bytes.Repeat(frame(corpus.ZstdHeader{WindowLog: 30}), 100)
	allocated := allocatedBy(func() {
		if _, err := d.ReadAll(bytes.NewReader(refusals), "zstd"); kind(err) != "memory_limit" {
			t.Errorf("window 2^30: %v", err)
		}
	})
	if allocated > 1<<20 {
		t.Errorf("refusing a 1 GiB window allocated %d bytes", allocated)
	}

	// 100 frames in a row, each asking for exactly the cap: allowed, and the cost is one decoder, not 100 windows.
	allowed := bytes.Repeat(frame(corpus.ZstdHeader{WindowLog: 23}), 100)
	allocated = allocatedBy(func() {
		got, err := d.ReadAll(bytes.NewReader(allowed), "zstd")
		if err != nil || len(got) != 500 {
			t.Errorf("100 frames of window 8 MiB: (%d, %v)", len(got), err)
		}
	})
	t.Logf("100 frames declaring an 8 MiB window each allocated %d bytes in total", allocated)
	if allocated > 64<<20 {
		t.Errorf("allocated %d bytes for 100 frames sharing one decoder", allocated)
	}
}

// GHSA-87m9-rv8p-rgmg (go-grpc-compression): the zstd path used the one-shot
// DecodeAll, which ignores a stream's limits. The codec modules must only ever
// use streaming reads through the limiter.
//
// Covers: SG-R-CDC-01 SG-R-API-01
func TestGHSA_87m9_rv8p_rgmg_NoOneShotDecoding(t *testing.T) {
	for _, dir := range []string{"../br", "../zstd"} {
		files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
		for _, file := range files {
			if strings.HasSuffix(file, "_test.go") {
				continue
			}
			source, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			for _, banned := range []string{"DecodeAll", "io.ReadAll", "ioutil.ReadAll", "WithDecoderConcurrency(0)", "WithDecoderConcurrency(2"} {
				if strings.Contains(string(source), banned) {
					t.Errorf("%s uses %s", file, banned)
				}
			}
		}
	}
}

// All five codecs in one chain: the layer budget, the order and the real
// decoders work together.
//
// Covers: SG-R-HDR-11 SG-R-HDR-12 SG-R-LAY-01
func TestAllCodecsInOneChain(t *testing.T) {
	data := corpus.Data(1, 3000)
	chain := corpus.GzipStored(
		corpus.ZlibStored(
			corpus.BrotliStored(
				corpus.ZstdStored(corpus.GzipStored(data), 17), 16)))
	d := allCodecs(t, spillgate.Limits{MaxOutput: 1 << 20, DisableRatioLimit: true})

	// Applied in this order: gzip, zstd, br, deflate, gzip.
	got, err := d.ReadAll(bytes.NewReader(chain), "gzip, zstd, br, deflate, gzip")
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("five layers: %v", err)
	}
	if _, err := d.ReadAll(bytes.NewReader(chain), "gzip, zstd, br, deflate, gzip, gzip"); kind(err) != "layer_limit" {
		t.Fatalf("six layers: %v", err)
	}
	if _, err := d.ReadAll(bytes.NewReader(chain), "gzip, br, zstd, deflate, gzip"); kind(err) != "corrupt" {
		t.Fatalf("wrong order: %v", err)
	}
}

// A bomb at the innermost position of a chain of different codecs is stopped
// in the layer that exceeds the budget.
//
// Covers: SG-R-LAY-01 SG-I-01
func TestBombInsideMixedChains(t *testing.T) {
	d := allCodecs(t, spillgate.Limits{MaxOutput: 1 << 20, DisableRatioLimit: true})
	for _, c := range []struct{ bomb, outer, encodings string }{
		{"br", "zlib", "br, deflate"},
		{"zstd", "gzip", "zstd, gzip"},
		{"gzip", "br", "gzip, br"},
		{"gzip", "zstd", "gzip, zstd"},
	} {
		var inner corpus.Spec
		switch c.bomb {
		case "br":
			inner = corpus.ZerosOf("br", 1<<28, 24)
		case "zstd":
			inner = corpus.ZerosOf("zstd", 1<<28, 23)
		default:
			inner = corpus.Zeros("gzip", 1<<20)
		}
		window := 16
		if c.outer == "zstd" {
			window = 17
		}
		stream, err := corpus.Generate(corpus.WrapWindow(c.outer, 1, window, inner))
		if err != nil {
			t.Fatal(err)
		}
		r, err := d.Reader(bytes.NewReader(stream), c.encodings)
		if err != nil {
			t.Fatal(err)
		}
		delivered, err := io.Copy(io.Discard, r)
		var e *spillgate.Error
		if !errors.As(err, &e) || e.Kind != spillgate.KindOutputLimit || e.Layer != 2 || delivered != 1<<20 {
			t.Errorf("%s: (%d, %v), want output_limit in layer 2 after exactly 1 MiB", c.encodings, delivered, err)
		}
	}
}
