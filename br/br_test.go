package br_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"runtime"
	"testing"

	"github.com/andybalholm/brotli"

	"github.com/FelixMiddelhoff/spillgate"
	"github.com/FelixMiddelhoff/spillgate/br"
	"github.com/FelixMiddelhoff/spillgate/internal/corpus"
)

// loose limits keep these tests about the codec.
var loose = spillgate.Limits{MaxOutput: 1 << 40, DisableRatioLimit: true}

func decoder(t testing.TB, limits spillgate.Limits, settings ...br.Setting) *spillgate.Decoder {
	t.Helper()
	d, err := spillgate.NewDecoder(limits, br.Enable(settings...))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func decodeAll(t testing.TB, stream []byte, settings ...br.Setting) ([]byte, error) {
	t.Helper()
	return decoder(t, loose, settings...).ReadAll(bytes.NewReader(stream), "br")
}

// encode compresses with the library's encoder at the given quality and window.
func encode(t testing.TB, data []byte, quality, lgwin int) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := brotli.NewWriterOptions(&buf, brotli.WriterOptions{Quality: quality, LGWin: lgwin})
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sample(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte((i*31)>>3) ^ byte(i/251)
	}
	return out
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

// The real encoder's streams decode to the original at every quality and
// window size.
func TestRoundTripWithTheRealEncoder(t *testing.T) {
	for _, size := range []int{0, 1, 100, 4096, 70000, 300000} {
		data := sample(size)
		for _, quality := range []int{0, 1, 5, 9, 11} {
			for _, lgwin := range []int{10, 16, 18, 22, 24} {
				got, err := decodeAll(t, encode(t, data, quality, lgwin))
				if err != nil || !bytes.Equal(got, data) {
					t.Fatalf("size %d quality %d lgwin %d: %v", size, quality, lgwin, err)
				}
			}
		}
	}
}

// The hand-built corpus streams are valid brotli: the library decodes them to
// exactly the zeros and the data they claim to hold.
func TestCorpusBuildersProduceValidStreams(t *testing.T) {
	for _, wbits := range []int{10, 15, 16, 17, 18, 22, 24} {
		for _, size := range []int64{2122, 2123, 4096, 25801, 1<<24 - 1, 1 << 24, 1<<24 + 1, 1<<24 + 2121, 1<<24 + 2122, 3 << 24, 3<<24 + 7} {
			got, err := decodeAll(t, corpus.BrotliZeros(size, wbits))
			if err != nil || int64(len(got)) != size || !isZero(got) {
				t.Fatalf("zeros size %d wbits %d: %d bytes, %v", size, wbits, len(got), err)
			}
		}
		for _, size := range []int{0, 1, 100, 70000} {
			data := corpus.Data(3, size)
			got, err := decodeAll(t, corpus.BrotliStored(data, wbits))
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("stored size %d wbits %d: %v", size, wbits, err)
			}
		}
	}
	empty, err := decodeAll(t, corpus.BrotliZeros(0, 16))
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty: %v", err)
	}
}

func isZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// Covers: SG-R-CDC-04
func TestWindowCap(t *testing.T) {
	small := corpus.BrotliStored([]byte("hello"), 10)
	for wbits := 10; wbits <= 24; wbits++ {
		stream := corpus.BrotliStored([]byte("hello"), wbits)

		// With the default cap every standard window is accepted.
		if got, err := decodeAll(t, stream); err != nil || string(got) != "hello" {
			t.Errorf("default cap, wbits %d: %v", wbits, err)
		}
		// With the cap at 2^20 exactly the larger windows are refused.
		got, err := decodeAll(t, stream, br.MaxWindowBits(20))
		if wbits <= 20 && (err != nil || string(got) != "hello") {
			t.Errorf("cap 20, wbits %d: %v", wbits, err)
		}
		if wbits > 20 && (kind(err) != "memory_limit" || got != nil) {
			t.Errorf("cap 20, wbits %d: (%q, %v), want memory_limit", wbits, got, err)
		}
	}
	// The smallest cap still accepts the smallest window.
	if _, err := decodeAll(t, small, br.MaxWindowBits(10)); err != nil {
		t.Errorf("cap 10: %v", err)
	}
}

// The large-window marker is reserved by RFC 7932 and not supported: it is a
// memory refusal, not data, whatever the cap.
//
// Covers: SG-R-CDC-04
func TestLargeWindowIsRefused(t *testing.T) {
	stream := corpus.BrotliLargeWindowPrefix()
	for _, settings := range [][]br.Setting{nil, {br.MaxWindowBits(24)}, {br.MaxWindowBits(10)}} {
		got, err := decodeAll(t, stream, settings...)
		if kind(err) != "memory_limit" || got != nil {
			t.Errorf("(%q, %v)", got, err)
		}
	}
}

// A stream that asks for too much is refused at its first byte: nothing is
// decoded and no memory is reserved for its window.
//
// Covers: SG-R-CDC-04 SG-I-08
func TestRefusalHappensBeforeAnyAllocation(t *testing.T) {
	stream := corpus.BrotliZeros(1<<24, 24)
	d := decoder(t, loose, br.MaxWindowBits(16))

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, err := d.ReadAll(bytes.NewReader(stream), "br")
	runtime.ReadMemStats(&after)

	if kind(err) != "memory_limit" {
		t.Fatalf("got %v", err)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 1<<20 {
		t.Fatalf("refusal allocated %d bytes", allocated)
	}
}

func TestInvalidSettingsFailInsteadOfWeakeningTheCap(t *testing.T) {
	for _, n := range []int{-1, 0, 9, 25, 30, 1000} {
		d := decoder(t, loose, br.MaxWindowBits(n))
		_, err := d.Reader(bytes.NewReader(corpus.BrotliStored([]byte("x"), 24)), "br")
		if kind(err) != "internal" {
			t.Errorf("MaxWindowBits(%d): %v", n, err)
		}
	}
}

// Covers: SG-R-CDC-06
func TestEveryTruncationIsCorrupt(t *testing.T) {
	data := sample(5000)
	for label, stream := range map[string][]byte{
		"encoded": encode(t, data, 5, 16),
		"stored":  corpus.BrotliStored(data[:300], 16),
		"zeros":   corpus.BrotliZeros(30000, 16),
	} {
		for n := range len(stream) {
			if _, err := decodeAll(t, stream[:n]); kind(err) != "corrupt" {
				t.Fatalf("%s truncated to %d of %d: %v", label, n, len(stream), err)
			}
		}
	}
}

// Covers: SG-R-CDC-04
func TestBytesAfterTheStreamAreCorrupt(t *testing.T) {
	stream := encode(t, sample(3000), 5, 16)
	for label, tail := range map[string][]byte{
		"one zero byte": {0}, "padding": make([]byte, 600), "text": []byte("garbage"),
		"a second stream": encode(t, sample(10), 5, 16),
	} {
		if _, err := decodeAll(t, append(bytes.Clone(stream), tail...)); kind(err) != "corrupt" {
			t.Errorf("%s: %v", label, err)
		}
	}
	// Also behind a stream that is far longer than the decoder's 32 KiB read buffer.
	big := encode(t, sample(200000), 1, 16)
	if _, err := decodeAll(t, append(bytes.Clone(big), 0)); kind(err) != "corrupt" {
		t.Errorf("trailing byte after a long stream: %v", err)
	}
}

// Brotli has no checksum, so a flipped bit may change the data. The only
// requirement is a clean result and no panic.
//
// Covers: SG-I-05
func TestEverySingleBitFlipIsHandled(t *testing.T) {
	good := encode(t, sample(400), 5, 12)
	for bit := range len(good) * 8 {
		stream := bytes.Clone(good)
		stream[bit/8] ^= 1 << (bit % 8)
		if _, err := decodeAll(t, stream); err != nil && kind(err) != "corrupt" && kind(err) != "memory_limit" {
			t.Fatalf("bit %d: %v", bit, err)
		}
	}
}

func TestEmptyAndForeignInput(t *testing.T) {
	for _, stream := range [][]byte{nil, {}, []byte("not brotli at all, just text"), bytes.Repeat([]byte{0xff}, 100)} {
		if _, err := decodeAll(t, stream); err == nil {
			t.Errorf("%q accepted", stream)
		}
	}
	if _, err := decodeAll(t, nil); kind(err) != "corrupt" {
		t.Errorf("empty input: %v", err)
	}
}

// A bomb of 1 GiB in under a kilobyte (ratio above 1,000,000:1) is stopped by
// the output limit, by the ratio limit, and identically for all read sizes.
//
// Covers: SG-R-CDC-01 SG-R-LAY-02 SG-R-RAT-01 SG-I-01
func TestBombs(t *testing.T) {
	stream := corpus.BrotliZeros(1<<30, 24)
	t.Logf("1 GiB of zeros in %d bytes", len(stream))

	limits := spillgate.Limits{MaxOutput: 1 << 20, DisableRatioLimit: true}
	for _, pattern := range [][]int{{1}, {4096}, {1 << 20}, {1, 7, 4096, 1}} {
		r, err := decoder(t, limits).Reader(bytes.NewReader(stream), "br")
		if err != nil {
			t.Fatal(err)
		}
		var delivered int64
		var endErr error
		for i := 0; endErr == nil; i++ {
			var n int
			n, endErr = r.Read(make([]byte, pattern[i%len(pattern)]))
			delivered += int64(n)
		}
		if delivered != 1<<20 || kind(endErr) != "output_limit" {
			t.Errorf("pattern %v: (%d, %v)", pattern, delivered, endErr)
		}
	}

	// With the default ratio the same bomb is a ratio error long before the output limit.
	_, err := decoder(t, spillgate.Limits{MaxOutput: 1 << 30}).ReadAll(bytes.NewReader(stream), "br")
	if kind(err) != "ratio_limit" {
		t.Errorf("default limits: %v", err)
	}

	// A bomb that exactly fits and one that is a byte over.
	fits := corpus.BrotliZeros(25801, 16)
	if _, err := decoder(t, spillgate.Limits{MaxOutput: 25801, DisableRatioLimit: true}).ReadAll(bytes.NewReader(fits), "br"); err != nil {
		t.Errorf("exact fit: %v", err)
	}
	if _, err := decoder(t, spillgate.Limits{MaxOutput: 25800, DisableRatioLimit: true}).ReadAll(bytes.NewReader(fits), "br"); kind(err) != "output_limit" {
		t.Errorf("one byte over: %v", err)
	}
}

// Decoding a bomb up to a small limit costs the window of the stream and a
// fixed buffer, not the size of the expansion.
//
// Covers: SG-R-MEM-02 SG-R-MEM-03 SG-I-08
func TestMemoryDoesNotGrowWithTheOutput(t *testing.T) {
	for _, wbits := range []int{10, 16, 22, 24} {
		stream := corpus.BrotliZeros(1<<30, wbits)
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		r, _ := decoder(t, spillgate.Limits{MaxOutput: 8 << 20, DisableRatioLimit: true}).Reader(bytes.NewReader(stream), "br")
		buf := make([]byte, 32<<10)
		for {
			if _, err := r.Read(buf); err != nil {
				break
			}
		}
		runtime.ReadMemStats(&after)
		allocated := after.TotalAlloc - before.TotalAlloc
		window := uint64(1)<<wbits - 16
		t.Logf("wbits %d: window %d bytes, allocated %d bytes", wbits, window, allocated)
		if allocated > 2*window+(1<<20) {
			t.Errorf("wbits %d: allocated %d bytes for a window of %d", wbits, allocated, window)
		}
	}
}

// Covers: SG-R-RDR-06 SG-I-10
func TestCloseIsHarmlessAndLeavesNoGoroutines(t *testing.T) {
	stream := encode(t, sample(5000), 5, 16)
	d := decoder(t, loose)
	before := runtime.NumGoroutine()
	for range 500 {
		r, err := d.Reader(bytes.NewReader(stream), "br")
		if err != nil {
			t.Fatal(err)
		}
		r.Read(make([]byte, 10))
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
		r.Close()
	}
	if after := runtime.NumGoroutine(); after > before+2 {
		t.Fatalf("goroutines grew from %d to %d", before, after)
	}
}

// The codec behaves inside a chain, in either position.
func TestInsideAChain(t *testing.T) {
	data := sample(4000)
	d, err := spillgate.NewDecoder(loose, br.Enable())
	if err != nil {
		t.Fatal(err)
	}
	// Applied br first, then gzip: header "br, gzip".
	stream := corpus.GzipStored(encode(t, data, 5, 16))
	got, err := d.ReadAll(bytes.NewReader(stream), "br, gzip")
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("br then gzip: %v", err)
	}
	// Applied gzip first, then br.
	stream = encode(t, corpus.GzipStored(data), 5, 16)
	got, err = d.ReadAll(bytes.NewReader(stream), "gzip, br")
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("gzip then br: %v", err)
	}
}

// Without Enable the encoding is unsupported and the source is not touched.
func TestBrIsUnsupportedUntilEnabled(t *testing.T) {
	d, _ := spillgate.NewDecoder(loose)
	if _, err := d.Reader(forbidden{t}, "br"); kind(err) != "unsupported_encoding" {
		t.Fatalf("got %v", err)
	}
}

type forbidden struct{ t testing.TB }

func (f forbidden) Read([]byte) (int, error) {
	f.t.Error("the source was read")
	return 0, io.EOF
}

// FuzzDecode feeds arbitrary bytes and limits through the brotli codec: no
// panic, at most `limit` bytes, and only the expected outcome classes.
func FuzzDecode(f *testing.F) {
	f.Add([]byte{}, uint16(100))
	f.Add(encode(f, sample(500), 5, 16), uint16(300))
	f.Add(corpus.BrotliZeros(30000, 16), uint16(1000))
	f.Add(corpus.BrotliLargeWindowPrefix(), uint16(10))
	f.Add(append(encode(f, sample(50), 5, 16), 0), uint16(10))

	f.Fuzz(func(t *testing.T, stream []byte, limit uint16) {
		if limit == 0 {
			t.Skip()
		}
		d := decoder(t, spillgate.Limits{MaxOutput: int64(limit)})
		r, err := d.Reader(bytes.NewReader(stream), "br")
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		var delivered int64
		buf := make([]byte, 777)
		for {
			n, err := r.Read(buf)
			delivered += int64(n)
			if err == nil {
				continue
			}
			if err != io.EOF {
				switch kind(err) {
				case "output_limit", "ratio_limit", "corrupt", "memory_limit":
				default:
					t.Fatalf("unexpected outcome: %v", err)
				}
			}
			break
		}
		if delivered > int64(limit) {
			t.Fatalf("delivered %d > limit %d", delivered, limit)
		}
	})
}

var _ = fmt.Sprintf
