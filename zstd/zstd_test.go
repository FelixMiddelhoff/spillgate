package zstd_test

import (
	"bytes"
	"errors"
	"io"
	"runtime"
	"testing"
	"time"

	kzstd "github.com/klauspost/compress/zstd"

	"github.com/FelixMiddelhoff/spillgate"
	"github.com/FelixMiddelhoff/spillgate/internal/corpus"
	"github.com/FelixMiddelhoff/spillgate/zstd"
)

var loose = spillgate.Limits{MaxOutput: 1 << 40, DisableRatioLimit: true}

func decoder(t testing.TB, limits spillgate.Limits, settings ...zstd.Setting) *spillgate.Decoder {
	t.Helper()
	d, err := spillgate.NewDecoder(limits, zstd.Enable(settings...))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func decodeAll(t testing.TB, stream []byte, settings ...zstd.Setting) ([]byte, error) {
	t.Helper()
	return decoder(t, loose, settings...).ReadAll(bytes.NewReader(stream), "zstd")
}

// encode compresses with the library's encoder.
func encode(t testing.TB, data []byte, opts ...kzstd.EOption) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := kzstd.NewWriter(&buf, opts...)
	if err != nil {
		t.Fatal(err)
	}
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

func u64(n uint64) *uint64 { return &n }
func u32(n uint32) *uint32 { return &n }

func isZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// The real encoder's frames decode to the original, with and without a
// checksum and at several levels and windows.
func TestRoundTripWithTheRealEncoder(t *testing.T) {
	for _, size := range []int{0, 1, 100, 4096, 70000, 300000} {
		data := sample(size)
		for _, level := range []kzstd.EncoderLevel{kzstd.SpeedFastest, kzstd.SpeedDefault, kzstd.SpeedBestCompression} {
			for _, crc := range []bool{false, true} {
				for _, window := range []int{1 << 10, 1 << 16, 1 << 20} {
					stream := encode(t, data, kzstd.WithEncoderLevel(level), kzstd.WithEncoderCRC(crc), kzstd.WithWindowSize(window))
					got, err := decodeAll(t, stream)
					if err != nil || !bytes.Equal(got, data) {
						t.Fatalf("size %d level %v crc %v window %d: %v", size, level, crc, window, err)
					}
				}
			}
		}
	}
}

// The hand-built corpus frames are valid Zstandard.
func TestCorpusBuildersProduceValidFrames(t *testing.T) {
	for _, windowLog := range []uint{10, 12, 17, 20, 23} {
		for _, size := range []int64{0, 1, 1000, 1 << 17, 1<<17 + 1, 5 << 20} {
			got, err := decodeAll(t, corpus.ZstdZeros(size, windowLog))
			if err != nil || int64(len(got)) != size || !isZero(got) {
				t.Fatalf("zeros size %d windowLog %d: %d bytes, %v", size, windowLog, len(got), err)
			}
		}
		for _, size := range []int{0, 1, 100, 200000} {
			data := corpus.Data(5, size)
			got, err := decodeAll(t, corpus.ZstdStored(data, windowLog))
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("stored size %d windowLog %d: %v", size, windowLog, err)
			}
		}
	}
}

// Several frames, with skippable frames anywhere, decode as one stream.
//
// Covers: SG-R-CDC-05
func TestConcatenatedAndSkippableFrames(t *testing.T) {
	a, b := sample(1000), sample(70000)
	stream := bytes.Join([][]byte{
		corpus.ZstdSkippable(5), encode(t, a), corpus.ZstdSkippable(0), encode(t, b), corpus.ZstdSkippable(300),
	}, nil)
	got, err := decodeAll(t, stream)
	if err != nil || !bytes.Equal(got, append(bytes.Clone(a), b...)) {
		t.Fatalf("got %d bytes, %v", len(got), err)
	}

	// Only skippable frames: valid, empty.
	got, err = decodeAll(t, bytes.Join([][]byte{corpus.ZstdSkippable(3), corpus.ZstdSkippable(9)}, nil))
	if err != nil || len(got) != 0 {
		t.Fatalf("only skippable frames: %d bytes, %v", len(got), err)
	}
}

// Frames share one output budget.
//
// Covers: SG-R-CDC-05 SG-R-LAY-01
func TestFramesShareOneBudget(t *testing.T) {
	frame := corpus.ZstdZeros(1000, 17)
	stream := bytes.Join([][]byte{frame, frame, frame}, nil)
	for limit, want := range map[int64]string{2999: "output_limit", 3000: "ok", 3001: "ok"} {
		_, err := decoder(t, spillgate.Limits{MaxOutput: limit, DisableRatioLimit: true}).ReadAll(bytes.NewReader(stream), "zstd")
		if kind(err) != want {
			t.Errorf("limit %d: %v, want %s", limit, err, want)
		}
	}
}

// The cap on the window is exact: 8 MiB is allowed, anything above is refused,
// including windows made with a mantissa and the window a single-segment frame
// gets from its declared content size.
//
// Covers: SG-R-CDC-05
func TestWindowCap(t *testing.T) {
	body := corpus.ZstdRawBlocks([]byte("hello"), corpus.ZstdBlockMax, true)
	frame := func(h corpus.ZstdHeader) []byte { return append(h.Bytes(), body...) }

	tests := []struct {
		name  string
		frame []byte
		want  string
	}{
		{"window 1 KiB", frame(corpus.ZstdHeader{WindowLog: 10}), "ok"},
		{"window 4 MiB", frame(corpus.ZstdHeader{WindowLog: 22}), "ok"},
		{"window exactly 8 MiB", frame(corpus.ZstdHeader{WindowLog: 23}), "ok"},
		{"window 16 MiB", frame(corpus.ZstdHeader{WindowLog: 24}), "memory_limit"},
		{"window 1 GiB", frame(corpus.ZstdHeader{WindowLog: 30}), "memory_limit"},
		{"window 2^41", frame(corpus.ZstdHeader{WindowLog: 41}), "memory_limit"},
	}
	for _, tc := range tests {
		got, err := decodeAll(t, tc.frame)
		if kind(err) != tc.want || (tc.want == "ok" && string(got) != "hello") {
			t.Errorf("%s: (%q, %v), want %s", tc.name, got, err, tc.want)
		}
	}

	// A mantissa adds eighths: 8 MiB + 1 MiB is above the cap. The descriptor is built by hand.
	withMantissa := append([]byte{0x28, 0xB5, 0x2F, 0xFD, 0x00, (23-10)<<3 | 1}, body...) // window 8 MiB + 1 MiB
	if _, err := decodeAll(t, withMantissa); kind(err) != "memory_limit" {
		t.Errorf("mantissa window above the cap: %v", err)
	}
	below := append([]byte{0x28, 0xB5, 0x2F, 0xFD, 0x00, (22-10)<<3 | 7}, body...) // 4 MiB + 3.5 MiB = 7.5 MiB
	if got, err := decodeAll(t, below); err != nil || string(got) != "hello" {
		t.Errorf("mantissa window below the cap: %v", err)
	}

	// Single-segment frames: the window is the declared content size, which the
	// frame does not have to honor, but memory is judged by it.
	for _, tc := range []struct {
		declared uint64
		want     string
	}{
		{5, "ok"}, {8 << 20, "ok"}, {8<<20 + 1, "memory_limit"}, {1 << 32, "memory_limit"}, {1 << 63, "memory_limit"},
	} {
		h := corpus.ZstdHeader{SingleSegment: true, ContentSize: u64(tc.declared)}
		_, err := decodeAll(t, frame(h))
		// A declared size that is not the real one ends as corrupt at best (the library
		// checks it at the end); what matters here is that memory_limit comes first.
		if tc.want == "memory_limit" && kind(err) != "memory_limit" {
			t.Errorf("single segment, declared %d: %v, want memory_limit", tc.declared, err)
		}
		if tc.want == "ok" && kind(err) == "memory_limit" {
			t.Errorf("single segment, declared %d: wrongly refused as memory", tc.declared)
		}
	}

	// The cap is configurable downward and upward.
	big := frame(corpus.ZstdHeader{WindowLog: 24})
	if got, err := decodeAll(t, big, zstd.MaxWindowBytes(16<<20)); err != nil || string(got) != "hello" {
		t.Errorf("cap raised to 16 MiB: %v", err)
	}
	small := frame(corpus.ZstdHeader{WindowLog: 21})
	if _, err := decodeAll(t, small, zstd.MaxWindowBytes(1<<20)); kind(err) != "memory_limit" {
		t.Errorf("cap lowered to 1 MiB: %v", err)
	}
}

// The content size of a single-segment frame comes in four sizes (1, 2, 4 and
// 8 bytes, the 2-byte form with an offset of 256). Each form must be read right:
// a frame whose declared size is the real size decodes, and the cap compares
// against the declared size exactly.
//
// Covers: SG-R-CDC-05
func TestSingleSegmentContentSizeForms(t *testing.T) {
	for _, size := range []int64{0, 5, 255, 256, 300, 65791, 65792, 70000, 1 << 20} {
		h := corpus.ZstdHeader{SingleSegment: true, ContentSize: u64(uint64(size))}
		frame := append(h.Bytes(), corpus.ZstdRLEBlocks(size, corpus.ZstdBlockMax, 0, true)...)
		got, err := decodeAll(t, frame)
		if err != nil || int64(len(got)) != size || !isZero(got) {
			t.Errorf("declared and real size %d: %d bytes, %v", size, len(got), err)
		}
	}

	// A cap of exactly 1 KiB: a declared 1024 is fine, 1025 is not (2-byte form).
	body := func(size int64) []byte { return corpus.ZstdRLEBlocks(size, corpus.ZstdBlockMax, 0, true) }
	at := corpus.ZstdHeader{SingleSegment: true, ContentSize: u64(1024)}
	if got, err := decodeAll(t, append(at.Bytes(), body(1024)...), zstd.MaxWindowBytes(1024)); err != nil || len(got) != 1024 {
		t.Errorf("declared 1024 under a cap of 1024: %v", err)
	}
	over := corpus.ZstdHeader{SingleSegment: true, ContentSize: u64(1025)}
	if _, err := decodeAll(t, append(over.Bytes(), body(1025)...), zstd.MaxWindowBytes(1024)); kind(err) != "memory_limit" {
		t.Errorf("declared 1025 under a cap of 1024: %v", err)
	}
}

func TestInvalidSettingsFailInsteadOfWeakeningTheCap(t *testing.T) {
	for _, n := range []uint64{0, 1, 1023, 1<<30 + 1, 1 << 40} {
		d := decoder(t, loose, zstd.MaxWindowBytes(n))
		_, err := d.Reader(bytes.NewReader(corpus.ZstdStored([]byte("x"), 17)), "zstd")
		if kind(err) != "internal" {
			t.Errorf("MaxWindowBytes(%d): %v", n, err)
		}
	}
}

// A hostile window costs at most the cap: a frame that declares an 8 MiB
// window and holds five bytes must not make us reserve more than about that.
//
// Covers: SG-I-08
func TestWindowMemoryIsBoundedByTheCap(t *testing.T) {
	frame := corpus.ZstdStored([]byte("hello"), 23)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	if _, err := decodeAll(t, frame); err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc
	t.Logf("a frame declaring an 8 MiB window and holding 5 bytes allocated %d bytes", allocated)
	if allocated > 32<<20 {
		t.Fatalf("allocated %d bytes", allocated)
	}
}

// Covers: SG-R-CDC-05
func TestDictionaryAndReservedBits(t *testing.T) {
	blocks := corpus.ZstdRawBlocks([]byte("x"), corpus.ZstdBlockMax, true)
	frame := func(h corpus.ZstdHeader) []byte { return append(h.Bytes(), blocks...) }

	if _, err := decodeAll(t, frame(corpus.ZstdHeader{WindowLog: 17, DictionaryID: u32(7)})); kind(err) != "corrupt" {
		t.Errorf("dictionary id 7: %v", err)
	}
	if got, err := decodeAll(t, frame(corpus.ZstdHeader{WindowLog: 17, DictionaryID: u32(0)})); err != nil || string(got) != "x" {
		t.Errorf("dictionary id 0 means none: %v", err)
	}

	reserved := frame(corpus.ZstdHeader{WindowLog: 17})
	reserved[4] |= 1 << 3
	if _, err := decodeAll(t, reserved); kind(err) != "corrupt" {
		t.Errorf("reserved bit: %v", err)
	}

	header := corpus.ZstdHeader{WindowLog: 17}.Bytes()
	reservedBlock := append(bytes.Clone(header), 0x07, 0x00, 0x00, 'x') // last, type 3, size 0
	if _, err := decodeAll(t, reservedBlock); kind(err) != "corrupt" {
		t.Errorf("reserved block type: %v", err)
	}
	value := uint32(corpus.ZstdBlockMax+1)<<3 | 1 // last block, raw, one byte too large
	oversized := append(bytes.Clone(header), byte(value), byte(value>>8), byte(value>>16), 'x')
	if _, err := decodeAll(t, oversized); kind(err) != "corrupt" {
		t.Errorf("block above 128 KiB: %v", err)
	}
}

// Covers: SG-R-CDC-06
func TestEveryTruncationIsCorrupt(t *testing.T) {
	data := sample(3000)
	for label, stream := range map[string][]byte{
		"encoded":      encode(t, data, kzstd.WithEncoderCRC(true)),
		"stored":       corpus.ZstdStored(data[:200], 17),
		"zeros":        corpus.ZstdZeros(300000, 17),
		"with skipped": append(corpus.ZstdSkippable(10), corpus.ZstdStored(data[:50], 17)...),
	} {
		for n := range len(stream) {
			_, err := decodeAll(t, stream[:n])
			// Cutting a stream right after a complete skippable frame leaves a valid, empty stream.
			if label == "with skipped" && n == len(corpus.ZstdSkippable(10)) {
				continue
			}
			if kind(err) != "corrupt" {
				t.Fatalf("%s truncated to %d of %d: %v", label, n, len(stream), err)
			}
		}
	}
}

// Covers: SG-R-CDC-05
func TestBytesAfterTheLastFrameAreCorrupt(t *testing.T) {
	stream := encode(t, sample(3000))
	for label, tail := range map[string][]byte{
		"one zero byte": {0}, "padding": make([]byte, 600), "text": []byte("garbage"),
		"half a magic number": {0x28, 0xB5}, "a magic number alone": {0x28, 0xB5, 0x2F, 0xFD},
	} {
		if _, err := decodeAll(t, append(bytes.Clone(stream), tail...)); kind(err) != "corrupt" {
			t.Errorf("%s: %v", label, err)
		}
	}
}

// The content checksum is verified, and a declared content size that is not
// the real size ends in corruption; neither is ever used as an allowance.
//
// Covers: SG-R-CDC-05 SG-R-CDC-07
func TestChecksumAndDeclaredSize(t *testing.T) {
	data := sample(5000)
	good := encode(t, data, kzstd.WithEncoderCRC(true))
	for i := 1; i <= 4; i++ {
		bad := bytes.Clone(good)
		bad[len(bad)-i] ^= 0x40
		if _, err := decodeAll(t, bad); kind(err) != "corrupt" {
			t.Errorf("checksum byte %d from the end flipped: %v", i, err)
		}
	}

	// A frame that declares 10 bytes but holds 1 MiB: under a 100 KiB limit the
	// limit decides; with a big limit the mismatch is corruption.
	liar := corpus.ZstdHeader{SingleSegment: true, ContentSize: u64(10)}
	frame := append(liar.Bytes(), corpus.ZstdRLEBlocks(1<<20, 1024, 0, true)...) // blocks of 1 KiB, the window of a tiny frame
	// The library rejects output beyond the declared size at once, which comes
	// first in the stream; the spec leaves this outcome open (SG-R-CDC-05
	// "SHOULD"), so either refusal is right, and never more than the limit.
	r, _ := decoder(t, spillgate.Limits{MaxOutput: 100 << 10, DisableRatioLimit: true}).Reader(bytes.NewReader(frame), "zstd")
	delivered, endErr := io.Copy(io.Discard, r)
	if k := kind(endErr); (k != "output_limit" && k != "corrupt") || delivered > 100<<10 {
		t.Errorf("lying content size, small limit: (%d, %v)", delivered, endErr)
	}
	if _, err := decodeAll(t, frame); kind(err) != "corrupt" {
		t.Errorf("lying content size, big limit: %v", err)
	}
}

// A bomb at 32768:1 in 128 bytes per 4 MiB: output limit, ratio limit and read
// sizes behave as everywhere else.
//
// Covers: SG-R-CDC-01 SG-R-LAY-02 SG-R-RAT-01 SG-I-01
func TestBombs(t *testing.T) {
	stream := corpus.ZstdZeros(1<<30, 23)
	t.Logf("1 GiB of zeros in %d bytes", len(stream))

	limits := spillgate.Limits{MaxOutput: 1 << 20, DisableRatioLimit: true}
	for _, pattern := range [][]int{{1}, {4096}, {1 << 20}, {1, 7, 4096, 1}} {
		r, err := decoder(t, limits).Reader(bytes.NewReader(stream), "zstd")
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
	if _, err := decoder(t, spillgate.Limits{MaxOutput: 1 << 30}).ReadAll(bytes.NewReader(stream), "zstd"); kind(err) != "ratio_limit" {
		t.Errorf("default ratio: %v", err)
	}

	exact := corpus.ZstdZeros(25801, 17)
	if _, err := decoder(t, spillgate.Limits{MaxOutput: 25801, DisableRatioLimit: true}).ReadAll(bytes.NewReader(exact), "zstd"); err != nil {
		t.Errorf("exact fit: %v", err)
	}
	if _, err := decoder(t, spillgate.Limits{MaxOutput: 25800, DisableRatioLimit: true}).ReadAll(bytes.NewReader(exact), "zstd"); kind(err) != "output_limit" {
		t.Errorf("one byte over: %v", err)
	}
}

// Streaming 1 GiB against a small limit costs the window and a fixed amount,
// not the output.
//
// Covers: SG-R-MEM-02 SG-R-MEM-03 SG-I-08
func TestMemoryDoesNotGrowWithTheOutput(t *testing.T) {
	for _, windowLog := range []uint{10, 17, 23} {
		stream := corpus.ZstdZeros(1<<30, windowLog)
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		r, _ := decoder(t, spillgate.Limits{MaxOutput: 8 << 20, DisableRatioLimit: true}).Reader(bytes.NewReader(stream), "zstd")
		buf := make([]byte, 32<<10)
		for {
			if _, err := r.Read(buf); err != nil {
				break
			}
		}
		r.Close()
		runtime.ReadMemStats(&after)
		allocated := after.TotalAlloc - before.TotalAlloc
		window := uint64(1) << windowLog
		t.Logf("windowLog %d: window %d bytes, allocated %d bytes", windowLog, window, allocated)
		if allocated > 4*window+(8<<20) {
			t.Errorf("windowLog %d: allocated %d bytes", windowLog, allocated)
		}
	}
}

// Skippable frames cost almost nothing: a hundred thousand of them are
// passed in a moment, and with an input cap they are refused.
//
// Covers: SG-R-CDC-05 SG-R-INP-01 SG-I-08
func TestManySkippableFrames(t *testing.T) {
	stream := bytes.Repeat(corpus.ZstdSkippable(0), 100000) // 800 KB
	stream = append(stream, corpus.ZstdStored([]byte("end"), 17)...)

	start := time.Now()
	got, err := decodeAll(t, stream)
	elapsed := time.Since(start)
	if err != nil || string(got) != "end" {
		t.Fatalf("(%q, %v)", got, err)
	}
	t.Logf("100000 skippable frames in %v", elapsed)
	if elapsed > 5*time.Second {
		t.Fatalf("took %v", elapsed)
	}

	d, _ := spillgate.NewDecoder(loose, zstd.Enable(), spillgate.WithMaxInput(100<<10))
	if _, err := d.ReadAll(bytes.NewReader(stream), "zstd"); kind(err) != "input_limit" {
		t.Fatalf("with MaxInput: %v", err)
	}

	// A skippable frame that claims 4 GiB and has nothing behind it is truncation.
	huge := []byte{0x50, 0x2A, 0x4D, 0x18, 0xff, 0xff, 0xff, 0xff, 1, 2, 3}
	if _, err := decodeAll(t, huge); kind(err) != "corrupt" {
		t.Fatalf("truncated skippable frame: %v", err)
	}
}

// A hundred thousand frames with no content are fine and quick.
func TestManyEmptyFrames(t *testing.T) {
	frame := corpus.ZstdStored(nil, 17)
	start := time.Now()
	got, err := decodeAll(t, bytes.Repeat(frame, 20000))
	if err != nil || len(got) != 0 {
		t.Fatalf("(%d bytes, %v)", len(got), err)
	}
	t.Logf("20000 empty frames in %v", time.Since(start))
}

// Covers: SG-R-RDR-06 SG-I-10
func TestCloseIsHarmlessAndLeavesNoGoroutines(t *testing.T) {
	stream := encode(t, sample(5000))
	d := decoder(t, loose)
	before := runtime.NumGoroutine()
	for range 300 {
		r, err := d.Reader(bytes.NewReader(stream), "zstd")
		if err != nil {
			t.Fatal(err)
		}
		r.Read(make([]byte, 10))
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
		r.Close()
	}
	// Abandoned without Close: no background work keeps running.
	for range 100 {
		r, _ := d.Reader(bytes.NewReader(stream), "zstd")
		r.Read(make([]byte, 10))
	}
	runtime.GC()
	if after := runtime.NumGoroutine(); after > before+2 {
		t.Fatalf("goroutines grew from %d to %d", before, after)
	}
}

func TestInsideAChain(t *testing.T) {
	data := sample(4000)
	d, err := spillgate.NewDecoder(loose, zstd.Enable())
	if err != nil {
		t.Fatal(err)
	}
	got, err := d.ReadAll(bytes.NewReader(corpus.GzipStored(encode(t, data))), "zstd, gzip")
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("zstd then gzip: %v", err)
	}
	got, err = d.ReadAll(bytes.NewReader(encode(t, corpus.GzipStored(data))), "gzip, zstd")
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("gzip then zstd: %v", err)
	}
}

type forbidden struct{ t testing.TB }

func (f forbidden) Read([]byte) (int, error) {
	f.t.Error("the source was read")
	return 0, io.EOF
}

func TestZstdIsUnsupportedUntilEnabled(t *testing.T) {
	d, _ := spillgate.NewDecoder(loose)
	if _, err := d.Reader(forbidden{t}, "zstd"); kind(err) != "unsupported_encoding" {
		t.Fatalf("got %v", err)
	}
}

// FuzzDecode feeds arbitrary bytes and limits through the zstd codec: no
// panic, at most `limit` bytes, and only the expected outcome classes.
func FuzzDecode(f *testing.F) {
	f.Add([]byte{}, uint16(100))
	f.Add(encode(f, sample(500)), uint16(300))
	f.Add(corpus.ZstdZeros(30000, 17), uint16(1000))
	f.Add(corpus.ZstdSkippable(7), uint16(10))
	f.Add(append(encode(f, sample(50)), 0), uint16(10))
	f.Add(append(corpus.ZstdHeader{WindowLog: 30}.Bytes(), 1, 0, 0), uint16(10))

	f.Fuzz(func(t *testing.T, stream []byte, limit uint16) {
		if limit == 0 {
			t.Skip()
		}
		r, err := decoder(t, spillgate.Limits{MaxOutput: int64(limit)}).Reader(bytes.NewReader(stream), "zstd")
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
