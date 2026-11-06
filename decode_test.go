package spillgate

import (
	"bytes"
	"errors"
	"io"
	"math/rand"
	"strings"
	"sync"
	"testing"
)

// untouchedSource returns a source that fails the test when read.
func untouchedSource(t *testing.T) io.Reader {
	t.Helper()
	return forbiddenSource{onRead: func() { t.Error("the source was read, but it must stay untouched") }}
}

// Covers: SG-R-LIM-01 SG-R-LIM-08 SG-R-API-03
func TestNewDecoderRejectsInvalidLimitsBeforeAnyRead(t *testing.T) {
	for _, limits := range []Limits{{}, {MaxOutput: -5}, {MaxOutput: 1, MaxLayers: 99}} {
		if _, err := Decode(untouchedSource(t), []string{"gzip"}, limits); !errors.Is(err, ErrInvalidLimits) {
			t.Errorf("limits %+v: %v", limits, err)
		}
	}
}

// Header problems are reported at construction and the source is never read.
// Covers: SG-R-HDR-09 SG-R-API-03 SG-I-06
func TestHeaderErrorsSurfaceBeforeAnyRead(t *testing.T) {
	limits := Limits{MaxOutput: 100}
	tests := []struct {
		name     string
		encoding []string
		want     error
	}{
		{"malformed", []string{"gzip;q=1"}, ErrMalformedEncoding},
		{"unsupported", []string{"gzip, snappy"}, ErrUnsupportedEncoding},
		{"unsupported optional codec", []string{"br"}, ErrUnsupportedEncoding},
		{"six layers", []string{"gzip,gzip,gzip,gzip,gzip,gzip"}, ErrLayerLimit},
		{"seventeen elements", []string{strings.Repeat("identity,", 16) + "identity"}, ErrLayerLimit},
		{"too long", []string{strings.Repeat(" ", 2000) + "gzip"}, ErrMalformedEncoding},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := Decode(untouchedSource(t), tc.encoding, limits)
			if !errors.Is(err, tc.want) || r != nil {
				t.Fatalf("got (%v, %v), want %v", r, err, tc.want)
			}
		})
	}
}

func TestDecodeRejectsANilSource(t *testing.T) {
	if _, err := Decode(nil, nil, Limits{MaxOutput: 1}); !errors.Is(err, ErrNilSource) {
		t.Fatalf("got %v", err)
	}
}

// An empty or identity-only chain still bounds the body (SG-R-CDC-10).
// Covers: SG-R-CDC-10 SG-R-LAY-03 SG-I-01
func TestIdentityChainIsBounded(t *testing.T) {
	body := sampleData(1000)
	for _, encodings := range [][]string{nil, {}, {""}, {"identity"}, {"identity, identity"}} {
		got, err := DecodeAll(bytes.NewReader(body), encodings, Limits{MaxOutput: 1000, DisableRatioLimit: true})
		if err != nil || !bytes.Equal(got, body) {
			t.Fatalf("%q at the limit: %v", encodings, err)
		}
		if _, err := DecodeAll(bytes.NewReader(body), encodings, Limits{MaxOutput: 999, DisableRatioLimit: true}); !errors.Is(err, ErrOutputLimit) {
			t.Fatalf("%q one byte over: %v", encodings, err)
		}
	}
}

// Covers: SG-R-HDR-03 SG-R-HDR-12
func TestChainDecodesInReverseHeaderOrder(t *testing.T) {
	data := sampleData(3000)
	// The sender applied gzip first and deflate second; the header says so.
	stream := zlibBytes(t, gzipBytes(t, data))
	got, err := DecodeAll(bytes.NewReader(stream), []string{"gzip", "deflate"}, loose)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("got %v", err)
	}
	// Presented the other way round, the first layer is gzip but the bytes are zlib.
	if _, err := DecodeAll(bytes.NewReader(stream), []string{"deflate", "gzip"}, loose); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("wrong order: %v", err)
	}
}

// Covers: SG-R-HDR-07 SG-R-HDR-14
func TestXGzipAliasAndHeaderPresentationsDecodeTheSame(t *testing.T) {
	data := sampleData(500)
	stream := gzipBytes(t, data)
	for _, enc := range [][]string{{"gzip"}, {"x-gzip"}, {"GZIP"}, {" gzip , "}, {"identity", "gzip"}, {"", "gzip", ","}} {
		got, err := DecodeAll(bytes.NewReader(stream), enc, loose)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("%q: %v", enc, err)
		}
	}
}

// Five nested layers work; every layer unwraps correctly.
// Covers: SG-R-HDR-11
func TestMaxDepthChainDecodes(t *testing.T) {
	data := sampleData(2000)
	stream, encodings := data, []string{}
	for range DefaultMaxLayers {
		stream = gzipBytes(t, stream)
		encodings = append(encodings, "gzip")
	}
	got, err := DecodeAll(bytes.NewReader(stream), encodings, loose)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("five layers: %v", err)
	}
}

// Each layer has its own budget: an inner layer that exceeds MaxOutput is
// refused even though the final result would fit.
// Covers: SG-R-LAY-01
func TestIntermediateLayersAreBounded(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	data := make([]byte, 1000)
	rng.Read(data) // incompressible, so the inner gzip stream is longer than the data

	stream := gzipBytes(t, gzipBytes(t, data))
	limits := Limits{MaxOutput: 1005, DisableRatioLimit: true}

	_, err := DecodeAll(bytes.NewReader(stream), []string{"gzip", "gzip"}, limits)
	var e *Error
	if !errors.As(err, &e) || e.Kind != KindOutputLimit || e.Layer != 1 {
		t.Fatalf("got %v, want output limit in layer 1", err)
	}
}

// Covers: SG-R-CDC-01 SG-I-01
func TestAnExtensionCodecWithoutAnyLimitIsStillBounded(t *testing.T) {
	d, err := NewDecoder(Limits{MaxOutput: 10000, DisableRatioLimit: true}, WithCodec("zzz", unboundedCodec()))
	if err != nil {
		t.Fatal(err)
	}
	r, err := d.Reader(bytes.NewReader([]byte("x")), "zzz")
	if err != nil {
		t.Fatal(err)
	}
	delivered, err := drain(r, 4096)
	if delivered != 10000 || !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("got (%d, %v)", delivered, err)
	}
}

// Covers: SG-R-CDC-08 SG-I-05
func TestAPanickingExtensionCodecIsContained(t *testing.T) {
	d, err := NewDecoder(Limits{MaxOutput: 100}, WithCodec("zzz", panickingCodec("secret")))
	if err != nil {
		t.Fatal(err)
	}
	r, _ := d.Reader(bytes.NewReader([]byte("x")), "zzz")
	_, err = r.Read(make([]byte, 10))
	if !errors.Is(err, ErrInternal) || strings.Contains(err.Error(), "secret") {
		t.Fatalf("got %v", err)
	}
}

// Covers: SG-R-CDC-08
func TestACodecThatCannotBeCreatedIsAnInternalError(t *testing.T) {
	cause := errors.New("no memory")
	d, err := NewDecoder(Limits{MaxOutput: 100}, WithCodec("zzz", failingCodec(cause)))
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.Reader(bytes.NewReader([]byte("x")), "gzip", "zzz")
	var e *Error
	if !errors.As(err, &e) || e.Kind != KindInternal || e.Layer != 1 || !errors.Is(err, cause) {
		t.Fatalf("got %v", err)
	}
}

// Covers: SG-R-CDC-09
func TestCodecRegistrationRules(t *testing.T) {
	limits := Limits{MaxOutput: 1}
	tests := []struct {
		name string
		opts []Option
	}{
		{"nil codec", []Option{WithCodec("zzz", nil)}},
		{"gzip is reserved", []Option{WithCodec("gzip", repeatCodec(1))}},
		{"deflate is reserved", []Option{WithCodec("deflate", repeatCodec(1))}},
		{"identity is reserved", []Option{WithCodec("identity", repeatCodec(1))}},
		{"x-gzip is reserved", []Option{WithCodec("x-gzip", repeatCodec(1))}},
		{"upper case", []Option{WithCodec("Zzz", repeatCodec(1))}},
		{"invalid token", []Option{WithCodec("a b", repeatCodec(1))}},
		{"empty name", []Option{WithCodec("", repeatCodec(1))}},
		{"twice", []Option{WithCodec("zzz", repeatCodec(1)), WithCodec("zzz", repeatCodec(1))}},
		{"invalid MaxInput", []Option{WithMaxInput(0)}},
		{"negative MaxInput", []Option{WithMaxInput(-1)}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewDecoder(limits, tc.opts...)
			if err == nil || (!errors.Is(err, ErrInvalidOption) && !errors.Is(err, ErrInvalidLimits)) {
				t.Fatalf("got %v", err)
			}
		})
	}
	if _, err := NewDecoder(limits, WithCodec("br", repeatCodec(1)), WithCodec("zstd", repeatCodec(1))); err != nil {
		t.Fatalf("br and zstd are the names the optional modules use: %v", err)
	}
}

// Covers: SG-R-HDR-08
func TestRegisteredCodecsBecomeSupportedEncodings(t *testing.T) {
	d, _ := NewDecoder(Limits{MaxOutput: 1000, DisableRatioLimit: true}, WithCodec("twice", repeatCodec(2)))
	got, err := d.ReadAll(strings.NewReader("abc"), "twice")
	if err != nil || string(got) != "aabbcc" {
		t.Fatalf("got %q, %v", got, err)
	}
	// The same decoder does not know encodings nobody registered.
	if _, err := d.ReadAll(strings.NewReader("abc"), "thrice"); !errors.Is(err, ErrUnsupportedEncoding) {
		t.Fatalf("got %v", err)
	}
}

// Per-layer ratios stay within the limit, the product does not: the end-to-end
// check catches it.
// Covers: SG-R-RAT-03
func TestEndToEndRatioAcrossLayers(t *testing.T) {
	limits := Limits{MaxOutput: 1 << 20, MaxRatio: 10, RatioGrace: 1}
	d, err := NewDecoder(limits, WithCodec("x8", repeatCodec(8)))
	if err != nil {
		t.Fatal(err)
	}
	input := bytes.Repeat([]byte("a"), 100)

	// One layer: ratio 8 <= 10.
	if _, err := d.ReadAll(bytes.NewReader(input), "x8"); err != nil {
		t.Fatalf("single layer: %v", err)
	}
	// Two layers: each is 8, together 64 > 10.
	_, err = d.ReadAll(bytes.NewReader(input), "x8", "x8")
	var e *Error
	if !errors.As(err, &e) || e.Kind != KindRatioLimit {
		t.Fatalf("two layers: got %v, want ratio limit", err)
	}
}

// Covers: SG-R-RAT-01
func TestRatioBoundaryWithAFakeCodec(t *testing.T) {
	input := bytes.Repeat([]byte("a"), 1000)
	for _, tc := range []struct {
		factor  int
		allowed bool
	}{{10, true}, {11, false}} {
		d, _ := NewDecoder(Limits{MaxOutput: 1 << 20, MaxRatio: 10, RatioGrace: 1}, WithCodec("rep", repeatCodec(tc.factor)))
		_, err := d.ReadAll(bytes.NewReader(input), "rep")
		if tc.allowed != (err == nil) || (!tc.allowed && !errors.Is(err, ErrRatioLimit)) {
			t.Errorf("factor %d: %v", tc.factor, err)
		}
	}
}

// Covers: SG-R-INP-01 SG-R-INP-02
func TestMaxInputOption(t *testing.T) {
	stream := gzipBytes(t, sampleData(5000))
	limits := Limits{MaxOutput: 1 << 20, DisableRatioLimit: true}

	if _, err := DecodeAll(bytes.NewReader(stream), []string{"gzip"}, limits, WithMaxInput(int64(len(stream)))); err != nil {
		t.Fatalf("input exactly at the cap: %v", err)
	}
	src := &countingSource{size: 1 << 20}
	_, err := DecodeAll(io.MultiReader(bytes.NewReader(stream), src), []string{"gzip"}, limits, WithMaxInput(int64(len(stream)-1)))
	if !errors.Is(err, ErrInputLimit) {
		t.Fatalf("input one byte over the cap: %v", err)
	}
	if src.handed != 0 {
		t.Fatalf("source read past the cap: %d", src.handed)
	}
}

// The cap is about what the caller's source delivers, not about what inner
// layers produce for the next layer.
// Covers: SG-R-INP-01
func TestMaxInputAppliesToTheSourceOnly(t *testing.T) {
	data := sampleData(5000)
	inner := gzipBytes(t, data)
	stream := gzipBytes(t, inner)
	if len(inner) <= len(stream)-100 {
		t.Fatal("test needs a first layer whose output is larger than the source")
	}

	limits := Limits{MaxOutput: 1 << 20, DisableRatioLimit: true}
	got, err := DecodeAll(bytes.NewReader(stream), []string{"gzip", "gzip"}, limits, WithMaxInput(int64(len(stream))))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("cap equal to the source size: %v", err)
	}
	if _, err := DecodeAll(bytes.NewReader(stream), []string{"gzip", "gzip"}, limits, WithMaxInput(int64(len(stream)-1))); !errors.Is(err, ErrInputLimit) {
		t.Fatalf("cap one byte below the source size: %v", err)
	}
}

// Covers: SG-R-INP-01
func TestMaxInputAlsoBoundsIdentityBodies(t *testing.T) {
	_, err := DecodeAll(bytes.NewReader(make([]byte, 100)), nil, Limits{MaxOutput: 1000}, WithMaxInput(99))
	if !errors.Is(err, ErrInputLimit) {
		t.Fatalf("got %v", err)
	}
}

// Covers: SG-R-RDR-06 SG-I-10
func TestCloseIsIdempotentAndLeavesTheSourceOpen(t *testing.T) {
	closed := 0
	src := &closeTrackingSource{Reader: strings.NewReader("hello")}
	d, _ := NewDecoder(Limits{MaxOutput: 100, DisableRatioLimit: true}, WithCodec("track", closableCodec{closed: &closed}))
	r, err := d.Reader(src, "track", "track")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(r); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if closed != 2 {
		t.Fatalf("codec readers closed %d times, want once each (2)", closed)
	}
	if src.closed {
		t.Fatal("the caller's source was closed")
	}
	if n, err := r.Read(make([]byte, 4)); n != 0 || !errors.Is(err, ErrClosed) {
		t.Fatalf("read after Close: (%d, %v)", n, err)
	}
}

// The first error a codec reports on Close is passed on, and the others are
// still closed.
func TestCloseReportsTheFirstCodecError(t *testing.T) {
	closeErr := errors.New("close failed")
	failing := codecFunc(func(src Source) (io.Reader, error) {
		return failingCloser{Reader: src, err: closeErr}, nil
	})
	d, _ := NewDecoder(Limits{MaxOutput: 10}, WithCodec("fc", failing))
	r, err := d.Reader(strings.NewReader("x"), "fc", "fc")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); !errors.Is(err, closeErr) {
		t.Fatalf("got %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

type failingCloser struct {
	io.Reader
	err error
}

func (f failingCloser) Close() error { return f.err }

// A failed construction releases the codecs created so far.
// Covers: SG-I-10
func TestFailedConstructionClosesEarlierLayers(t *testing.T) {
	closed := 0
	d, _ := NewDecoder(Limits{MaxOutput: 100},
		WithCodec("track", closableCodec{closed: &closed}),
		WithCodec("fail", failingCodec(errors.New("boom"))))
	if _, err := d.Reader(strings.NewReader("x"), "fail", "track"); err == nil {
		t.Fatal("expected an error")
	}
	if closed != 1 {
		t.Fatalf("closed %d, want 1", closed)
	}
}

// Closing a reader that gzip and deflate created releases their flate state
// and keeps errors sticky.
func TestCloseAfterPartialReadOfBuiltinCodecs(t *testing.T) {
	for _, tc := range []struct {
		encoding string
		stream   []byte
	}{{"gzip", gzipBytes(t, sampleData(5000))}, {"deflate", zlibBytes(t, sampleData(5000))}} {
		r, err := Decode(bytes.NewReader(tc.stream), []string{tc.encoding}, loose)
		if err != nil {
			t.Fatal(err)
		}
		r.Read(make([]byte, 10))
		if err := r.Close(); err != nil {
			t.Fatalf("%s: %v", tc.encoding, err)
		}
		if _, err := r.Read(make([]byte, 10)); !errors.Is(err, ErrClosed) {
			t.Fatalf("%s: %v", tc.encoding, err)
		}
	}
	// Close before the first read must also be harmless.
	r, _ := Decode(bytes.NewReader(gzipBytes(t, nil)), []string{"gzip"}, loose)
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
}

// A failing source is a source error, not corruption.
// Covers: SG-R-RDR-05
func TestSourceErrorsAreReportedAsSourceErrors(t *testing.T) {
	stream := gzipBytes(t, sampleData(5000))
	for _, cut := range []int{0, 5, len(stream) / 2, len(stream) - 1} {
		src := io.MultiReader(bytes.NewReader(stream[:cut]), readerFunc(func([]byte) (int, error) { return 0, errBoom }))
		_, err := DecodeAll(src, []string{"gzip"}, loose)
		if !errors.Is(err, ErrSource) || !errors.Is(err, errBoom) || errors.Is(err, ErrCorrupt) {
			t.Errorf("cut at %d: %v", cut, err)
		}
	}
	// The same holds one layer deeper.
	src := io.MultiReader(bytes.NewReader(gzipBytes(t, gzipBytes(t, sampleData(500)))[:20]), readerFunc(func([]byte) (int, error) { return 0, errBoom }))
	if _, err := DecodeAll(src, []string{"gzip", "gzip"}, loose); !errors.Is(err, ErrSource) {
		t.Errorf("two layers: %v", err)
	}
}

// DecodeAll returns an error and no data, never a partial body.
// Covers: SG-R-API-02 SG-R-LAY-06
func TestDecodeAllReturnsNoPartialData(t *testing.T) {
	stream := gzipBytes(t, sampleData(10000))
	got, err := DecodeAll(bytes.NewReader(stream), []string{"gzip"}, Limits{MaxOutput: 9999, DisableRatioLimit: true})
	if !errors.Is(err, ErrOutputLimit) || got != nil {
		t.Fatalf("got (%d bytes, %v)", len(got), err)
	}
	got, err = DecodeAll(bytes.NewReader(stream[:len(stream)-1]), []string{"gzip"}, loose)
	if !errors.Is(err, ErrCorrupt) || got != nil {
		t.Fatalf("truncated: got (%d bytes, %v)", len(got), err)
	}
}

// Covers: SG-R-LAY-05 SG-R-LAY-09 SG-I-03
func TestRealBombStopsEarlyAndStaysStopped(t *testing.T) {
	stream := zerosGzip(t, 256<<20) // about 250 KiB, 256 MiB when decoded
	counter := &readCounter{r: bytes.NewReader(stream)}

	r, err := Decode(counter, []string{"gzip"}, Limits{MaxOutput: 1 << 20, DisableRatioLimit: true})
	if err != nil {
		t.Fatal(err)
	}
	delivered, err := drain(r, 32<<10)
	if delivered != 1<<20 || !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("got (%d, %v)", delivered, err)
	}
	if counter.total >= len(stream)/2 {
		t.Fatalf("read %d of %d bytes before stopping", counter.total, len(stream))
	}

	readsBefore := counter.reads
	requireSticky(t, r, ErrOutputLimit)
	if counter.reads != readsBefore {
		t.Fatal("the source was read after the terminal error")
	}
}

type readCounter struct {
	r     io.Reader
	reads int
	total int
}

func (c *readCounter) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.reads++
	c.total += n
	return n, err
}

// A nested bomb: the outer layer is harmless, the inner one explodes.
// Covers: SG-R-LAY-01 SG-I-01
func TestNestedBombIsStopped(t *testing.T) {
	stream := gzipBytes(t, zerosGzip(t, 128<<20))
	r, err := Decode(bytes.NewReader(stream), []string{"gzip", "gzip"}, Limits{MaxOutput: 1 << 20, DisableRatioLimit: true})
	if err != nil {
		t.Fatal(err)
	}
	delivered, err := drain(r, 4096)
	if delivered != 1<<20 || !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("got (%d, %v)", delivered, err)
	}
}

// With default limits the maximal gzip bomb also trips the ratio check (the
// best deflate can do is about 1032:1 and the default is 1000).
// Covers: SG-R-RAT-01 SG-I-02
func TestDefaultLimitsStopAMaximalGzipBomb(t *testing.T) {
	stream := zerosGzip(t, 256<<20)
	_, err := DecodeAll(bytes.NewReader(stream), []string{"gzip"}, Limits{MaxOutput: 1 << 30})
	if !errors.Is(err, ErrRatioLimit) {
		t.Fatalf("got %v", err)
	}
}

// Covers: SG-R-RDR-01 SG-I-09
func TestEveryChainShapeIsIndependentOfReadSizes(t *testing.T) {
	data := sampleData(30000)
	cases := []struct {
		encodings []string
		stream    []byte
	}{
		{nil, data},
		{[]string{"gzip"}, gzipBytes(t, data)},
		{[]string{"deflate"}, zlibBytes(t, data)},
		{[]string{"deflate"}, rawDeflateBytes(t, data)},
		{[]string{"gzip", "deflate", "gzip"}, gzipBytes(t, zlibBytes(t, gzipBytes(t, data)))},
	}
	for _, tc := range cases {
		for _, pattern := range [][]int{{1}, {3}, {5000}, {1 << 20}, {1, 7, 4096, 1}} {
			r, err := Decode(bytes.NewReader(tc.stream), tc.encodings, loose)
			if err != nil {
				t.Fatal(err)
			}
			delivered, err := drainPatternCollect(r, pattern)
			if err != io.EOF || !bytes.Equal(delivered, data) {
				t.Fatalf("%q pattern %v: err=%v equal=%v", tc.encodings, pattern, err, bytes.Equal(delivered, data))
			}
		}
	}
}

// drainPatternCollect is drainPattern that keeps the bytes.
func drainPatternCollect(r io.Reader, sizes []int) ([]byte, error) {
	var out bytes.Buffer
	for i := 0; ; i++ {
		buf := make([]byte, sizes[i%len(sizes)])
		n, err := r.Read(buf)
		out.Write(buf[:n])
		if err != nil {
			return out.Bytes(), err
		}
	}
}

// One Decoder serves many goroutines.
// Covers: SG-R-RDR-07
func TestADecoderIsSafeForConcurrentUse(t *testing.T) {
	d, err := NewDecoder(Limits{MaxOutput: 1 << 20, DisableRatioLimit: true})
	if err != nil {
		t.Fatal(err)
	}
	data := sampleData(20000)
	good := gzipBytes(t, data)
	bad := good[:len(good)-5]

	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				got, err := d.ReadAll(bytes.NewReader(good), "gzip")
				if err != nil || !bytes.Equal(got, data) {
					t.Errorf("goroutine %d: good stream: %v", i, err)
				}
				if _, err := d.ReadAll(bytes.NewReader(bad), "gzip"); !errors.Is(err, ErrCorrupt) {
					t.Errorf("goroutine %d: bad stream: %v", i, err)
				}
			}
		}()
	}
	wg.Wait()
}

func TestZeroLengthReadsOnAChain(t *testing.T) {
	r, _ := Decode(bytes.NewReader(gzipBytes(t, []byte("hello"))), []string{"gzip"}, loose)
	if n, err := r.Read(nil); n != 0 || err != nil {
		t.Fatalf("Read(nil) = (%d, %v)", n, err)
	}
	got, err := io.ReadAll(r)
	if err != nil || string(got) != "hello" {
		t.Fatalf("got %q, %v", got, err)
	}
}
