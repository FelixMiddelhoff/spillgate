package spillgate

import (
	"errors"
	"io"
	"math"
	"math/rand"
	"strings"
	"testing"
)

var readSizes = []int{1, 2, 3, 7, 4096, 1 << 20}

// Boundary matrix: the true size is limit-1, limit and limit+1, read with many
// buffer sizes. Up to the limit the stream is delivered whole and ends with
// EOF; one byte more is a typed error and nothing beyond the limit leaks.
// Covers: SG-R-LAY-02 SG-R-LAY-03 SG-R-LAY-04 SG-R-RDR-01 SG-I-01 SG-I-02 SG-I-09
func TestGuardOutputLimitBoundary(t *testing.T) {
	for _, limit := range []int64{1, 2, 3, 63, 64, 65, 4095, 4096, 4097, 10000} {
		for _, size := range []int64{limit - 1, limit, limit + 1} {
			for _, readSize := range readSizes {
				g := guardOver(&zerosReader{left: size}, noLimitsExceptOutput(t, limit))
				delivered, err := drain(g, readSize)

				if size <= limit {
					if err != io.EOF || delivered != size {
						t.Errorf("limit=%d size=%d read=%d: got (%d, %v), want (%d, EOF)", limit, size, readSize, delivered, err, size)
					}
				} else if !errors.Is(err, ErrOutputLimit) || delivered != limit {
					t.Errorf("limit=%d size=%d read=%d: got (%d, %v), want (%d, output limit)", limit, size, readSize, delivered, err, limit)
				}
			}
		}
	}
}

// Covers: SG-R-LAY-05 SG-I-03
func TestGuardTerminalConditionsAreSticky(t *testing.T) {
	over := guardOver(&zerosReader{left: 10}, noLimitsExceptOutput(t, 5))
	if _, err := drain(over, 3); !errors.Is(err, ErrOutputLimit) {
		t.Fatal(err)
	}
	requireSticky(t, over, ErrOutputLimit)

	clean := guardOver(&zerosReader{left: 5}, noLimitsExceptOutput(t, 5))
	if _, err := drain(clean, 3); err != io.EOF {
		t.Fatal(err)
	}
	requireSticky(t, clean, io.EOF)
}

// The extra byte that proves the limit was exceeded must never reach the caller.
// Covers: SG-R-LAY-03 SG-R-LAY-04
func TestGuardNeverDeliversTheProbeByte(t *testing.T) {
	g := guardOver(&zerosReader{left: 100}, noLimitsExceptOutput(t, 10))
	delivered, err := drain(g, 1000)
	if delivered != 10 || !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("got (%d, %v)", delivered, err)
	}
}

// Covers: SG-R-RDR-02
func TestGuardZeroLengthReadChangesNothing(t *testing.T) {
	called := false
	g := guardOver(readerFunc(func([]byte) (int, error) { called = true; return 0, io.EOF }), noLimitsExceptOutput(t, 5))
	if n, err := g.Read(nil); n != 0 || err != nil || called {
		t.Fatalf("Read(nil) = (%d, %v), codec called: %v", n, err, called)
	}
	if _, err := g.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("state changed by the empty read: %v", err)
	}
}

// Whatever the read sizes and stream sizes, the guard never delivers more than
// the limit and ends with the right condition. Seeded, so failures reproduce.
// Covers: SG-I-01 SG-I-09
func TestGuardRandomReadPatterns(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for range 2000 {
		limit := rng.Int63n(5000) + 1
		size := rng.Int63n(10000)
		sizes := make([]int, rng.Intn(5)+1)
		for i := range sizes {
			sizes[i] = rng.Intn(3000) + 1
		}

		g := guardOver(&zerosReader{left: size}, noLimitsExceptOutput(t, limit))
		delivered, err := drainPattern(g, sizes)

		if delivered > limit {
			t.Fatalf("limit=%d size=%d sizes=%v: delivered %d", limit, size, sizes, delivered)
		}
		if size <= limit && (err != io.EOF || delivered != size) {
			t.Fatalf("limit=%d size=%d sizes=%v: got (%d, %v)", limit, size, sizes, delivered, err)
		}
		if size > limit && !errors.Is(err, ErrOutputLimit) {
			t.Fatalf("limit=%d size=%d sizes=%v: got (%d, %v)", limit, size, sizes, delivered, err)
		}
	}
}

// A limit of MaxInt64 must work without overflow.
// Covers: SG-R-LIM-02
func TestGuardWithMaxInt64Limit(t *testing.T) {
	g := guardOver(&zerosReader{left: 1000}, noLimitsExceptOutput(t, math.MaxInt64))
	if delivered, err := drain(g, 64); err != io.EOF || delivered != 1000 {
		t.Fatalf("got (%d, %v)", delivered, err)
	}
}

func TestGuardPassesDataTogetherWithEOF(t *testing.T) {
	g := guardOver(readerFunc(func(p []byte) (int, error) { return copy(p, "hello"), io.EOF }), noLimitsExceptOutput(t, 100))
	buf := make([]byte, 10)
	if n, err := g.Read(buf); n != 5 || err != io.EOF {
		t.Fatalf("got (%d, %v)", n, err)
	}
	requireSticky(t, g, io.EOF)
}

// Exactly MaxOutput bytes followed by a bad trailer is corruption, not success;
// MaxOutput+1 bytes is the output limit even though the trailer would be bad too.
// Covers: SG-R-LAY-03 SG-R-LAY-07
func TestGuardLimitAndLaterCorruptionOrdering(t *testing.T) {
	makeCodec := func(total int) io.Reader {
		left := total
		return readerFunc(func(p []byte) (int, error) {
			if left == 0 {
				return 0, io.ErrUnexpectedEOF // the "trailer" is bad
			}
			n := min(len(p), left)
			clear(p[:n])
			left -= n
			return n, nil
		})
	}

	exact := guardOver(makeCodec(10), noLimitsExceptOutput(t, 10))
	if _, err := drain(exact, 4); !errors.Is(err, ErrCorrupt) {
		t.Errorf("exact fit with bad trailer: got %v, want corrupt", err)
	}
	over := guardOver(makeCodec(11), noLimitsExceptOutput(t, 10))
	if _, err := drain(over, 4); !errors.Is(err, ErrOutputLimit) {
		t.Errorf("one byte over: got %v, want output limit", err)
	}
}

// consumingCodec takes `in` bytes from its meter and produces `out` zero bytes
// per read. It lets a test dial in an exact expansion ratio.
func consumingCodec(m *inputMeter, in, out int) io.Reader {
	return readerFunc(func(p []byte) (int, error) {
		for range in {
			if _, err := m.ReadByte(); err != nil {
				return 0, err
			}
		}
		n := min(out, len(p))
		clear(p[:n])
		return n, nil
	})
}

// Covers: SG-R-RAT-01 SG-R-RAT-03 SG-I-02
func TestGuardRatioBoundary(t *testing.T) {
	limits := mustResolve(t, Limits{MaxOutput: 1 << 30, MaxRatio: 10, RatioGrace: 1})
	for _, tc := range []struct {
		out     int
		tripped bool
	}{
		{100, false}, // exactly 10 bytes out per byte in: allowed
		{101, true},  // one more: refused
		{50, false},
	} {
		m := newInputMeter(&zerosReader{left: 1 << 20}, 0, 1)
		g := newLayerGuard(consumingCodec(m, 10, tc.out), m, 1, limits)

		buf := make([]byte, 1000)
		var err error
		for range 100 {
			if _, err = g.Read(buf); err != nil {
				break
			}
		}
		if tc.tripped != errors.Is(err, ErrRatioLimit) {
			t.Errorf("out=%d: error %v, want ratio limit: %v", tc.out, err, tc.tripped)
		}
		if tc.tripped {
			requireSticky(t, g, ErrRatioLimit)
		}
	}
}

// Covers: SG-R-RAT-01
func TestGuardRatioIsOnlyCheckedPastTheGrace(t *testing.T) {
	limits := mustResolve(t, Limits{MaxOutput: 1 << 30, MaxRatio: 10, RatioGrace: 1000})
	m := newInputMeter(&zerosReader{left: 1 << 20}, 0, 1)
	g := newLayerGuard(consumingCodec(m, 10, 101), m, 1, limits)

	buf := make([]byte, 1000)
	reads := 0
	var err error
	for err == nil && reads < 100 {
		_, err = g.Read(buf)
		reads++
	}
	// 101 bytes per read: the grace of 1000 is passed on read 10 (1010 bytes).
	if !errors.Is(err, ErrRatioLimit) || reads != 10 {
		t.Fatalf("tripped on read %d with %v, want read 10 with ratio limit", reads, err)
	}
}

// Covers: SG-R-RAT-04
func TestGuardRatioOptOut(t *testing.T) {
	limits := noLimitsExceptOutput(t, 1<<30)
	m := newInputMeter(&zerosReader{left: 1 << 20}, 0, 1)
	g := newLayerGuard(consumingCodec(m, 1, 1000), m, 1, limits)

	buf := make([]byte, 1000)
	for range 100 {
		if _, err := g.Read(buf); err != nil {
			t.Fatalf("ratio opt-out still refused: %v", err)
		}
	}
}

// Covers: SG-R-CDC-08 SG-I-05
func TestGuardContainsPanicsWithoutLeakingTheirValue(t *testing.T) {
	g := guardOver(readerFunc(func([]byte) (int, error) { panic("attacker-controlled-secret") }), noLimitsExceptOutput(t, 10))

	_, err := g.Read(make([]byte, 4))
	if !errors.Is(err, ErrInternal) {
		t.Fatalf("got %v, want internal", err)
	}
	if strings.Contains(err.Error(), "attacker-controlled-secret") {
		t.Fatalf("panic value leaked into the error: %v", err)
	}
	requireSticky(t, g, ErrInternal)
}

// Covers: SG-R-CDC-08
func TestGuardRejectsImpossibleByteCounts(t *testing.T) {
	for name, n := range map[string]func(p []byte) int{
		"more than asked": func(p []byte) int { return len(p) + 1 },
		"negative":        func([]byte) int { return -1 },
	} {
		g := guardOver(readerFunc(func(p []byte) (int, error) { return n(p), nil }), noLimitsExceptOutput(t, 10))
		if _, err := g.Read(make([]byte, 4)); !errors.Is(err, ErrInternal) {
			t.Errorf("%s: got %v, want internal", name, err)
		}
	}
}

// Covers: SG-R-RDR-03
func TestGuardStopsAStuckCodec(t *testing.T) {
	calls := 0
	g := guardOver(readerFunc(func([]byte) (int, error) { calls++; return 0, nil }), noLimitsExceptOutput(t, 10))

	_, err := g.Read(make([]byte, 4))
	if !errors.Is(err, ErrInternal) || !errors.Is(err, io.ErrNoProgress) || calls != maxEmptyReads {
		t.Fatalf("got %v after %d calls", err, calls)
	}
}

func TestGuardClassifiesCodecErrors(t *testing.T) {
	stamped := func(layer int) *Error { return &Error{Kind: KindMemoryLimit, Layer: layer} }
	tests := []struct {
		name      string
		codecErr  error
		wantKind  Kind
		wantLayer int
	}{
		{"our error without layer gets the layer", &Error{Kind: KindMemoryLimit}, KindMemoryLimit, 3},
		{"our error with a layer keeps it", stamped(2), KindMemoryLimit, 2},
		{"wrapped error of ours is found", errors.Join(errors.New("ctx"), &Error{Kind: KindMemoryLimit}), KindMemoryLimit, 3},
		{"truncation is corruption", io.ErrUnexpectedEOF, KindCorrupt, 3},
		{"any unknown error is corruption", errors.New("flate: corrupt input"), KindCorrupt, 3},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			codec := readerFunc(func([]byte) (int, error) { return 0, tc.codecErr })
			g := newLayerGuard(codec, newInputMeter(&zerosReader{}, 0, 3), 3, noLimitsExceptOutput(t, 10))

			_, err := g.Read(make([]byte, 4))
			var e *Error
			if !errors.As(err, &e) || e.Kind != tc.wantKind || e.Layer != tc.wantLayer {
				t.Fatalf("got %v, want kind %v layer %d", err, tc.wantKind, tc.wantLayer)
			}
		})
	}
}

// A failing source is reported as such, not as corruption.
// Covers: SG-R-RDR-05
func TestGuardDistinguishesSourceFailureFromCorruption(t *testing.T) {
	m := newInputMeter(readerFunc(func([]byte) (int, error) { return 0, errBoom }), 0, 1)
	codec := readerFunc(func([]byte) (int, error) {
		_, err := m.ReadByte()
		return 0, err
	})
	g := newLayerGuard(codec, m, 1, noLimitsExceptOutput(t, 10))

	_, err := g.Read(make([]byte, 4))
	if !errors.Is(err, ErrSource) || !errors.Is(err, errBoom) || errors.Is(err, ErrCorrupt) {
		t.Fatalf("got %v", err)
	}
}

// The MaxInput error raised by the meter passes through the guard unchanged.
// Covers: SG-R-INP-01
func TestGuardPassesTheInputLimitThrough(t *testing.T) {
	m := newInputMeter(&zerosReader{left: 100}, 5, 2)
	g := newLayerGuard(consumingCodec(m, 3, 3), m, 2, noLimitsExceptOutput(t, 100))

	_, err := drain(g, 10)
	var e *Error
	if !errors.As(err, &e) || e.Kind != KindInputLimit || e.Layer != 2 {
		t.Fatalf("got %v", err)
	}
}

func TestGuardReportsItsLayerOnLimitErrors(t *testing.T) {
	g := newLayerGuard(&zerosReader{left: 10}, newInputMeter(&zerosReader{}, 0, 4), 4, noLimitsExceptOutput(t, 5))
	_, err := drain(g, 100)
	var e *Error
	if !errors.As(err, &e) || e.Layer != 4 || e.Limit != 5 {
		t.Fatalf("got %+v", err)
	}
}
