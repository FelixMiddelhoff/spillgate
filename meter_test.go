package spillgate

import (
	"bytes"
	"errors"
	"io"
	"math"
	"testing"
)

var errBoom = errors.New("boom")

// The meter counts what the codec takes, not what it fetched from the source.
// Covers: SG-R-RAT-02
func TestMeterCountsConsumptionNotFetching(t *testing.T) {
	src := &countingSource{size: 100000}
	m := newInputMeter(src, 0, 1)

	for range 5 {
		if _, err := m.ReadByte(); err != nil {
			t.Fatal(err)
		}
	}
	if m.Consumed() != 5 {
		t.Fatalf("Consumed = %d, want 5", m.Consumed())
	}
	if src.handed != meterBufferSize {
		t.Fatalf("source handed out %d bytes, want one buffer (%d)", src.handed, meterBufferSize)
	}

	buf := make([]byte, 10)
	n, _ := m.Read(buf)
	if n != 10 || m.Consumed() != 15 {
		t.Fatalf("after Read: n=%d consumed=%d", n, m.Consumed())
	}
}

func TestMeterDeliversTheSourceBytesInOrder(t *testing.T) {
	want := make([]byte, 3*meterBufferSize+17)
	for i := range want {
		want[i] = byte(i * 7)
	}
	m := newInputMeter(bytes.NewReader(want), 0, 1)

	got, err := io.ReadAll(m)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("ReadAll: err=%v, equal=%v", err, bytes.Equal(got, want))
	}
	if m.Consumed() != int64(len(want)) {
		t.Fatalf("Consumed = %d, want %d", m.Consumed(), len(want))
	}
}

func TestMeterZeroLengthReadChangesNothing(t *testing.T) {
	m := newInputMeter(bytes.NewReader([]byte{1, 2, 3}), 0, 1)
	if n, err := m.Read(nil); n != 0 || err != nil {
		t.Fatalf("Read(nil) = (%d, %v)", n, err)
	}
	if m.Consumed() != 0 || m.fetched != 0 {
		t.Fatal("a zero-length read must not touch the source or the counters")
	}
}

// Covers: SG-R-INP-01 SG-R-INP-02
func TestMeterInputCapBoundary(t *testing.T) {
	const sourceSize = 10000
	for _, cap := range []int64{1, 2, 4095, 4096, 4097, 5000, 9999, 10000} {
		for _, byteWise := range []bool{true, false} {
			src := &countingSource{size: sourceSize}
			m := newInputMeter(src, cap, 1)

			consumed, err := consumeAll(m, byteWise)

			if consumed != cap {
				t.Errorf("cap %d byteWise=%v: consumed %d bytes before stopping", cap, byteWise, consumed)
			}
			if cap < sourceSize && !errors.Is(err, ErrInputLimit) {
				t.Errorf("cap %d byteWise=%v: error %v, want input limit", cap, byteWise, err)
			}
			if cap == sourceSize && err != io.EOF {
				t.Errorf("cap %d equals the stream size: error %v, want EOF", cap, err)
			}
			if int64(src.handed) > cap+1 {
				t.Errorf("cap %d: source handed out %d bytes, more than cap+1", cap, src.handed)
			}
		}
	}
}

// A stream that fits into the cap is fine even if the source holds more after it
// is consumed; the meter just never asks beyond the probe byte.
// Covers: SG-R-INP-01
func TestMeterInputCapAllowsExactFit(t *testing.T) {
	m := newInputMeter(bytes.NewReader(make([]byte, 50)), 50, 1)
	got, err := io.ReadAll(m)
	if err != nil || len(got) != 50 {
		t.Fatalf("ReadAll = (%d bytes, %v)", len(got), err)
	}
}

func TestMeterInputCapErrorIsStickyAndNamesLayerAndLimit(t *testing.T) {
	m := newInputMeter(&zerosReader{left: 100}, 10, 3)
	consumeAll(m, false)

	for range 3 {
		_, err := m.ReadByte()
		var e *Error
		if !errors.As(err, &e) || e.Kind != KindInputLimit || e.Layer != 3 || e.Limit != 10 {
			t.Fatalf("got %v", err)
		}
	}
}

// Defense in depth: even if the meter were asked to refill after the probe
// byte was fetched (normally unreachable), it must not read the source again.
// Covers: SG-R-INP-02
func TestMeterNeverReadsPastTheProbeByte(t *testing.T) {
	src := readerFunc(func([]byte) (int, error) {
		t.Fatal("source read beyond MaxInput+1 bytes")
		return 0, nil
	})
	m := newInputMeter(src, 10, 1)
	m.fetched = 11 // all allowed bytes plus the probe were fetched already

	if err := m.fill(); !errors.Is(err, ErrInputLimit) {
		t.Fatalf("got %v, want input limit", err)
	}
}

func TestMeterInputCapAtMaxInt64DoesNotOverflow(t *testing.T) {
	m := newInputMeter(bytes.NewReader(make([]byte, 100)), math.MaxInt64, 1)
	got, err := io.ReadAll(m)
	if err != nil || len(got) != 100 {
		t.Fatalf("ReadAll = (%d bytes, %v)", len(got), err)
	}
}

func TestMeterDeliversDataBeforeTheSourceError(t *testing.T) {
	calls := 0
	src := readerFunc(func(p []byte) (int, error) {
		calls++
		if calls == 1 {
			return copy(p, []byte("abc")), errBoom // data and error together
		}
		t.Error("source read again after it failed")
		return 0, errBoom
	})
	m := newInputMeter(src, 0, 1)

	got := make([]byte, 3)
	if n, err := io.ReadFull(m, got); err != nil || string(got[:n]) != "abc" {
		t.Fatalf("data before the error was lost: %q, %v", got[:n], err)
	}
	for range 3 {
		if _, err := m.ReadByte(); !errors.Is(err, errBoom) {
			t.Fatalf("got %v, want the source error", err)
		}
	}
	if !errors.Is(m.SourceErr(), errBoom) {
		t.Fatalf("SourceErr = %v", m.SourceErr())
	}
}

func TestMeterTreatsEOFAsEndNotAsSourceError(t *testing.T) {
	m := newInputMeter(bytes.NewReader([]byte{1}), 0, 1)
	if _, err := io.ReadAll(m); err != nil {
		t.Fatal(err)
	}
	if m.SourceErr() != nil {
		t.Fatalf("EOF recorded as a source error: %v", m.SourceErr())
	}
	for range 3 {
		if _, err := m.ReadByte(); err != io.EOF {
			t.Fatalf("EOF not sticky: %v", err)
		}
	}
}

func TestMeterAcceptsDataTogetherWithEOF(t *testing.T) {
	src := readerFunc(func(p []byte) (int, error) { return copy(p, "xy"), io.EOF })
	m := newInputMeter(src, 0, 1)
	got, err := io.ReadAll(m)
	if err != nil || string(got) != "xy" {
		t.Fatalf("got %q, %v", got, err)
	}
}

// Covers: SG-R-RDR-03
func TestMeterStopsAStuckSource(t *testing.T) {
	calls := 0
	m := newInputMeter(readerFunc(func([]byte) (int, error) { calls++; return 0, nil }), 0, 2)

	_, err := m.ReadByte()
	var e *Error
	if !errors.As(err, &e) || e.Kind != KindInternal || e.Layer != 2 || !errors.Is(err, io.ErrNoProgress) {
		t.Fatalf("got %v", err)
	}
	if calls != maxEmptyReads {
		t.Fatalf("source called %d times, want %d", calls, maxEmptyReads)
	}
	if _, err2 := m.ReadByte(); err2 != err || calls != maxEmptyReads {
		t.Fatal("failure not sticky or source read again")
	}
}

// Covers: SG-R-RDR-04
func TestMeterRejectsASourceThatReportsTooManyBytes(t *testing.T) {
	m := newInputMeter(readerFunc(func(p []byte) (int, error) { return len(p) + 1, nil }), 0, 1)
	if _, err := m.ReadByte(); !errors.Is(err, ErrInternal) {
		t.Fatalf("got %v, want internal", err)
	}

	m = newInputMeter(readerFunc(func(p []byte) (int, error) { return -1, nil }), 0, 1)
	if _, err := m.ReadByte(); !errors.Is(err, ErrInternal) {
		t.Fatalf("negative count: got %v, want internal", err)
	}
}

func TestMeterSurvivesOneByteSources(t *testing.T) {
	data := bytes.Repeat([]byte("spill"), 500)
	m := newInputMeter(io.NopCloser(oneByteAtATime{bytes.NewReader(data)}), 0, 1)
	got, err := io.ReadAll(m)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("err=%v equal=%v", err, bytes.Equal(got, data))
	}
}

type oneByteAtATime struct{ r io.Reader }

func (o oneByteAtATime) Read(p []byte) (int, error) { return o.r.Read(p[:min(1, len(p))]) }

// consumeAll takes bytes until the first error and returns how many it got.
func consumeAll(m *inputMeter, byteWise bool) (int64, error) {
	if byteWise {
		for {
			if _, err := m.ReadByte(); err != nil {
				return m.Consumed(), err
			}
		}
	}
	buf := make([]byte, 333)
	for {
		if _, err := m.Read(buf); err != nil {
			return m.Consumed(), err
		}
	}
}
