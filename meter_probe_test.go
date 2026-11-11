package spillgate

import (
	"bytes"
	"errors"
	"io"
	"math"
	"testing"
	"testing/iotest"
)

// Unit tests of the codec's view of the meter (SG-R-INP-01, SG-R-INP-02): the
// probe byte can be handed out and given back, the strict meter and the
// fetch cap are unchanged.

// Covers: SG-R-INP-01 SG-R-INP-02
func TestCodecSourceHandsOutTheProbeByteButNeverMore(t *testing.T) {
	for _, maxInput := range []int64{1, 2, 4095, 4096, 4097, 5000} {
		for _, byteWise := range []bool{true, false} {
			src := &countingSource{size: 10000}
			m := newInputMeter(src, maxInput, 1)
			c := codecSource{m}

			var taken int64
			var err error
			buf := make([]byte, 333)
			for err == nil {
				if byteWise {
					_, err = c.ReadByte()
					if err == nil {
						taken++
					}
				} else {
					var n int
					n, err = c.Read(buf)
					taken += int64(n)
				}
			}
			if taken != maxInput+1 || m.Consumed() != maxInput+1 {
				t.Errorf("MaxInput %d byteWise=%v: took %d bytes (consumed %d), want MaxInput+1", maxInput, byteWise, taken, m.Consumed())
			}
			if !errors.Is(err, ErrInputLimit) {
				t.Errorf("MaxInput %d byteWise=%v: asking beyond the probe gave %v, want input_limit", maxInput, byteWise, err)
			}
			if int64(src.handed) != maxInput+1 {
				t.Errorf("MaxInput %d byteWise=%v: source handed out %d bytes, want MaxInput+1", maxInput, byteWise, src.handed)
			}
			if m.checkTaken() == nil {
				t.Errorf("MaxInput %d: a codec holding the probe must fail the step check", maxInput)
			}
		}
	}
}

// Covers: SG-R-INP-01
func TestCodecSourceUnreadGivesTheProbeBack(t *testing.T) {
	for _, viaRead := range []bool{false, true} {
		m := newInputMeter(bytes.NewReader([]byte("0123456789")), 4, 1)
		c := codecSource{m}
		io.ReadFull(readerFunc(func(p []byte) (int, error) { return c.Read(p[:min(len(p), 4)]) }), make([]byte, 4))
		if m.checkTaken() != nil || m.Consumed() != 4 {
			t.Fatalf("setup: consumed %d", m.Consumed())
		}
		if err := c.UnreadByte(); err == nil {
			t.Fatal("UnreadByte of a byte below the probe must fail")
		}
		if m.Consumed() != 4 {
			t.Fatal("a refused UnreadByte changed the count")
		}

		var b byte
		if viaRead {
			one := make([]byte, 1)
			if n, err := c.Read(one); n != 1 || err != nil {
				t.Fatal(n, err)
			}
			b = one[0]
		} else {
			var err error
			if b, err = c.ReadByte(); err != nil {
				t.Fatal(err)
			}
		}
		if b != '4' || m.Consumed() != 5 || m.checkTaken() == nil {
			t.Fatalf("probe = %q, consumed %d", b, m.Consumed())
		}
		if err := c.UnreadByte(); err != nil {
			t.Fatal(err)
		}
		if m.Consumed() != 4 || m.checkTaken() != nil {
			t.Fatalf("after UnreadByte: consumed %d", m.Consumed())
		}
		if err := c.UnreadByte(); err == nil {
			t.Fatal("a second UnreadByte must fail")
		}
		if again, _ := c.ReadByte(); again != '4' {
			t.Fatalf("the probe is handed out again as %q", again)
		}
	}
}

// Without MaxInput nothing can be unread and nothing is limited.
func TestCodecSourceWithoutMaxInputHasNoProbe(t *testing.T) {
	m := newInputMeter(bytes.NewReader([]byte("abc")), 0, 1)
	c := codecSource{m}
	if _, err := c.ReadByte(); err != nil {
		t.Fatal(err)
	}
	if err := c.UnreadByte(); err == nil {
		t.Fatal("UnreadByte without MaxInput must fail")
	}
	if m.checkTaken() != nil {
		t.Fatal("no cap, no violation")
	}
}

// A source with short reads, one byte at a time, data together with EOF, or an
// error after the probe never makes the meter read more than MaxInput+1 bytes
// or lose bytes.
//
// Covers: SG-R-INP-02
func TestCodecSourceShortReadsFetchAtMostMaxInputPlusOne(t *testing.T) {
	data := bytes.Repeat([]byte("abcdefghij"), 1000)
	for _, maxInput := range []int64{1, 9, 10, 4096, 4097, 9999} {
		for name, wrap := range map[string]func(io.Reader) io.Reader{
			"one-byte": iotest.OneByteReader, "half": iotest.HalfReader, "data+eof": iotest.DataErrReader,
		} {
			ps := &probeSource{r: wrap(bytes.NewReader(data))}
			m := newInputMeter(ps, maxInput, 1)
			c := codecSource{m}
			var got []byte
			buf := make([]byte, 100)
			for {
				n, err := c.Read(buf)
				got = append(got, buf[:n]...)
				if err != nil {
					break
				}
			}
			if int64(len(got)) != maxInput+1 || !bytes.Equal(got, data[:maxInput+1]) {
				t.Errorf("%s MaxInput %d: got %d bytes", name, maxInput, len(got))
			}
			if int64(ps.handed) > maxInput+1 {
				t.Errorf("%s MaxInput %d: source handed out %d bytes", name, maxInput, ps.handed)
			}
		}
	}
}

// MaxInput at the largest value must not overflow the probe arithmetic.
func TestCodecSourceAtMaxInt64DoesNotOverflow(t *testing.T) {
	m := newInputMeter(bytes.NewReader(make([]byte, 100)), math.MaxInt64, 1)
	got, err := io.ReadAll(codecSource{m})
	if err != nil || len(got) != 100 {
		t.Fatalf("ReadAll = (%d bytes, %v)", len(got), err)
	}
	if m.checkTaken() != nil {
		t.Fatal("no violation expected")
	}
}

// The source ending exactly at the cap is EOF for the codec, not a limit.
func TestCodecSourceEndingAtTheCapIsEOF(t *testing.T) {
	m := newInputMeter(bytes.NewReader(make([]byte, 20)), 20, 1)
	got, err := io.ReadAll(codecSource{m})
	if err != nil || len(got) != 20 || m.checkTaken() != nil {
		t.Fatalf("ReadAll = (%d bytes, %v), check %v", len(got), err, m.checkTaken())
	}
}

// The strict meter that identity layers use is unchanged: it never hands out
// the probe.
//
// Covers: SG-R-INP-01
func TestStrictMeterStillRefusesTheProbe(t *testing.T) {
	m := newInputMeter(bytes.NewReader(make([]byte, 50)), 10, 1)
	got, err := io.ReadAll(m)
	if len(got) != 10 || !errors.Is(err, ErrInputLimit) {
		t.Fatalf("got %d bytes, %v", len(got), err)
	}
}
