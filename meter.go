package spillgate

import (
	"context"
	"errors"
	"io"
	"math"
)

const (
	// meterBufferSize is how much the meter fetches from its source at once.
	// It is far below the 64 KiB look-ahead tolerance of SG-R-RAT-02.
	meterBufferSize = 4 << 10

	// maxEmptyReads is how many times in a row a reader may return nothing
	// (0 bytes, no error) before it is declared stuck (SG-R-RDR-03).
	maxEmptyReads = 100
)

// inputMeter sits between a codec and its input. It counts the bytes the
// codec actually takes (not the bytes it fetched from the source), so that a
// read-ahead buffer never gives the codec free ratio credit (SG-R-RAT-02).
//
// It implements io.ByteReader so that compress/flate does not wrap it in a
// reading-ahead bufio.Reader of its own.
//
// Besides counting, the meter enforces the optional MaxInput cap (SG-R-INP-*)
// and defends against misbehaving sources (SG-R-RDR-03, SG-R-RDR-04).
// It is not safe for concurrent use.
type inputMeter struct {
	src      io.Reader
	maxInput int64           // 0 means no cap
	layer    int             // layer this meter feeds, for error reporting
	ctx      context.Context // optional; nil means never canceled. Checked on every refill (4 KiB), well within SG-R-API-04

	buf        [meterBufferSize]byte
	start, end int // buf[start:end] holds fetched but not yet consumed bytes

	fetched  int64 // bytes taken from src
	consumed int64 // bytes handed to the codec

	srcEOF bool  // src reported io.EOF
	srcErr error // first non-EOF error from src; sticky
	failed error // sticky meter failure (input limit, broken source)
}

// newInputMeter wraps src. maxInput 0 means no cap.
func newInputMeter(src io.Reader, maxInput int64, layer int) *inputMeter {
	return &inputMeter{src: src, maxInput: maxInput, layer: layer}
}

// limitError builds the sticky input_limit failure of this meter.
func (m *inputMeter) limitError() error {
	return &Error{Kind: KindInputLimit, Layer: m.layer, Limit: m.maxInput}
}

// checkTaken is called by the layer guard at the end of every codec step. A
// codec that has taken the MaxInput+1-th byte (and not given it back) has
// violated SG-R-INP-01, whatever else it returned in that step. Looking at the
// byte is not taking it: only the consumed count matters, never the fetch count.
func (m *inputMeter) checkTaken() error {
	if m.maxInput > 0 && m.consumed > m.maxInput {
		return m.limitError() // the guard makes it the layer's terminal condition
	}
	return nil
}

// Consumed returns how many bytes the codec has taken so far.
func (m *inputMeter) Consumed() int64 { return m.consumed }

// SourceErr returns the error the source failed with, or nil. The layer guard
// uses it to tell a failing source (KindSource) from a corrupt stream.
func (m *inputMeter) SourceErr() error { return m.srcErr }

// ReadByte implements io.ByteReader.
func (m *inputMeter) ReadByte() (byte, error) {
	if err := m.prepare(); err != nil {
		return 0, err
	}
	b := m.buf[m.start]
	m.start++
	m.consumed++
	return b, nil
}

// Read implements io.Reader. It never returns more than the MaxInput cap allows.
func (m *inputMeter) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if err := m.prepare(); err != nil {
		return 0, err
	}
	n := min(len(p), m.end-m.start)
	if m.maxInput > 0 {
		n = int(min(int64(n), m.maxInput-m.consumed))
	}
	copy(p, m.buf[m.start:m.start+n])
	m.start += n
	m.consumed += int64(n)
	return n, nil
}

// prepare makes sure at least one byte can be handed out. It fails with the
// source's error or EOF when nothing is left, and with KindInputLimit when
// the only byte left would be number MaxInput+1.
func (m *inputMeter) prepare() error {
	if m.failed != nil {
		return m.failed
	}
	if m.start == m.end {
		if err := m.fill(); err != nil {
			return err
		}
	}
	if m.maxInput > 0 && m.consumed >= m.maxInput {
		m.failed = m.limitError()
		return m.failed
	}
	return nil
}

// codecSource is what a codec reads from (the Source of codec.go). Unlike the
// strict meter, which identity layers use, it may hand out the probe byte, the
// MaxInput+1-th, so that a codec can look at it: to find trailing data after a
// complete stream, or to find out that it cannot go on. Whether the codec took
// the byte is decided when the codec step ends (inputMeter.checkTaken), by what
// is consumed then: a codec that finds trailing data gives the probe back with
// UnreadByte and reports the data under its own rules (SG-R-INP-01).
type codecSource struct{ m *inputMeter }

// ReadByte implements io.ByteReader.
func (c codecSource) ReadByte() (byte, error) {
	m := c.m
	if err := m.available(); err != nil {
		return 0, err
	}
	b := m.buf[m.start]
	m.start++
	m.consumed++
	return b, nil
}

// Read implements io.Reader. It hands out at most the bytes up to the probe
// byte; the probe itself comes alone, in the next call, if the codec asks.
func (c codecSource) Read(p []byte) (int, error) {
	m := c.m
	if len(p) == 0 {
		return 0, nil
	}
	if err := m.available(); err != nil {
		return 0, err
	}
	n := min(len(p), m.end-m.start)
	if m.maxInput > 0 {
		if room := m.maxInput - m.consumed; room < math.MaxInt64 {
			n = int(min(int64(n), room+1)) // the probe is the last byte that may be handed out
			if n > 1 && int64(n) == room+1 {
				// The probe is never handed out together with bytes before it:
				// a codec that buffers (a bulk Read into its own buffer) must
				// not be charged for the byte just because it filled its buffer.
				// It is handed out alone, when the codec asks again.
				n--
			}
		}
	}
	copy(p, m.buf[m.start:m.start+n])
	m.start += n
	m.consumed += int64(n)
	return n, nil
}

// UnreadByte implements io.ByteScanner in the one case that matters: it gives
// back the probe byte (number MaxInput+1) if that was the last byte handed out,
// whether by ReadByte or by Read. Taking it back is how a codec says it only
// looked at the byte. For every other byte it returns an error and changes nothing.
func (c codecSource) UnreadByte() error {
	m := c.m
	if m.maxInput <= 0 || m.consumed != m.maxInput+1 || m.start == 0 {
		return errUnreadNotProbe
	}
	m.start--
	m.consumed--
	return nil
}

var errUnreadNotProbe = errors.New("spillgate: only the byte after MaxInput can be unread")

// available makes sure at least one byte is buffered, fetching from the source
// if needed. It does not compare against MaxInput: the fetch size already
// keeps the total at MaxInput+1 (SG-R-INP-02).
func (m *inputMeter) available() error {
	if m.failed != nil {
		return m.failed
	}
	if m.start == m.end {
		return m.fill()
	}
	return nil
}

// fill refills the empty buffer from the source. It returns nil only if at
// least one byte is available afterwards.
func (m *inputMeter) fill() error {
	if m.srcErr != nil {
		return m.srcErr
	}
	if m.srcEOF {
		return io.EOF
	}
	if err := canceledError(m.ctx, m.layer); err != nil {
		m.failed = err
		return err
	}
	want := m.fetchSize()
	if want < 1 {
		// Everything allowed, probe included, was fetched already. Unreachable
		// while prepare guards consumption, but never read past the cap.
		m.failed = m.limitError()
		return m.failed
	}
	for range maxEmptyReads {
		n, err := m.src.Read(m.buf[:want])
		if n < 0 || n > want {
			return m.fail(io.ErrShortBuffer)
		}
		m.start, m.end = 0, n
		m.fetched += int64(n)
		m.rememberSourceState(err)
		switch {
		case n > 0:
			return nil // report err only after the data is drained
		case err != nil:
			return m.sourceState()
		}
	}
	return m.fail(io.ErrNoProgress)
}

// fetchSize is how many bytes the next source read may ask for. With a
// MaxInput cap the meter never requests more than MaxInput+1 bytes in total;
// the extra byte is the probe that detects a violation (SG-R-INP-02).
func (m *inputMeter) fetchSize() int {
	if m.maxInput == 0 {
		return len(m.buf)
	}
	room := m.maxInput - m.fetched // bytes still allowed before the probe
	if room >= int64(len(m.buf)) {
		return len(m.buf)
	}
	return int(room) + 1
}

// rememberSourceState records EOF or a source error so they stay sticky.
func (m *inputMeter) rememberSourceState(err error) {
	switch {
	case err == nil:
	case err == io.EOF:
		m.srcEOF = true
	case m.srcErr == nil:
		m.srcErr = err
	}
}

// sourceState returns the sticky end condition of the source.
func (m *inputMeter) sourceState() error {
	if m.srcErr != nil {
		return m.srcErr
	}
	return io.EOF
}

// fail records that the source broke its contract.
func (m *inputMeter) fail(cause error) error {
	m.failed = &Error{Kind: KindInternal, Layer: m.layer, Cause: cause}
	return m.failed
}
