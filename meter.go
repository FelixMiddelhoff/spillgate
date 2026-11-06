package spillgate

import (
	"io"
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
	maxInput int64 // 0 means no cap
	layer    int   // layer this meter feeds, for error reporting

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
		m.failed = &Error{Kind: KindInputLimit, Layer: m.layer, Limit: m.maxInput}
		return m.failed
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
	want := m.fetchSize()
	if want < 1 {
		// Everything allowed, probe included, was fetched already. Unreachable
		// while prepare guards consumption, but never read past the cap.
		m.failed = &Error{Kind: KindInputLimit, Layer: m.layer, Limit: m.maxInput}
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
