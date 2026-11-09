package spillgate_test

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/FelixMiddelhoff/spillgate"
)

// wrappedEOFSource delivers data and then fails with an error that merely
// wraps io.EOF. A failing source must be source_error (SG-R-RDR-05), never a
// clean end of the body (SG-I-02, SG-R-CDC-06).
type wrappedEOFSource struct {
	data []byte
	err  error
}

func (s *wrappedEOFSource) Read(p []byte) (int, error) {
	if len(s.data) == 0 {
		return 0, s.err
	}
	n := copy(p, s.data)
	s.data = s.data[n:]
	return n, nil
}

func smallLimits() spillgate.Limits {
	return spillgate.Limits{MaxOutput: 1 << 20, DisableRatioLimit: true}
}

// A source error that wraps io.EOF is a failure, not the end of the body: the
// guard compares with == io.EOF as the io.Reader contract says.
//
// Covers: SG-R-RDR-05 SG-R-CDC-06 SG-I-02
func TestWrappedEOFSourceErrorIsNotCleanEnd_Identity(t *testing.T) {
	src := &wrappedEOFSource{data: []byte("partial body"), err: fmt.Errorf("connection reset: %w", io.EOF)}
	got, err := spillgate.DecodeAll(src, nil, smallLimits())
	if err == nil {
		t.Fatalf("truncated identity body accepted as complete: %q", got)
	}
	if !errors.Is(err, spillgate.ErrSource) {
		t.Fatalf("want source_error, got %v", err)
	}
}

func TestWrappedEOFSourceErrorIsNotCleanEnd_Gzip(t *testing.T) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write(bytes.Repeat([]byte("abcdefgh"), 4096))
	w.Close()
	cut := buf.Bytes()[:buf.Len()/2] // truncated member
	src := &wrappedEOFSource{data: cut, err: fmt.Errorf("connection reset: %w", io.EOF)}
	got, err := spillgate.DecodeAll(src, []string{"gzip"}, smallLimits())
	if err == nil {
		t.Fatalf("truncated gzip stream accepted as complete (%d bytes)", len(got))
	}
	if !errors.Is(err, spillgate.ErrSource) {
		t.Fatalf("want source_error, got %v", err)
	}
}
