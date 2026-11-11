package spillgate

import (
	"fmt"
	"io"
)

// corrupt builds the error for an invalid or truncated stream. The layer is
// filled in by the layer guard.
func corrupt(format string, args ...any) error {
	return &Error{Kind: KindCorrupt, Cause: fmt.Errorf(format, args...)}
}

// noEOF turns a plain io.EOF into io.ErrUnexpectedEOF: inside a structure
// that must be complete, running out of input is truncation (SG-R-CDC-06).
func noEOF(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}

// readFull reads exactly len(buf) bytes from src. Running out of input,
// including at the very first byte, is io.ErrUnexpectedEOF; other errors
// (a failing source) are returned unchanged.
func readFull(src Source, buf []byte) error {
	_, err := io.ReadFull(src, buf)
	return noEOF(err)
}

// giveBack returns the byte just read to the source if it was the probe byte
// beyond MaxInput: a codec that only looked at it to find trailing data has
// not taken it (SG-R-INP-01). For any other byte, or a source that cannot take
// bytes back, it does nothing.
func giveBack(src Source) {
	if u, ok := src.(io.ByteScanner); ok {
		_ = u.UnreadByte()
	}
}

// expectEndOfStream succeeds only if src has no byte left. Anything else after
// the end of a compressed stream is an error (SG-R-CDC-02, -03, -04, -05).
func expectEndOfStream(src Source, what string) error {
	_, err := src.ReadByte()
	switch err {
	case io.EOF:
		return nil
	case nil:
		giveBack(src)
		return corrupt("%s: unexpected data after the end of the stream", what)
	default:
		return err
	}
}
