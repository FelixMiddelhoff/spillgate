package spillgate

import (
	"io"
)

// Fake codecs for tests of the chain and of the limits around codecs. They
// behave the way careless or hostile third-party codecs might.

// codecFunc adapts a function to the Codec interface.
type codecFunc func(src Source) (io.Reader, error)

func (f codecFunc) NewReader(src Source) (io.Reader, error) { return f(src) }

// repeatCodec emits every input byte `factor` times: an exact, tunable
// expansion ratio.
func repeatCodec(factor int) Codec {
	return codecFunc(func(src Source) (io.Reader, error) {
		return &repeatReader{src: src, factor: factor}, nil
	})
}

type repeatReader struct {
	src     Source
	factor  int
	current byte
	left    int
}

func (r *repeatReader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if r.left == 0 {
			b, err := r.src.ReadByte()
			if err != nil {
				return n, err
			}
			r.current, r.left = b, r.factor
		}
		p[n] = r.current
		n++
		r.left--
	}
	return n, nil
}

// unboundedCodec ignores its input and produces zeros forever, like a decoder
// whose own size limit is missing (the Netty bzip2 / br / zstd class).
func unboundedCodec() Codec {
	return codecFunc(func(Source) (io.Reader, error) {
		return readerFunc(func(p []byte) (int, error) {
			clear(p)
			return len(p), nil
		}), nil
	})
}

// panickingCodec panics on the first read.
func panickingCodec(value any) Codec {
	return codecFunc(func(Source) (io.Reader, error) {
		return readerFunc(func([]byte) (int, error) { panic(value) }), nil
	})
}

// failingCodec fails to even create its reader.
func failingCodec(err error) Codec {
	return codecFunc(func(Source) (io.Reader, error) { return nil, err })
}

// closableCodec wraps passthrough reading and counts Close calls.
type closableCodec struct{ closed *int }

func (c closableCodec) NewReader(src Source) (io.Reader, error) {
	return &closableReader{Reader: src, closed: c.closed}, nil
}

type closableReader struct {
	io.Reader
	closed *int
}

func (r *closableReader) Close() error { *r.closed++; return nil }

// closeTrackingSource records whether the caller's source was closed.
type closeTrackingSource struct {
	io.Reader
	closed bool
}

func (s *closeTrackingSource) Close() error { s.closed = true; return nil }

// forbiddenSource fails the test if anything reads from it.
type forbiddenSource struct{ onRead func() }

func (s forbiddenSource) Read([]byte) (int, error) {
	s.onRead()
	return 0, io.EOF
}
