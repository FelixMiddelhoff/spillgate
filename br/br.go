// Package br adds the brotli content coding ("br") to spillgate.
//
// It is a separate module so that programs that never decode brotli do not
// carry its dependency. Enable it when building a decoder:
//
//	d, err := spillgate.NewDecoder(limits, br.Enable())
//
// The decoder is the pure Go port github.com/andybalholm/brotli (no cgo). The
// codec adds what spillgate requires of every codec:
//
//   - the stream's window size is read from its first byte and checked against
//     a cap before any decoding starts; larger windows, and the large-window
//     extension, which the RFC reserves and this package does not support, are
//     refused with spillgate.KindMemoryLimit (SG-R-CDC-04);
//   - bytes after the last meta-block are an error, truncation is an error.
//
// Output, ratio and input limits are enforced by spillgate around the codec,
// as for every other codec.
package br

import (
	"errors"
	"fmt"
	"io"

	"github.com/andybalholm/brotli"

	"github.com/FelixMiddelhoff/spillgate"
)

const (
	// DefaultMaxWindowBits is the largest window the RFC 7932 format allows:
	// 2^24-16 bytes, about 16 MiB. It is the default cap.
	DefaultMaxWindowBits = 24
	// MinWindowBits is the smallest window of the format (1 KiB).
	MinWindowBits = 10
)

// Setting configures the codec.
type Setting func(*settings)

type settings struct {
	maxWindowBits int
}

// MaxWindowBits lowers the cap on the window a stream may ask for, to
// 2^n bytes for n in 10..24. Streams that ask for more are refused before
// decoding. The format cannot express more than 24, so raising the cap
// beyond the default is not possible.
func MaxWindowBits(n int) Setting {
	return func(s *settings) { s.maxWindowBits = n }
}

// New returns the brotli codec. Register it with spillgate.WithCodec("br", ...)
// or use Enable. Invalid settings make every reader creation fail, so a
// mistake cannot weaken the cap silently.
func New(setting ...Setting) spillgate.Codec {
	s := settings{maxWindowBits: DefaultMaxWindowBits}
	for _, apply := range setting {
		apply(&s)
	}
	c := codec{maxWindowBits: s.maxWindowBits}
	if s.maxWindowBits < MinWindowBits || s.maxWindowBits > DefaultMaxWindowBits {
		c.err = fmt.Errorf("br: MaxWindowBits must be in %d..%d, got %d", MinWindowBits, DefaultMaxWindowBits, s.maxWindowBits)
	}
	return c
}

// Enable returns the spillgate option that makes "br" a supported encoding.
func Enable(setting ...Setting) spillgate.Option {
	return spillgate.WithCodec("br", New(setting...))
}

type codec struct {
	maxWindowBits int
	err           error // invalid settings
}

// NewReader implements spillgate.Codec. It reads nothing yet.
func (c codec) NewReader(src spillgate.Source) (io.Reader, error) {
	if c.err != nil {
		return nil, c.err
	}
	return &reader{src: src, maxWindowBits: c.maxWindowBits}, nil
}

// reader checks the window bits in the first byte and then hands the stream to
// the brotli decoder.
type reader struct {
	src           spillgate.Source
	maxWindowBits int
	decoder       *brotli.Reader
	err           error // sticky terminal condition
}

// Read implements io.Reader.
func (r *reader) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	if r.decoder == nil {
		if err := r.start(); err != nil {
			r.err = err
			return 0, err
		}
	}
	n, err := r.decoder.Read(p)
	if err != nil {
		r.err = err
	}
	return n, err
}

// Close implements io.Closer. The decoder holds no resources beyond memory.
func (r *reader) Close() error {
	if r.err == nil {
		r.err = io.ErrClosedPipe
	}
	r.decoder = nil
	return nil
}

// start reads the first byte, which holds the whole WBITS field, checks the
// window and creates the decoder over the stream including that byte.
func (r *reader) start() error {
	first, err := r.src.ReadByte()
	if err != nil {
		if err == io.EOF {
			return io.ErrUnexpectedEOF // an empty input is not a brotli stream
		}
		return err
	}
	bits, largeWindow := windowBits(first)
	switch {
	case largeWindow:
		return memoryLimit("a large-window brotli stream (not supported)")
	case bits > r.maxWindowBits:
		return memoryLimit(fmt.Sprintf("a window of 2^%d bytes (the cap is 2^%d)", bits, r.maxWindowBits))
	}
	r.decoder = brotli.NewReader(&prefixed{first: first, src: r.src})
	return nil
}

func memoryLimit(what string) error {
	return &spillgate.Error{Kind: spillgate.KindMemoryLimit, Cause: errors.New("brotli stream asks for " + what)}
}

// windowBits decodes the WBITS field of RFC 7932 section 9.1 from the first
// byte. The pattern 1000001 is reserved by the RFC and used by the large-window
// extension; it is reported as largeWindow.
func windowBits(first byte) (bits int, largeWindow bool) {
	if first&1 == 0 {
		return 16, false
	}
	if n := int(first>>1) & 7; n != 0 {
		return 17 + n, false
	}
	switch m := int(first>>4) & 7; m {
	case 0:
		return 17, false
	case 1:
		return 0, true
	default:
		return 8 + m, false
	}
}

// prefixed yields one byte that was already taken from src, then src itself.
type prefixed struct {
	first byte
	used  bool
	src   io.Reader
}

func (p *prefixed) Read(buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if !p.used {
		p.used = true
		buf[0] = p.first
		return 1, nil
	}
	return p.src.Read(buf)
}
