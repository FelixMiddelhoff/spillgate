// Package zstd adds the Zstandard content coding ("zstd") to spillgate.
//
// It is a separate module so that programs that never decode zstd do not
// carry its dependency. Enable it when building a decoder:
//
//	d, err := spillgate.NewDecoder(limits, zstd.Enable())
//
// The decoder is github.com/klauspost/compress/zstd (pure Go, no cgo). It is
// not given the raw input. This package splits the input into frames itself
// and hands the library one validated frame at a time, so that:
//
//   - the window size, the dictionary id and the reserved bits are checked
//     from the frame header before the library allocates anything; a window
//     above the cap, including the window a single-segment frame implies by
//     its declared content size, is spillgate.KindMemoryLimit (SG-R-CDC-05);
//   - skippable frames are skipped here, counted as input only;
//   - the library never reads past the end of a frame, so the input counted
//     for the ratio is exact, and bytes after the last frame are an error;
//   - no declared size is used for anything except that window check.
package zstd

import (
	"fmt"
	"io"

	kzstd "github.com/klauspost/compress/zstd"

	"github.com/FelixMiddelhoff/spillgate"
)

const (
	// DefaultMaxWindow is the default cap on a frame's window: 8 MiB, the size
	// RFC 9659 requires decoders of the "zstd" content coding to support.
	DefaultMaxWindow = 8 << 20
	// MinWindow is the smallest window the format allows (1 KiB).
	MinWindow = 1 << 10
	// MaxWindow is the largest window this package accepts as a cap (1 GiB).
	MaxWindow = 1 << 30
)

// Setting configures the codec.
type Setting func(*settings)

type settings struct {
	maxWindow uint64
}

// MaxWindowBytes sets the cap on the window a frame may ask for, in bytes, between
// 1 KiB and 1 GiB. Frames that ask for more are refused before decoding. A
// larger cap lets a hostile frame make the decoder allocate that much memory.
func MaxWindowBytes(n uint64) Setting {
	return func(s *settings) { s.maxWindow = n }
}

// New returns the zstd codec. Register it with spillgate.WithCodec("zstd", ...)
// or use Enable. Invalid settings make every reader creation fail, so a
// mistake cannot weaken the cap silently.
func New(setting ...Setting) spillgate.Codec {
	s := settings{maxWindow: DefaultMaxWindow}
	for _, apply := range setting {
		apply(&s)
	}
	c := codec{maxWindow: s.maxWindow}
	if s.maxWindow < MinWindow || s.maxWindow > MaxWindow {
		c.err = fmt.Errorf("zstd: MaxWindowBytes must be in %d..%d, got %d", MinWindow, MaxWindow, s.maxWindow)
	}
	return c
}

// Enable returns the spillgate option that makes "zstd" a supported encoding.
func Enable(setting ...Setting) spillgate.Option {
	return spillgate.WithCodec("zstd", New(setting...))
}

type codec struct {
	maxWindow uint64
	err       error // invalid settings
}

// NewReader implements spillgate.Codec. It reads nothing yet.
func (c codec) NewReader(src spillgate.Source) (io.Reader, error) {
	if c.err != nil {
		return nil, c.err
	}
	return &reader{src: src, maxWindow: c.maxWindow}, nil
}

// reader decodes a sequence of frames, one at a time.
type reader struct {
	src       spillgate.Source
	maxWindow uint64

	decoder *kzstd.Decoder // created with the first frame, reset for the others
	frame   io.Reader      // the frame being decoded, nil between frames
	frames  int            // frames started so far
	err     error          // sticky terminal condition
}

// Read implements io.Reader.
func (r *reader) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	for {
		if r.frame == nil {
			if err := r.nextFrame(); err != nil {
				r.err = err
				return 0, err
			}
		}
		n, err := r.decoder.Read(p)
		switch {
		case err == nil:
			return n, nil
		case err == io.EOF:
			r.frame = nil // this frame is complete; look for the next one
			if n > 0 {
				return n, nil
			}
		default:
			r.err = err // the library's complaints about a frame we validated are corruption
			return n, r.err
		}
	}
}

// Close implements io.Closer. It releases the library's decoder.
func (r *reader) Close() error {
	if r.err == nil {
		r.err = io.ErrClosedPipe
	}
	if r.decoder != nil {
		r.decoder.Close()
		r.decoder = nil
	}
	return nil
}

// nextFrame skips skippable frames, then reads and validates the header of the
// next real frame and points the decoder at it. It returns io.EOF when the
// input ends cleanly after at least one frame.
func (r *reader) nextFrame() error {
	for {
		magic, err := r.readMagic()
		if err != nil {
			return err
		}
		switch {
		case magic == frameMagic:
			return r.startFrame(magic)
		case magic&skippableMask == skippableMagic:
			if err := r.skipFrame(); err != nil {
				return err
			}
		default:
			return corrupt("data that is not a zstd frame follows the stream")
		}
	}
}

// readMagic reads the 4-byte magic number of a frame. The input may end before
// it only between frames and only after the first one.
func (r *reader) readMagic() (uint32, error) {
	first, err := r.src.ReadByte()
	if err != nil {
		if err == io.EOF && r.frames > 0 {
			return 0, io.EOF
		}
		return 0, noEOF(err)
	}
	if r.frames > 0 && first != frameMagicFirst && first&0xf0 != skippableFirst {
		// Cannot start another frame: trailing data. The byte was only looked
		// at, so it is given back and not taken (SG-R-INP-01).
		if u, ok := r.src.(io.ByteScanner); ok {
			_ = u.UnreadByte()
		}
		return 0, corrupt("data that is not a zstd frame follows the stream")
	}
	var rest [3]byte
	if _, err := io.ReadFull(r.src, rest[:]); err != nil {
		return 0, noEOF(err)
	}
	return uint32(first) | uint32(rest[0])<<8 | uint32(rest[1])<<16 | uint32(rest[2])<<24, nil
}

// skipFrame skips the payload of a skippable frame. The bytes count as input
// consumed by the codec and as nothing else.
func (r *reader) skipFrame() error {
	var size [4]byte
	if _, err := io.ReadFull(r.src, size[:]); err != nil {
		return noEOF(err)
	}
	left := int64(uint32(size[0]) | uint32(size[1])<<8 | uint32(size[2])<<16 | uint32(size[3])<<24)
	var scratch [4096]byte
	for left > 0 {
		n, err := r.src.Read(scratch[:min(left, int64(len(scratch)))])
		left -= int64(n)
		if err != nil && left > 0 {
			return noEOF(err)
		}
	}
	r.frames++ // a skippable frame is a frame: the input may end after it
	return nil
}

// startFrame reads the frame header after the magic number, validates it and
// hands the frame to the decoder.
func (r *reader) startFrame(magic uint32) error {
	header, err := r.readHeader(magic)
	if err != nil {
		return err
	}
	body := &frameBody{src: r.src, out: header.raw, checksum: header.checksum}

	if r.decoder == nil {
		r.decoder, err = kzstd.NewReader(body,
			kzstd.WithDecoderConcurrency(1), // no background goroutines
			kzstd.WithDecoderMaxWindow(r.maxWindow),
			kzstd.WithDecoderMaxMemory(r.maxWindow),
		)
	} else {
		err = r.decoder.Reset(body)
	}
	if err != nil {
		return fmt.Errorf("zstd: starting the decoder: %w", err)
	}
	r.frame = body
	r.frames++
	return nil
}

func noEOF(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}

func corrupt(format string, args ...any) error {
	return &spillgate.Error{Kind: spillgate.KindCorrupt, Cause: fmt.Errorf("zstd: "+format, args...)}
}
