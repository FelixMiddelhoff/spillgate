package spillgate

import (
	"compress/flate"
	"encoding/binary"
	"hash"
	"hash/adler32"
	"io"
)

// zlib header layout (RFC 1950).
const (
	zlibMethodDeflate = 8      // CM
	zlibMaxWindowInfo = 7      // CINFO above this is not allowed
	zlibFlagDict      = 1 << 5 // FDICT
	zlibCheckModulus  = 31     // CMF*256+FLG must be a multiple of this
	zlibTrailerSize   = 4      // Adler-32, big-endian
)

// deflateCodec decodes the HTTP "deflate" content coding: a zlib stream
// (RFC 9110 section 8.4.1.2). Some senders omit the zlib wrapper and send raw
// deflate, so unless strict is set, a stream that does not start with a valid
// zlib header is decoded as raw deflate (SG-R-CDC-03).
type deflateCodec struct{ strict bool }

// NewReader implements Codec.
func (c deflateCodec) NewReader(src Source) (io.Reader, error) {
	return &deflateReader{src: src, strict: c.strict}, nil
}

// isZlibHeader reports whether the two bytes form a valid zlib header with
// the deflate method: CM = 8, CINFO <= 7, and the header checksum holds.
func isZlibHeader(cmf, flg byte) bool {
	return cmf&0x0f == zlibMethodDeflate &&
		cmf>>4 <= zlibMaxWindowInfo &&
		(uint16(cmf)<<8|uint16(flg))%zlibCheckModulus == 0
}

// deflateReader decodes one zlib or raw deflate stream and rejects anything
// after it.
type deflateReader struct {
	src    Source
	strict bool

	body  io.ReadCloser // flate decoder; nil until the first Read
	adler hash.Hash32   // checksum of the output; nil for raw deflate
	err   error         // sticky terminal condition
}

// Read implements io.Reader.
func (d *deflateReader) Read(p []byte) (int, error) {
	if d.err != nil {
		return 0, d.err
	}
	if d.body == nil {
		if err := d.start(); err != nil {
			d.err = err
			return 0, err
		}
	}
	n, err := d.body.Read(p)
	if d.adler != nil {
		d.adler.Write(p[:n])
	}
	if err == nil {
		return n, nil
	}
	if err == io.EOF {
		err = d.finish()
	}
	d.err = err
	return n, err
}

// Close implements io.Closer. It releases the flate decoder and leaves the
// source alone. flate's Close only repeats an error that Read has reported
// already, so it is not passed on.
func (d *deflateReader) Close() error {
	if d.err == nil {
		d.err = io.ErrClosedPipe
	}
	if d.body != nil {
		d.body.Close()
		d.body = nil
	}
	return nil
}

// start looks at the first two bytes to choose between zlib and raw deflate.
func (d *deflateReader) start() error {
	var header [2]byte
	if err := readFull(d.src, header[:]); err != nil {
		return err
	}
	if isZlibHeader(header[0], header[1]) {
		if header[1]&zlibFlagDict != 0 {
			return corrupt("deflate: preset dictionaries are not supported")
		}
		d.body = flate.NewReader(d.src)
		d.adler = adler32.New()
		return nil
	}
	if d.strict {
		return corrupt("deflate: not a zlib stream")
	}
	// Raw deflate: hand the two bytes we looked at back to the decoder.
	d.body = flate.NewReader(&replaySource{prefix: header, src: d.src})
	return nil
}

// finish runs after the flate body ended: it verifies the zlib trailer, if
// there is one, and requires that nothing follows.
func (d *deflateReader) finish() error {
	if d.adler != nil {
		var trailer [zlibTrailerSize]byte
		if err := readFull(d.src, trailer[:]); err != nil {
			return err
		}
		if binary.BigEndian.Uint32(trailer[:]) != d.adler.Sum32() {
			return corrupt("deflate: checksum mismatch")
		}
	}
	if err := expectEndOfStream(d.src, "deflate"); err != nil {
		return err
	}
	return io.EOF
}

// replaySource yields two bytes that were already taken from src, then
// continues with src. The bytes were counted when they were first taken, so
// replaying them does not count again.
type replaySource struct {
	prefix [2]byte
	used   int
	src    Source
}

func (r *replaySource) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.used < len(r.prefix) {
		n := copy(p, r.prefix[r.used:])
		r.used += n
		return n, nil
	}
	return r.src.Read(p)
}

func (r *replaySource) ReadByte() (byte, error) {
	if r.used < len(r.prefix) {
		b := r.prefix[r.used]
		r.used++
		return b, nil
	}
	return r.src.ReadByte()
}
