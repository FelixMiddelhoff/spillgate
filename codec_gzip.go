package spillgate

import (
	"compress/flate"
	"encoding/binary"
	"hash/crc32"
	"io"
)

// gzip member layout (RFC 1952).
const (
	gzipID1      = 0x1f
	gzipID2      = 0x8b
	gzipMethodCM = 8 // deflate

	gzipFlagHeaderCRC = 1 << 1
	gzipFlagExtra     = 1 << 2
	gzipFlagName      = 1 << 3
	gzipFlagComment   = 1 << 4
	gzipReservedFlags = 0xe0 // must be zero; RFC 1952 requires an error otherwise

	gzipFixedHeaderSize = 10
	gzipTrailerSize     = 8

	// gzipMaxStringSize bounds FNAME and FCOMMENT including the terminating
	// zero byte. RFC 1952 sets no limit; this equals the Go standard library's
	// and keeps a header from being used as an unbounded scratch area
	// (SG-R-CDC-02).
	gzipMaxStringSize = 512
)

// gzipCodec is the built-in gzip codec.
type gzipCodec struct{}

// NewReader implements Codec.
func (gzipCodec) NewReader(src Source) (io.Reader, error) {
	return &gzipReader{src: src}, nil
}

// gzipReader decodes a sequence of gzip members. It does its own framing on
// top of compress/flate instead of using compress/gzip, because the standard
// library ignores reserved header flags and cannot be told to reject trailing
// bytes, and the specification requires both (SG-R-CDC-02).
//
// All members share one output budget, because the layer guard around the
// reader counts everything it returns.
type gzipReader struct {
	src     Source
	body    io.ReadCloser // flate decoder of the current member; reused across members
	crc     uint32        // CRC-32 of the current member's output so far
	size    uint32        // size of the current member's output so far, modulo 2^32
	err     error         // sticky terminal condition
	scratch [gzipMaxStringSize]byte
}

// Read implements io.Reader.
func (z *gzipReader) Read(p []byte) (int, error) {
	if z.err != nil {
		return 0, z.err
	}
	if z.body == nil {
		if err := z.readHeader(false); err != nil { // the first member is mandatory
			z.err = err
			return 0, err
		}
	}
	for {
		n, err := z.body.Read(p)
		z.crc = crc32.Update(z.crc, crc32.IEEETable, p[:n])
		z.size += uint32(n)

		if err == nil {
			return n, nil
		}
		if err != io.EOF {
			z.err = err
			return n, err
		}
		// The member's compressed body ended: check the trailer, then look
		// for another member or the end of the stream.
		if err := z.finishMember(); err != nil {
			z.err = err
			return n, err
		}
		if n > 0 {
			return n, nil
		}
	}
}

// Close implements io.Closer. It releases the flate decoder and leaves the
// source alone. flate's Close only repeats an error that Read has reported
// already, so it is not passed on.
func (z *gzipReader) Close() error {
	if z.err == nil {
		z.err = io.ErrClosedPipe
	}
	if z.body != nil {
		z.body.Close()
		z.body = nil
	}
	return nil
}

// finishMember verifies the trailer of the member that just ended and then
// starts the next member. It returns io.EOF when the stream ends cleanly at a
// member boundary.
func (z *gzipReader) finishMember() error {
	var trailer [gzipTrailerSize]byte
	if err := readFull(z.src, trailer[:]); err != nil {
		return err
	}
	if binary.LittleEndian.Uint32(trailer[0:4]) != z.crc {
		return corrupt("gzip: checksum mismatch")
	}
	if binary.LittleEndian.Uint32(trailer[4:8]) != z.size {
		return corrupt("gzip: size mismatch") // ISIZE is checked, never trusted as an allowance
	}
	z.crc, z.size = 0, 0
	return z.readHeader(true)
}

// readHeader reads and validates one member header and prepares the flate
// decoder. At a member boundary a clean end of input returns io.EOF; anywhere
// else it is truncation.
func (z *gzipReader) readHeader(atBoundary bool) error {
	if atBoundary {
		first, err := z.src.ReadByte()
		if err != nil {
			return err // io.EOF here is the clean end of the stream
		}
		z.scratch[0] = first
		if err := readFull(z.src, z.scratch[1:gzipFixedHeaderSize]); err != nil {
			return err
		}
	} else if err := readFull(z.src, z.scratch[:gzipFixedHeaderSize]); err != nil {
		return err
	}

	fixed := z.scratch[:gzipFixedHeaderSize]
	if fixed[0] != gzipID1 || fixed[1] != gzipID2 || fixed[2] != gzipMethodCM {
		return corrupt("gzip: invalid header")
	}
	flags := fixed[3]
	if flags&gzipReservedFlags != 0 {
		return corrupt("gzip: reserved header flags are set")
	}

	headerCRC := crc32.ChecksumIEEE(fixed)
	var err error
	if flags&gzipFlagExtra != 0 {
		if headerCRC, err = z.skipExtraField(headerCRC); err != nil {
			return err
		}
	}
	if flags&gzipFlagName != 0 {
		if headerCRC, err = z.skipString(headerCRC, "name"); err != nil {
			return err
		}
	}
	if flags&gzipFlagComment != 0 {
		if headerCRC, err = z.skipString(headerCRC, "comment"); err != nil {
			return err
		}
	}
	if flags&gzipFlagHeaderCRC != 0 {
		if err := z.checkHeaderCRC(headerCRC); err != nil {
			return err
		}
	}

	z.startBody()
	return nil
}

// skipExtraField discards the FEXTRA field (at most 65535 bytes by format)
// while keeping the running header CRC.
func (z *gzipReader) skipExtraField(headerCRC uint32) (uint32, error) {
	var length [2]byte
	if err := readFull(z.src, length[:]); err != nil {
		return 0, err
	}
	headerCRC = crc32.Update(headerCRC, crc32.IEEETable, length[:])
	for remaining := int(binary.LittleEndian.Uint16(length[:])); remaining > 0; {
		chunk := z.scratch[:min(remaining, len(z.scratch))]
		if err := readFull(z.src, chunk); err != nil {
			return 0, err
		}
		headerCRC = crc32.Update(headerCRC, crc32.IEEETable, chunk)
		remaining -= len(chunk)
	}
	return headerCRC, nil
}

// skipString discards a zero-terminated FNAME or FCOMMENT of at most
// gzipMaxStringSize bytes including the terminator.
func (z *gzipReader) skipString(headerCRC uint32, what string) (uint32, error) {
	for i := range z.scratch {
		b, err := z.src.ReadByte()
		if err != nil {
			return 0, noEOF(err)
		}
		z.scratch[i] = b
		if b == 0 {
			return crc32.Update(headerCRC, crc32.IEEETable, z.scratch[:i+1]), nil
		}
	}
	return 0, corrupt("gzip: header %s is longer than %d bytes", what, gzipMaxStringSize-1)
}

// checkHeaderCRC verifies the optional header checksum (the low 16 bits of the
// CRC-32 of the header).
func (z *gzipReader) checkHeaderCRC(headerCRC uint32) error {
	var stored [2]byte
	if err := readFull(z.src, stored[:]); err != nil {
		return err
	}
	if uint32(binary.LittleEndian.Uint16(stored[:])) != headerCRC&0xffff {
		return corrupt("gzip: header checksum mismatch")
	}
	return nil
}

// startBody (re)initializes the flate decoder for a new member.
func (z *gzipReader) startBody() {
	if z.body == nil {
		z.body = flate.NewReader(z.src)
		return
	}
	z.body.(flate.Resetter).Reset(z.src, nil)
}
