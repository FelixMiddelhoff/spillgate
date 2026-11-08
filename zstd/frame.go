package zstd

import (
	"fmt"
	"io"

	"github.com/FelixMiddelhoff/spillgate"
)

// Frame layout constants (RFC 8878 section 3.1).
const (
	frameMagic     = 0xFD2FB528
	skippableMagic = 0x184D2A50
	skippableMask  = 0xFFFFFFF0

	// maxBlockSize is the largest block any frame may hold (128 KiB).
	maxBlockSize = 128 << 10

	blockRaw        = 0
	blockRLE        = 1
	blockCompressed = 2
	blockReserved   = 3
)

// frameHeader is what the codec needs to know about a frame before decoding.
type frameHeader struct {
	raw      []byte // the header bytes as read, magic number included
	checksum bool   // a 4-byte content checksum follows the last block
}

// readHeader reads and validates the frame header that follows the magic
// number. It is deliberately strict and checks everything it can before the
// library is involved: reserved bit, dictionary, window size.
func (r *reader) readHeader(magic uint32) (frameHeader, error) {
	header := frameHeader{raw: []byte{byte(magic), byte(magic >> 8), byte(magic >> 16), byte(magic >> 24)}}
	take := func(n int) ([]byte, error) {
		buf := make([]byte, n) // n is at most 8, set by the descriptor's 2-bit fields
		if _, err := io.ReadFull(r.src, buf); err != nil {
			return nil, noEOF(err)
		}
		header.raw = append(header.raw, buf...)
		return buf, nil
	}

	descriptor, err := take(1)
	if err != nil {
		return header, err
	}
	d := descriptor[0]
	singleSegment := d&(1<<5) != 0
	header.checksum = d&(1<<2) != 0
	if d&(1<<3) != 0 {
		return header, corrupt("reserved bit set in the frame header")
	}

	var window uint64
	if !singleSegment {
		wd, err := take(1)
		if err != nil {
			return header, err
		}
		exponent, mantissa := uint(wd[0]>>3), uint64(wd[0]&7)
		base := uint64(1) << (10 + exponent)
		window = base + base/8*mantissa
	}

	dictBytes, err := take([]int{0, 1, 2, 4}[d&3])
	if err != nil {
		return header, err
	}
	for _, b := range dictBytes {
		if b != 0 {
			return header, corrupt("the frame needs a dictionary")
		}
	}

	fcsSize := []int{0, 2, 4, 8}[d>>6]
	if d>>6 == 0 && singleSegment {
		fcsSize = 1
	}
	fcs, err := take(fcsSize)
	if err != nil {
		return header, err
	}
	if singleSegment {
		// The window of a single-segment frame is its content size, a size the
		// sender declares. It is checked as memory, nothing else (SG-R-CDC-07).
		window = littleEndian(fcs)
		if len(fcs) == 2 {
			window += 256
		}
	}

	if window > r.maxWindow {
		return header, &spillgate.Error{Kind: spillgate.KindMemoryLimit,
			Cause: fmt.Errorf("zstd frame asks for a window of %d bytes (the cap is %d)", window, r.maxWindow)}
	}
	return header, nil
}

func littleEndian(b []byte) uint64 {
	var v uint64
	for i := len(b) - 1; i >= 0; i-- {
		v = v<<8 | uint64(b[i])
	}
	return v
}

// frameBody hands the library the bytes of one frame, and nothing more. It
// first yields the already-read header, then follows the block structure of
// the frame (block headers say how long each block is) until the last block
// and the optional checksum, then reports io.EOF.
type frameBody struct {
	src      spillgate.Source
	checksum bool

	out   []byte // bytes ready to hand out: the header, then each block header
	state int
	left  int64 // bytes of the current block (or checksum) still to pass on
	last  bool  // the current block is the last
}

const (
	stateBlockHeader = iota
	stateBlockBody
	stateDone
)

// Read implements io.Reader.
func (f *frameBody) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		if len(f.out) > 0 {
			n := copy(p, f.out)
			f.out = f.out[n:]
			return n, nil
		}
		switch f.state {
		case stateBlockHeader:
			if err := f.readBlockHeader(); err != nil {
				return 0, err
			}
		case stateBlockBody:
			if f.left == 0 {
				f.endOfBlock()
				continue
			}
			n, err := f.src.Read(p[:min(int64(len(p)), f.left)])
			f.left -= int64(n)
			if n > 0 {
				return n, nil
			}
			if err != nil {
				return 0, noEOF(err)
			}
		default:
			return 0, io.EOF
		}
	}
}

// readBlockHeader reads the 3-byte block header and queues it for the library.
func (f *frameBody) readBlockHeader() error {
	var h [3]byte
	if _, err := io.ReadFull(f.src, h[:]); err != nil {
		return noEOF(err)
	}
	value := uint32(h[0]) | uint32(h[1])<<8 | uint32(h[2])<<16
	f.last = value&1 != 0
	blockType := int(value >> 1 & 3)
	size := int64(value >> 3)

	switch {
	case blockType == blockReserved:
		return corrupt("reserved block type")
	case size > maxBlockSize:
		return corrupt("block of %d bytes, the maximum is %d", size, maxBlockSize)
	case blockType == blockRLE:
		size = 1 // an RLE block stores one byte, whatever size it expands to
	}
	f.out = h[:]
	f.left = size
	f.state = stateBlockBody
	return nil
}

// endOfBlock moves to the next block, to the checksum, or to the end.
func (f *frameBody) endOfBlock() {
	switch {
	case !f.last:
		f.state = stateBlockHeader
	case f.checksum:
		f.checksum = false
		f.left = 4 // the content checksum, passed on like a block body
	default:
		f.state = stateDone
	}
}
