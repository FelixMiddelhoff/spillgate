package corpus

import "encoding/binary"

// Zstandard frames (RFC 8878) built by hand, without an encoder.

// ZstdBlockMax is Block_Maximum_Size for windows of 128 KiB and more.
const ZstdBlockMax = 128 << 10

const zstdMagic = 0xFD2FB528

// ZstdHeader describes a frame header. WindowLog is used unless SingleSegment
// is set, in which case the window equals the content size.
type ZstdHeader struct {
	SingleSegment bool
	WindowLog     uint    // 10..41; ignored for single-segment frames
	Mantissa      uint8   // 0..7: adds Mantissa/8 of the base window
	ReservedBit   bool    // sets the reserved bit of the descriptor, which makes the frame invalid
	ContentSize   *uint64 // Frame_Content_Size; required when SingleSegment is set
	DictionaryID  *uint32 // Dictionary_ID
	Checksum      bool    // Content_Checksum_Flag (the checksum itself is not written)
}

// blockMax returns Block_Maximum_Size: the smaller of the window and 128 KiB.
func (h ZstdHeader) blockMax() int {
	if h.SingleSegment || h.WindowLog >= 17 {
		return ZstdBlockMax
	}
	return 1 << h.WindowLog
}

// Bytes renders the header, magic number included.
func (h ZstdHeader) Bytes() []byte {
	out := binary.LittleEndian.AppendUint32(nil, zstdMagic)

	var fcsFlag byte
	var fcsField []byte
	if h.ContentSize != nil {
		size := *h.ContentSize
		switch {
		case h.SingleSegment && size <= 255:
			fcsFlag, fcsField = 0, []byte{byte(size)}
		case size >= 256 && size <= 65791:
			fcsFlag, fcsField = 1, binary.LittleEndian.AppendUint16(nil, uint16(size-256))
		case size <= 1<<32-1:
			fcsFlag, fcsField = 2, binary.LittleEndian.AppendUint32(nil, uint32(size))
		default:
			fcsFlag, fcsField = 3, binary.LittleEndian.AppendUint64(nil, size)
		}
	}

	var dictFlag byte
	var dictField []byte
	if h.DictionaryID != nil {
		dictFlag, dictField = 3, binary.LittleEndian.AppendUint32(nil, *h.DictionaryID)
	}

	descriptor := fcsFlag<<6 | dictFlag
	if h.SingleSegment {
		descriptor |= 1 << 5
	}
	if h.Checksum {
		descriptor |= 1 << 2
	}
	if h.ReservedBit {
		descriptor |= 1 << 3
	}
	out = append(out, descriptor)
	if !h.SingleSegment {
		out = append(out, byte(h.WindowLog-10)<<3|h.Mantissa&7) // exponent in the high bits
	}
	out = append(out, dictField...)
	return append(out, fcsField...)
}

// zstdBlockHeader renders a 3-byte block header.
func zstdBlockHeader(last bool, blockType, size int) []byte {
	value := uint32(size)<<3 | uint32(blockType)<<1
	if last {
		value |= 1
	}
	return []byte{byte(value), byte(value >> 8), byte(value >> 16)}
}

// ZstdRLEBlocks returns blocks that decode to size copies of one byte. Each
// RLE block is 4 bytes and decodes to up to blockMax bytes, a ratio of
// 32768:1. last marks the final block of the frame.
func ZstdRLEBlocks(size int64, blockMax int, value byte, last bool) []byte {
	var out []byte
	for {
		chunk := int(min(size, int64(blockMax)))
		size -= int64(chunk)
		final := last && size == 0
		out = append(out, zstdBlockHeader(final, 1, chunk)...)
		out = append(out, value)
		if size == 0 {
			return out
		}
	}
}

// ZstdRawBlocks returns blocks that hold data uncompressed.
func ZstdRawBlocks(data []byte, blockMax int, last bool) []byte {
	var out []byte
	for {
		chunk := data[:min(len(data), blockMax)]
		data = data[len(chunk):]
		final := last && len(data) == 0
		out = append(out, zstdBlockHeader(final, 0, len(chunk))...)
		out = append(out, chunk...)
		if len(data) == 0 {
			return out
		}
	}
}

// ZstdZeros returns a frame that decodes to size zero bytes at 32768:1
// (windowLog 17 or more), with no content size and no checksum.
func ZstdZeros(size int64, windowLog uint) []byte {
	header := ZstdHeader{WindowLog: windowLog}
	return append(header.Bytes(), ZstdRLEBlocks(size, header.blockMax(), 0, true)...)
}

// ZstdStored returns a frame that holds data in raw blocks.
func ZstdStored(data []byte, windowLog uint) []byte {
	header := ZstdHeader{WindowLog: windowLog}
	return append(header.Bytes(), ZstdRawBlocks(data, header.blockMax(), true)...)
}

// ZstdSkippable returns a skippable frame with n zero bytes of payload.
func ZstdSkippable(n int) []byte {
	out := binary.LittleEndian.AppendUint32(nil, 0x184D2A50)
	out = binary.LittleEndian.AppendUint32(out, uint32(n))
	return append(out, make([]byte, n)...)
}
