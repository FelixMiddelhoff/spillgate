package corpus

import (
	"encoding/binary"
	"hash/adler32"
	"hash/crc32"
)

// Data returns size deterministic bytes derived from seed with an xorshift64
// generator. The bytes look random, so they do not compress.
func Data(seed uint64, size int) []byte {
	state := seed*0x9e3779b97f4a7c15 + 1
	out := make([]byte, size)
	for i := range out {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		out[i] = byte(state >> 24)
	}
	return out
}

// GzipHeader describes the optional fields of a gzip member header
// (RFC 1952 section 2.3). A nil slice means the field is absent; an empty
// non-nil slice is an empty field.
type GzipHeader struct {
	Flags     byte   // extra flag bits OR-ed in, for example reserved ones
	Extra     []byte // FEXTRA
	Name      []byte // FNAME, written with a terminating zero byte
	Comment   []byte // FCOMMENT, written with a terminating zero byte
	HeaderCRC bool   // FHCRC, computed correctly
}

// gzipHeaderBytes renders the header of one member.
func gzipHeaderBytes(h GzipHeader) []byte {
	flags := h.Flags
	out := []byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255}
	if h.Extra != nil {
		flags |= 1 << 2
		out = binary.LittleEndian.AppendUint16(out, uint16(len(h.Extra)))
		out = append(out, h.Extra...)
	}
	if h.Name != nil {
		flags |= 1 << 3
		out = append(append(out, h.Name...), 0)
	}
	if h.Comment != nil {
		flags |= 1 << 4
		out = append(append(out, h.Comment...), 0)
	}
	if h.HeaderCRC {
		flags |= 1 << 1
	}
	out[3] = flags
	if h.HeaderCRC {
		out = binary.LittleEndian.AppendUint16(out, uint16(crc32.ChecksumIEEE(out)))
	}
	return out
}

// GzipMember builds one gzip member around an existing raw DEFLATE stream.
// crc and size are the CRC-32 and the length (modulo 2^32) of the decoded data.
func GzipMember(h GzipHeader, deflate []byte, crc, size uint32) []byte {
	out := gzipHeaderBytes(h)
	out = append(out, deflate...)
	out = binary.LittleEndian.AppendUint32(out, crc)
	return binary.LittleEndian.AppendUint32(out, size)
}

// GzipStored wraps data in one gzip member with stored (uncompressed) blocks.
func GzipStored(data []byte) []byte {
	return GzipMember(GzipHeader{}, StoredDeflate(data), crc32.ChecksumIEEE(data), uint32(len(data)))
}

// GzipStoredWith is GzipStored with header fields.
func GzipStoredWith(h GzipHeader, data []byte) []byte {
	return GzipMember(h, StoredDeflate(data), crc32.ChecksumIEEE(data), uint32(len(data)))
}

// ZlibStored wraps data in a zlib stream with stored blocks.
func ZlibStored(data []byte) []byte {
	return zlibWrap(StoredDeflate(data), adler32.Checksum(data))
}

// zlibWrap adds the zlib header (78 01, a valid CMF/FLG pair) and the Adler-32
// trailer around a raw DEFLATE stream.
func zlibWrap(deflate []byte, adler uint32) []byte {
	out := append([]byte{0x78, 0x01}, deflate...)
	return binary.BigEndian.AppendUint32(out, adler)
}

// GzipZeros returns a gzip stream that decodes to ZerosDecodedSize(matches)
// zero bytes.
func GzipZeros(matches int64) []byte {
	size := ZerosDecodedSize(matches)
	return GzipMember(GzipHeader{}, ZerosDeflate(matches), crcOfZeros(size), uint32(size))
}

// ZlibZeros returns a zlib stream that decodes to ZerosDecodedSize(matches)
// zero bytes.
func ZlibZeros(matches int64) []byte {
	return zlibWrap(ZerosDeflate(matches), adlerOfZeros(ZerosDecodedSize(matches)))
}

// crcOfZeros is the CRC-32 of n zero bytes, computed in chunks.
func crcOfZeros(n int64) uint32 {
	var crc uint32
	zeros := make([]byte, 1<<20)
	for n > 0 {
		chunk := min(n, int64(len(zeros)))
		crc = crc32.Update(crc, crc32.IEEETable, zeros[:chunk])
		n -= chunk
	}
	return crc
}

// adlerOfZeros is the Adler-32 of n zero bytes, computed in chunks.
func adlerOfZeros(n int64) uint32 {
	digest := adler32.New()
	zeros := make([]byte, 1<<20)
	for n > 0 {
		chunk := min(n, int64(len(zeros)))
		digest.Write(zeros[:chunk])
		n -= chunk
	}
	return digest.Sum32()
}
