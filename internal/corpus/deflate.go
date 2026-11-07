package corpus

// MaxMatchLength is the longest match DEFLATE can express.
const MaxMatchLength = 258

// ZerosDeflate returns a raw DEFLATE stream that decodes to 1+258*matches zero
// bytes, at the highest ratio the format allows (about 1032:1): one dynamic
// Huffman block in which a 258-byte match at distance 1 costs two bits.
//
// The block uses three literal/length symbols (literal 0, end of block, and
// length 258) and two distance symbols, so the whole code description is a
// few dozen bytes. Construction, following RFC 1951 section 3.2.7:
//
//	literal/length code lengths: symbol 285 -> 1 bit ('0'), symbols 0 and 256 -> 2 bits ('10', '11')
//	distance code lengths:       symbols 0 and 1 -> 1 bit each ('0', '1')
//	code-length alphabet:        symbol 18 -> 1 bit ('0'), symbols 1 and 2 -> 2 bits ('10', '11')
func ZerosDeflate(matches int64) []byte {
	w := &bitWriter{}

	w.bits(1, 1)  // BFINAL: this is the last block
	w.bits(2, 2)  // BTYPE 10: dynamic Huffman codes
	w.bits(29, 5) // HLIT: 286 literal/length symbols (257 + 29)
	w.bits(1, 5)  // HDIST: 2 distance symbols (1 + 1)
	w.bits(14, 4) // HCLEN: 18 code-length code lengths (4 + 14)

	// Code lengths of the code-length alphabet, in the order fixed by the RFC:
	// 16 17 18 0 8 7 9 6 10 5 11 4 12 3 13 2 14 1. Only 18, 2 and 1 are used.
	for _, length := range []uint64{0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 2} {
		w.bits(length, 3)
	}

	const (
		lengthIs1 = iota // code-length symbol 1 is written as '10'
		lengthIs2        // code-length symbol 2 is written as '11'
		zeroRun          // code-length symbol 18 is written as '0' plus 7 extra bits
	)
	emit := func(symbol int, extra uint64) {
		switch symbol {
		case lengthIs1:
			w.code(0b10, 2)
		case lengthIs2:
			w.code(0b11, 2)
		case zeroRun:
			w.code(0b0, 1)
			w.bits(extra, 7) // repeat count minus 11
		}
	}
	emit(lengthIs2, 0)    // symbol 0 has code length 2
	emit(zeroRun, 138-11) // symbols 1..138 are unused
	emit(zeroRun, 117-11) // symbols 139..255 are unused
	emit(lengthIs2, 0)    // symbol 256 (end of block) has code length 2
	emit(zeroRun, 28-11)  // symbols 257..284 are unused
	emit(lengthIs1, 0)    // symbol 285 (length 258) has code length 1
	emit(lengthIs1, 0)    // distance symbol 0 has code length 1
	emit(lengthIs1, 0)    // distance symbol 1 has code length 1

	w.code(0b10, 2) // literal 0: gives distance 1 something to point at
	for range matches {
		w.code(0b0, 1) // length symbol 285 = 258 bytes, no extra bits
		w.code(0b0, 1) // distance symbol 0 = distance 1, no extra bits
	}
	w.code(0b11, 2) // end of block
	return w.finish()
}

// ZerosDecodedSize returns how many bytes ZerosDeflate(matches) decodes to.
func ZerosDecodedSize(matches int64) int64 { return 1 + MaxMatchLength*matches }

// storedBlockLimit is the most bytes one stored block can carry.
const storedBlockLimit = 65535

// StoredDeflate returns a raw DEFLATE stream that holds data uncompressed in
// stored blocks. It is valid for any data, including none.
func StoredDeflate(data []byte) []byte {
	var out []byte
	for first := true; first || len(data) > 0; first = false {
		n := min(len(data), storedBlockLimit)
		final := byte(0)
		if n == len(data) {
			final = 1
		}
		out = append(out, final, // BFINAL, BTYPE 00, padding to the byte boundary
			byte(n), byte(n>>8), // LEN
			^byte(n), ^byte(n>>8)) // NLEN, the complement of LEN
		out = append(out, data[:n]...)
		data = data[n:]
	}
	return out
}
