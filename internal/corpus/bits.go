// Package corpus builds the byte streams of the conformance corpus without
// depending on any compressor. Bombs and wrappers are constructed by hand from
// the format specifications (RFC 1950, 1951, 1952), so the same bytes come out
// on every Go version and every machine, and the construction can be repeated
// in other languages.
package corpus

// bitWriter packs bits the way DEFLATE does: fields are written starting at
// the least significant bit of each byte.
type bitWriter struct {
	out   []byte
	acc   uint64 // pending bits, least significant first
	count uint   // number of pending bits, always below 8 between calls
}

// bits appends the low `n` bits of value, least significant bit first.
// Used for all DEFLATE header fields and extra bits.
func (w *bitWriter) bits(value uint64, n uint) {
	w.acc |= value << w.count
	w.count += n
	for w.count >= 8 {
		w.out = append(w.out, byte(w.acc))
		w.acc >>= 8
		w.count -= 8
	}
}

// code appends a Huffman code of the given length, most significant bit
// first, as DEFLATE requires for Huffman codes.
func (w *bitWriter) code(code uint64, n uint) {
	var reversed uint64
	for i := uint(0); i < n; i++ {
		reversed = reversed<<1 | (code>>i)&1
	}
	w.bits(reversed, n)
}

// alignToByte pads the current byte with zero bits, so the next write starts
// on a byte boundary (as brotli requires before raw bytes).
func (w *bitWriter) alignToByte() {
	if w.count > 0 {
		w.out = append(w.out, byte(w.acc))
		w.acc, w.count = 0, 0
	}
}

// finish pads the last byte with zero bits and returns everything written.
func (w *bitWriter) finish() []byte {
	if w.count > 0 {
		w.out = append(w.out, byte(w.acc))
		w.acc, w.count = 0, 0
	}
	return w.out
}
