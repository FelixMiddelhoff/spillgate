package corpus

// Brotli streams (RFC 7932) built by hand, without an encoder.

// BrotliMetablockMax is the largest meta-block RFC 7932 allows (2^24 bytes).
const BrotliMetablockMax = 1 << 24

// brotliMinCommandBytes is the smallest meta-block BrotliZeros can produce:
// 4 inserted literals plus a copy of at least 2118 bytes (copy length code 23).
const brotliMinCommandBytes = 4 + 2118

// brotliWindowBits writes the WBITS field (RFC 7932 section 9.1) for 10..24.
func brotliWindowBits(w *bitWriter, wbits int) {
	switch {
	case wbits == 16:
		w.bits(0, 1)
	case wbits == 17:
		w.bits(1, 1)
		w.bits(0, 3)
		w.bits(0, 3)
	case wbits >= 18 && wbits <= 24:
		w.bits(1, 1)
		w.bits(uint64(wbits-17), 3)
	case wbits >= 10 && wbits <= 15:
		w.bits(1, 1)
		w.bits(0, 3)
		w.bits(uint64(wbits-8), 3)
	default:
		panic("corpus: brotli window bits must be in 10..24")
	}
}

// brotliMLEN writes ISLAST=0, MNIBBLES and MLEN-1 for a meta-block of mlen
// bytes, using the fewest nibbles so that the top nibble is never zero (the
// format forbids that for 5 and 6 nibbles).
func brotliMLEN(w *bitWriter, mlen int64) {
	value := uint64(mlen - 1)
	w.bits(0, 1) // ISLAST
	switch {
	case value < 1<<16:
		w.bits(0, 2)
		w.bits(value, 16)
	case value < 1<<20:
		w.bits(1, 2)
		w.bits(value, 20)
	default:
		w.bits(2, 2)
		w.bits(value, 24)
	}
}

// brotliEnd writes the final, empty meta-block (ISLAST=1, ISLASTEMPTY=1).
func brotliEnd(w *bitWriter) {
	w.bits(1, 1)
	w.bits(1, 1)
}

// brotliZerosMetablock writes one compressed meta-block that decodes to mlen
// zero bytes (2122 <= mlen <= 2^24).
//
// Every prefix code has a single symbol, so symbols cost no bits. The one
// command is symbol 423 of the insert-and-copy alphabet: insert length code 4
// (4 literals, each the single literal symbol 0) and copy length code 23 (base
// 2118, 24 extra bits), with distance symbol 0 ("last distance", initially 4).
// The 24 extra bits carry the copy length, which is how a few bytes describe
// up to 16 MiB.
func brotliZerosMetablock(w *bitWriter, mlen int64) {
	brotliMLEN(w, mlen)
	w.bits(0, 1) // ISUNCOMPRESSED
	w.bits(0, 3) // NBLTYPESL, NBLTYPESI, NBLTYPESD = 1 each
	w.bits(0, 2) // NPOSTFIX
	w.bits(0, 4) // NDIRECT
	w.bits(0, 2) // context mode of the one literal block type
	w.bits(0, 2) // NTREESL = 1, NTREESD = 1

	simpleSingleSymbol := func(symbol uint64, symbolBits uint) {
		w.bits(1, 2) // HSKIP = 1: simple prefix code
		w.bits(0, 2) // NSYM - 1
		w.bits(symbol, symbolBits)
	}
	simpleSingleSymbol(0, 8)    // literal alphabet (256): the literal 0
	simpleSingleSymbol(423, 10) // insert-and-copy alphabet (704): insert code 4, copy code 23
	simpleSingleSymbol(0, 6)    // distance alphabet (64): last distance

	copyLength := mlen - 4
	w.bits(uint64(copyLength-2118), 24) // extra bits of copy length code 23
}

// BrotliZeros returns a brotli stream that decodes to size zero bytes, with
// window bits wbits (10..24). It needs size >= 2122 or size == 0, and costs
// about 12 bytes per 16 MiB, a ratio above 1,000,000:1.
func BrotliZeros(size int64, wbits int) []byte {
	w := &bitWriter{}
	brotliWindowBits(w, wbits)
	for size > 0 {
		chunk := min(size, BrotliMetablockMax)
		if remainder := size - chunk; remainder > 0 && remainder < brotliMinCommandBytes {
			chunk -= brotliMinCommandBytes // leave a final meta-block that is big enough
		}
		brotliZerosMetablock(w, chunk)
		size -= chunk
	}
	brotliEnd(w)
	return w.finish()
}

// BrotliStored returns a brotli stream that holds data in uncompressed
// meta-blocks, valid for any data.
func BrotliStored(data []byte, wbits int) []byte {
	w := &bitWriter{}
	brotliWindowBits(w, wbits)
	for len(data) > 0 {
		chunk := data[:min(len(data), BrotliMetablockMax)]
		brotliMLEN(w, int64(len(chunk)))
		w.bits(1, 1) // ISUNCOMPRESSED
		w.alignToByte()
		w.out = append(w.out, chunk...)
		data = data[len(chunk):]
	}
	brotliEnd(w)
	return w.finish()
}

// BrotliLargeWindowPrefix returns the first bytes of a stream that starts with
// the large-window marker (WBITS bits 1000001), which RFC 7932 reserves and
// the large-window extension uses. Nothing useful follows it.
func BrotliLargeWindowPrefix() []byte {
	return []byte{0x11, 0x00, 0x00, 0x00}
}
