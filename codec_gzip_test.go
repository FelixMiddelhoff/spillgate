package spillgate

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// loose limits keep the codec tests about the codec: no ratio check, a limit
// far above anything the tests produce.
var loose = Limits{MaxOutput: 1 << 30, DisableRatioLimit: true}

func decodeOne(stream []byte, encoding string, opts ...Option) ([]byte, error) {
	return DecodeAll(bytes.NewReader(stream), []string{encoding}, loose, opts...)
}

func requireDecodes(t *testing.T, stream []byte, encoding string, want []byte, opts ...Option) {
	t.Helper()
	got, err := decodeOne(stream, encoding, opts...)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("decode: err=%v, equal=%v (got %d bytes, want %d)", err, bytes.Equal(got, want), len(got), len(want))
	}
}

func requireCorrupt(t *testing.T, stream []byte, encoding string, opts ...Option) {
	t.Helper()
	got, err := decodeOne(stream, encoding, opts...)
	if !errors.Is(err, ErrCorrupt) || got != nil {
		t.Fatalf("decode: got (%d bytes, %v), want corrupt and no data", len(got), err)
	}
}

// Covers: SG-R-CDC-02
func TestGzipRoundTrip(t *testing.T) {
	for _, size := range []int{0, 1, 2, 100, 4095, 4096, 4097, 100000} {
		data := sampleData(size)
		requireDecodes(t, gzipBytes(t, data), "gzip", data)
	}
}

// Covers: SG-R-CDC-02
func TestGzipMultipleMembersShareTheStream(t *testing.T) {
	a, b, c := sampleData(100), []byte{}, sampleData(5000)
	stream := bytes.Join([][]byte{gzipBytes(t, a), gzipBytes(t, b), gzipBytes(t, c)}, nil)
	requireDecodes(t, stream, "gzip", bytes.Join([][]byte{a, b, c}, nil))
}

// Covers: SG-R-CDC-02 SG-R-LAY-01
func TestGzipMembersShareOneOutputBudget(t *testing.T) {
	member := gzipBytes(t, sampleData(600))
	stream := bytes.Join([][]byte{member, member, member}, nil) // 1800 bytes in total

	limits := Limits{MaxOutput: 1799, DisableRatioLimit: true}
	if _, err := DecodeAll(bytes.NewReader(stream), []string{"gzip"}, limits); !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("budget of 1799 for 1800 bytes: %v", err)
	}
	limits.MaxOutput = 1800
	if _, err := DecodeAll(bytes.NewReader(stream), []string{"gzip"}, limits); err != nil {
		t.Fatalf("budget of 1800 for 1800 bytes: %v", err)
	}
}

// Covers: SG-R-CDC-02
func TestGzipHeaderFields(t *testing.T) {
	data := sampleData(300)
	// Literal sizes on purpose: the tests must not move with the constant.
	name511 := bytes.Repeat([]byte("n"), 511) // 512 bytes with the terminator: the maximum
	name512 := bytes.Repeat([]byte("n"), 512)
	extraMax := bytes.Repeat([]byte("e"), 65535)

	valid := map[string]gzipHeader{
		"name of 511 bytes plus terminator": {name: name511},
		"comment of 511 bytes":              {comment: name511},
		"empty name":                        {name: []byte{}},
		"extra field of 65535 bytes":        {extra: extraMax},
		"empty extra field":                 {extra: []byte{}},
		"header checksum":                   {headerCRC: true},
		"everything together":               {name: []byte("file.txt"), comment: []byte("hi"), extra: []byte("xy"), headerCRC: true},
		"text flag":                         {flags: 1},
	}
	for label, header := range valid {
		t.Run("valid/"+label, func(t *testing.T) {
			requireDecodes(t, gzipMember(t, header, data), "gzip", data)
		})
	}

	invalid := map[string]gzipHeader{
		"name of 512 bytes":    {name: name512},
		"comment of 512 bytes": {comment: name512},
	}
	for label, header := range invalid {
		t.Run("invalid/"+label, func(t *testing.T) {
			requireCorrupt(t, gzipMember(t, header, data), "gzip")
		})
	}
}

// A name without terminator must not make the decoder read on without bound.
// Covers: SG-R-CDC-02 SG-I-08
func TestGzipUnterminatedNameIsBounded(t *testing.T) {
	src := &countingSource{size: 1 << 30}
	header := []byte{0x1f, 0x8b, 8, gzipFlagName, 0, 0, 0, 0, 0, 255}
	stream := io.MultiReader(bytes.NewReader(header), &nonZeroReader{limit: 1 << 30}, src)

	_, err := DecodeAll(stream, []string{"gzip"}, loose)
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("got %v", err)
	}
	if src.handed != 0 {
		t.Fatalf("decoder read on to the end of the name field: %d", src.handed)
	}
}

// nonZeroReader yields 0x41 bytes forever (up to limit).
type nonZeroReader struct{ limit, given int64 }

func (r *nonZeroReader) Read(p []byte) (int, error) {
	if r.given >= r.limit {
		return 0, io.EOF
	}
	n := int(min(int64(len(p)), r.limit-r.given))
	for i := range p[:n] {
		p[i] = 0x41
	}
	r.given += int64(n)
	return n, nil
}

// Covers: SG-R-CDC-02
func TestGzipRejectsBadHeaders(t *testing.T) {
	good := gzipBytes(t, sampleData(50))
	mutate := func(index int, value byte) []byte {
		out := bytes.Clone(good)
		out[index] = value
		return out
	}
	tests := map[string][]byte{
		"first magic byte":        mutate(0, 0x1e),
		"second magic byte":       mutate(1, 0x8c),
		"method 0":                mutate(2, 0),
		"method 7":                mutate(2, 7),
		"method 9":                mutate(2, 9),
		"reserved flag bit 5":     mutate(3, 0x20),
		"reserved flag bit 6":     mutate(3, 0x40),
		"reserved flag bit 7":     mutate(3, 0x80),
		"all reserved flags":      mutate(3, 0xe0),
		"header checksum missing": mutate(3, gzipFlagHeaderCRC),
	}
	for label, stream := range tests {
		t.Run(label, func(t *testing.T) { requireCorrupt(t, stream, "gzip") })
	}
}

// Covers: SG-R-CDC-02
func TestGzipRejectsAWrongHeaderChecksum(t *testing.T) {
	stream := gzipMember(t, gzipHeader{headerCRC: true}, sampleData(50))
	stream[gzipFixedHeaderSize] ^= 0x01 // first byte of the stored header CRC
	requireCorrupt(t, stream, "gzip")
}

// Covers: SG-R-CDC-02
func TestGzipChecksAndSizeTrailer(t *testing.T) {
	good := gzipBytes(t, sampleData(500))
	end := len(good)
	tests := map[string]func([]byte){
		"CRC first byte":  func(b []byte) { b[end-8] ^= 1 },
		"CRC last byte":   func(b []byte) { b[end-5] ^= 0x80 },
		"ISIZE plus one":  func(b []byte) { b[end-4]++ },
		"ISIZE zero":      func(b []byte) { clear(b[end-4:]) },
		"ISIZE all ones":  func(b []byte) { b[end-4], b[end-3], b[end-2], b[end-1] = 255, 255, 255, 255 },
		"ISIZE high byte": func(b []byte) { b[end-1] = 1 },
	}
	for label, corruptTrailer := range tests {
		t.Run(label, func(t *testing.T) {
			stream := bytes.Clone(good)
			corruptTrailer(stream)
			requireCorrupt(t, stream, "gzip")
		})
	}
}

// Whatever the declared size says, only produced bytes count (SG-I-04): a
// lying ISIZE can neither raise nor lower the allowance.
// Covers: SG-R-CDC-07 SG-I-04
func TestGzipDeclaredSizeIsNeverAnAllowance(t *testing.T) {
	data := sampleData(5000)
	for _, declared := range []uint32{0, 1, 4999, 5000, 5001, 1 << 31, 1<<32 - 1} {
		stream := gzipBytes(t, data)
		end := len(stream)
		stream[end-4], stream[end-3] = byte(declared), byte(declared>>8)
		stream[end-2], stream[end-1] = byte(declared>>16), byte(declared>>24)

		limits := Limits{MaxOutput: 2500, DisableRatioLimit: true}
		_, err := DecodeAll(bytes.NewReader(stream), []string{"gzip"}, limits)
		if !errors.Is(err, ErrOutputLimit) {
			t.Errorf("declared %d: got %v, want output limit (LAY-07: the limit is hit before the trailer)", declared, err)
		}
	}
}

// Covers: SG-R-CDC-06
func TestGzipEveryTruncationIsCorrupt(t *testing.T) {
	stream := gzipBytes(t, sampleData(300))
	for n := range len(stream) {
		requireCorrupt(t, stream[:n], "gzip")
	}
}

// Every single-bit change of a valid stream must either be harmless (the same
// data comes out) or be reported as corruption: never other data, never a
// different error class, never a panic.
// Covers: SG-R-CDC-02 SG-I-05
func TestGzipEverySingleBitFlip(t *testing.T) {
	data := sampleData(200)
	good := gzipBytes(t, data)
	for bit := range len(good) * 8 {
		stream := bytes.Clone(good)
		stream[bit/8] ^= 1 << (bit % 8)

		got, err := decodeOne(stream, "gzip")
		switch {
		case err == nil && bytes.Equal(got, data):
		case errors.Is(err, ErrCorrupt) && got == nil:
		default:
			t.Fatalf("bit %d: got (%d bytes, %v)", bit, len(got), err)
		}
	}
}

// Covers: SG-R-CDC-02
func TestGzipBytesAfterTheLastMemberAreCorrupt(t *testing.T) {
	member := gzipBytes(t, sampleData(100))
	tests := map[string][]byte{
		"one zero byte":           {0},
		"zero padding":            make([]byte, 512),
		"first magic byte only":   {0x1f},
		"magic only":              {0x1f, 0x8b},
		"truncated second header": member[:9],
		"truncated second body":   member[:len(member)-3],
		"text":                    []byte("trailing garbage"),
		"newline":                 {'\n'},
	}
	for label, trailing := range tests {
		t.Run(label, func(t *testing.T) {
			requireCorrupt(t, append(bytes.Clone(member), trailing...), "gzip")
		})
	}
}

// Covers: SG-R-CDC-06
func TestGzipEmptyAndForeignInput(t *testing.T) {
	requireCorrupt(t, nil, "gzip")
	requireCorrupt(t, []byte{}, "gzip")
	requireCorrupt(t, []byte("hello"), "gzip")
	requireCorrupt(t, []byte(strings.Repeat("x", 100)), "gzip")
	requireCorrupt(t, zlibBytes(t, sampleData(20)), "gzip") // header says gzip, bytes are zlib
}

// Covers: SG-R-RDR-01 SG-I-09
func TestGzipResultDoesNotDependOnReadSizes(t *testing.T) {
	data := sampleData(70000)
	stream := bytes.Join([][]byte{gzipBytes(t, data), gzipBytes(t, data[:123])}, nil)
	want := append(bytes.Clone(data), data[:123]...)

	for _, pattern := range [][]int{{1}, {2}, {3}, {7}, {4096}, {1 << 20}, {1, 7, 4096, 1}, {65536, 1}} {
		r, err := Decode(bytes.NewReader(stream), []string{"gzip"}, loose)
		if err != nil {
			t.Fatal(err)
		}
		var got bytes.Buffer
		buf := make([]byte, 0)
		for i := 0; ; i++ {
			buf = buf[:0]
			buf = append(buf, make([]byte, pattern[i%len(pattern)])...)
			n, err := r.Read(buf)
			got.Write(buf[:n])
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("pattern %v: %v", pattern, err)
			}
		}
		if !bytes.Equal(got.Bytes(), want) {
			t.Fatalf("pattern %v: output differs", pattern)
		}
	}
}
