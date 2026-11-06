package spillgate

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// failAfter returns a source that serves stream[:n] and then fails with errBoom.
func failAfter(stream []byte, n int) io.Reader {
	return io.MultiReader(bytes.NewReader(stream[:n]), readerFunc(func([]byte) (int, error) { return 0, errBoom }))
}

// Truncation or a failing source inside every part of a gzip header.
// Covers: SG-R-CDC-02 SG-R-CDC-06 SG-R-RDR-05
func TestGzipHeaderPartsTruncatedOrFailing(t *testing.T) {
	stream := gzipMember(t, gzipHeader{
		extra: bytes.Repeat([]byte("e"), 700), name: []byte("name"), comment: []byte("comment"), headerCRC: true,
	}, sampleData(100))
	headerEnd := gzipFixedHeaderSize + 2 + 700 + len("name") + 1 + len("comment") + 1 + 2

	for cut := 0; cut < headerEnd; cut++ {
		if _, err := decodeOne(stream[:cut], "gzip"); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("truncated at %d: %v", cut, err)
		}
		if _, err := DecodeAll(failAfter(stream, cut), []string{"gzip"}, loose); !errors.Is(err, ErrSource) || !errors.Is(err, errBoom) {
			t.Fatalf("source failing at %d: %v", cut, err)
		}
	}
	// The untouched stream still decodes.
	if _, err := decodeOne(stream, "gzip"); err != nil {
		t.Fatal(err)
	}
}

// A source that fails right after a complete stream is a source error.
// Covers: SG-R-RDR-05
func TestSourceFailureAfterTheLastByteIsReported(t *testing.T) {
	for encoding, stream := range map[string][]byte{
		"gzip":    gzipBytes(t, sampleData(100)),
		"deflate": zlibBytes(t, sampleData(100)),
	} {
		if _, err := DecodeAll(failAfter(stream, len(stream)), []string{encoding}, loose); !errors.Is(err, ErrSource) {
			t.Errorf("%s: %v", encoding, err)
		}
	}
}

// The codec readers keep their terminal condition on their own, independent of
// the guard around them.
func TestCodecReadersAreStickyOnTheirOwn(t *testing.T) {
	tests := []struct {
		name   string
		codec  Codec
		stream []byte
	}{
		{"gzip good", gzipCodec{}, gzipBytes(t, sampleData(10))},
		{"gzip bad", gzipCodec{}, []byte("not gzip at all")},
		{"deflate good", deflateCodec{}, zlibBytes(t, sampleData(10))},
		{"deflate bad", deflateCodec{}, []byte("not deflate at all")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reader, err := tc.codec.NewReader(newInputMeter(bytes.NewReader(tc.stream), 0, 1))
			if err != nil {
				t.Fatal(err)
			}
			_, first := io.Copy(io.Discard, reader)
			buf := make([]byte, 8)
			for range 3 {
				n, err := reader.Read(buf)
				if n != 0 || err == nil {
					t.Fatalf("not sticky: (%d, %v)", n, err)
				}
				if first != nil && err != first { // io.Copy hides a clean EOF
					t.Fatalf("error changed: first %v, then %v", first, err)
				}
			}
			if closer, ok := reader.(io.Closer); ok {
				if err := closer.Close(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestReplaySourceServesThePrefixFirst(t *testing.T) {
	meter := newInputMeter(bytes.NewReader([]byte("cdef")), 0, 1)
	r := &replaySource{prefix: [2]byte{'a', 'b'}, src: meter}

	if n, err := r.Read(nil); n != 0 || err != nil {
		t.Fatalf("zero-length read: (%d, %v)", n, err)
	}
	one := make([]byte, 1)
	if n, _ := r.Read(one); n != 1 || one[0] != 'a' {
		t.Fatalf("first byte: %q", one)
	}
	if b, _ := r.ReadByte(); b != 'b' {
		t.Fatalf("second byte: %q", b)
	}
	rest, err := io.ReadAll(r)
	if err != nil || string(rest) != "cdef" {
		t.Fatalf("rest: %q, %v", rest, err)
	}
	if meter.Consumed() != 4 {
		t.Fatalf("replayed bytes were counted again: consumed %d", meter.Consumed())
	}
}

func TestDecodeAllRejectsInvalidLimits(t *testing.T) {
	if _, err := DecodeAll(bytes.NewReader(nil), nil, Limits{}); !errors.Is(err, ErrInvalidLimits) {
		t.Fatalf("got %v", err)
	}
}

func TestDecodeAllWithInvalidOptionsFails(t *testing.T) {
	if _, err := DecodeAll(bytes.NewReader(nil), nil, Limits{MaxOutput: 1}, WithMaxInput(0)); !errors.Is(err, ErrInvalidLimits) {
		t.Fatalf("got %v", err)
	}
}
