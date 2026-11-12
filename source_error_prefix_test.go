package spillgate

import (
	"bytes"
	"errors"
	"io"
	"math/rand"
	"testing"
)

// errLateSource is the error the failing sources below return.
var errLateSource = errors.New("late source failure")

// failingSource delivers stream in pieces of at most chunk bytes and then
// fails with errLateSource instead of io.EOF.
type failingSource struct {
	stream []byte
	chunk  int
	pos    int
}

func (s *failingSource) Read(p []byte) (int, error) {
	if s.pos >= len(s.stream) {
		return 0, errLateSource
	}
	n := min(len(p), s.chunk, len(s.stream)-s.pos)
	copy(p, s.stream[s.pos:s.pos+n])
	s.pos += n
	return n, nil
}

// F1 of the Java port review: when a source (or a lower layer) fails late in
// the stream, the delivered bytes and the outcome must not depend on the
// caller's read sizes, nor on how the source chunks its data. Early failure
// of a guard or of the inflater's refill must not drop bytes that a
// differently sized read would have delivered.
//
// Covers: SG-R-RDR-01 SG-R-LAY-05 SG-R-LAY-06 SG-I-03 SG-I-09
func TestSG_T_RDR_F1_LateSourceErrorDeliversSamePrefixForAllReadSizes(t *testing.T) {
	rnd := rand.New(rand.NewSource(1))
	data := make([]byte, 30000) // not compressible: the late cut is really late
	rnd.Read(data)
	text := sampleData(30000)

	// A lower layer that fails late: the inner gzip loses its last bytes
	// (truncated), the outer layer is intact and ends cleanly.
	inner := gzipBytes(t, data)
	truncatedInner := inner[:len(inner)-12]
	// A lower layer with a bad CRC at its very end.
	badCRC := append([]byte(nil), inner...)
	badCRC[len(badCRC)-8] ^= 0xff

	cases := []struct {
		name      string
		encodings []string
		stream    []byte
		cut       int  // keep this many bytes of stream, then source error (0: keep all)
		fullCut   bool // source error right after the complete stream
	}{
		{"identity", nil, data, len(data) - 5, false},
		{"gzip", []string{"gzip"}, gzipBytes(t, data), -10, false},
		{"gzip-after-complete", []string{"gzip"}, gzipBytes(t, data), 0, true},
		{"deflate-zlib", []string{"deflate"}, zlibBytes(t, text), -6, false},
		{"deflate-raw", []string{"deflate"}, rawDeflateBytes(t, data), -4, false},
		{"chain-gzip-gzip", []string{"gzip", "gzip"}, gzipBytes(t, gzipBytes(t, data)), -10, false},
		{"chain-3", []string{"gzip", "deflate", "gzip"}, gzipBytes(t, zlibBytes(t, gzipBytes(t, text))), -10, false},
		{"lower-layer-truncated", []string{"gzip", "gzip"}, gzipBytes(t, truncatedInner), 0, true},
		{"lower-layer-bad-crc", []string{"gzip", "gzip"}, gzipBytes(t, badCRC), 0, true},
	}
	patterns := [][]int{{1}, {2}, {7}, {4096}, {65536}, {1 << 20}, {1, 7, 4096, 1}, {20000, 3}}
	chunks := []int{1, 13, 4096, 1 << 30}
	limits := Limits{MaxOutput: 1 << 30, MaxRatio: 1 << 20}

	for _, tc := range cases {
		stream := tc.stream
		if !tc.fullCut {
			cut := tc.cut
			if cut < 0 {
				cut += len(stream)
			}
			stream = stream[:cut]
		}
		var refBytes []byte
		var refErr error
		first := true
		for _, chunk := range chunks {
			for _, pattern := range patterns {
				src := &failingSource{stream: stream, chunk: chunk}
				r, err := Decode(src, tc.encodings, limits)
				if err != nil {
					t.Fatalf("%s: Decode: %v", tc.name, err)
				}
				got, gotErr := drainPatternCollect(r, pattern)
				requireSticky(t, r, gotErr)
				r.Close()
				if gotErr == nil || gotErr == io.EOF {
					t.Fatalf("%s chunk %d pattern %v: want an error, got %v", tc.name, chunk, pattern, gotErr)
				}
				if first {
					refBytes, refErr, first = got, gotErr, false
					if len(refBytes) == 0 && tc.name != "lower-layer-bad-crc" {
						t.Fatalf("%s: reference delivered nothing; the test would prove nothing", tc.name)
					}
					continue
				}
				if !bytes.Equal(got, refBytes) {
					t.Fatalf("%s chunk %d pattern %v: delivered %d bytes, reference %d (prefix depends on chunking)",
						tc.name, chunk, pattern, len(got), len(refBytes))
				}
				var a, b *Error
				if errors.As(gotErr, &a) != errors.As(refErr, &b) || (a != nil && a.Kind != b.Kind) || errors.Is(gotErr, errLateSource) != errors.Is(refErr, errLateSource) {
					t.Fatalf("%s chunk %d pattern %v: outcome %v differs from reference %v", tc.name, chunk, pattern, gotErr, refErr)
				}
			}
		}
	}
}
