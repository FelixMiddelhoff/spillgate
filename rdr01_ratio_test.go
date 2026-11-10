package spillgate_test

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"testing"

	"github.com/FelixMiddelhoff/spillgate"
)

// SG-R-RDR-01 allows one difference between read sizes: before a ratio_limit
// error the delivered prefix may differ by at most the tolerance T of
// SG-R-RAT-02 (64 KiB). Everything delivered is a prefix of the same stream,
// and the outcome class never changes.
//
// Covers: SG-R-RDR-01 SG-R-RAT-02
func TestRatioErrorPrefixDependsOnReadSizeOnlyWithinTheTolerance(t *testing.T) {
	var buf bytes.Buffer
	w, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	w.Write(make([]byte, 20<<20))
	w.Close()
	stream := buf.Bytes()

	limits := spillgate.Limits{MaxOutput: 1 << 30, MaxRatio: 1000, RatioGrace: 1}
	lengths := map[int]int64{}
	for _, size := range []int{1, 4096, 1 << 20} {
		r, err := spillgate.Decode(bytes.NewReader(stream), []string{"gzip"}, limits)
		if err != nil {
			t.Fatal(err)
		}
		chunk := make([]byte, size)
		var delivered int64
		for {
			n, err := r.Read(chunk)
			for _, b := range chunk[:n] {
				if b != 0 {
					t.Fatalf("read size %d: delivered bytes are not a prefix of the zero stream", size)
				}
			}
			delivered += int64(n)
			if err != nil {
				if !errors.Is(err, spillgate.ErrRatioLimit) || err == io.EOF {
					t.Fatalf("read size %d: got %v, want a ratio limit", size, err)
				}
				break
			}
		}
		lengths[size] = delivered
	}
	lo, hi := lengths[1], lengths[1]
	for _, n := range lengths {
		lo, hi = min(lo, n), max(hi, n)
	}
	if hi-lo > 64<<10 {
		t.Fatalf("delivered prefixes %v differ by %d bytes, more than the 64 KiB tolerance", lengths, hi-lo)
	}
}
