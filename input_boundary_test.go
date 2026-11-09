package spillgate_test

import (
	"bytes"
	"compress/gzip"
	"errors"
	"testing"

	"github.com/FelixMiddelhoff/spillgate"
)

// MaxInput is exact: a stream of exactly MaxInput compressed bytes decodes,
// one byte more is input_limit. The test finishes promptly in both directions,
// so an off-by-one cannot hide behind a timeout.
//
// Covers: SG-R-INP-01 SG-R-INP-02
func TestMaxInputBoundaryIsExact(t *testing.T) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write(bytes.Repeat([]byte("boundary "), 200))
	w.Close()
	stream := buf.Bytes()
	n := int64(len(stream))
	limits := spillgate.Limits{MaxOutput: 1 << 20, DisableRatioLimit: true}

	tests := []struct {
		name     string
		maxInput int64
		wantErr  bool
	}{
		{"exactly the stream size", n, false},
		{"one byte more than needed", n + 1, false},
		{"one byte short", n - 1, true},
		{"one byte", 1, true},
	}
	for _, tc := range tests {
		d, err := spillgate.NewDecoder(limits, spillgate.WithMaxInput(tc.maxInput))
		if err != nil {
			t.Fatal(err)
		}
		_, err = d.ReadAll(bytes.NewReader(stream), "gzip")
		if tc.wantErr != errors.Is(err, spillgate.ErrInputLimit) || (!tc.wantErr && err != nil) {
			t.Errorf("%s: MaxInput %d, stream %d bytes: err = %v", tc.name, tc.maxInput, n, err)
		}
	}
}
