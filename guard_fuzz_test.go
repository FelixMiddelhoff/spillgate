package spillgate

import (
	"errors"
	"io"
	"testing"
)

// FuzzGuardNeverExceedsTheLimit checks the central property for arbitrary
// stream sizes, limits and read patterns: the guard delivers at most `limit`
// bytes, delivers everything when the stream fits, and otherwise ends with a
// typed output-limit error.
//
// Covers: SG-I-01 SG-I-02 SG-I-03 SG-I-09
func FuzzGuardNeverExceedsTheLimit(f *testing.F) {
	f.Add(uint32(0), uint32(1), []byte{1})
	f.Add(uint32(10), uint32(10), []byte{3, 1, 7})
	f.Add(uint32(11), uint32(10), []byte{255})
	f.Add(uint32(70000), uint32(65536), []byte{0, 200})

	f.Fuzz(func(t *testing.T, size, limit uint32, patternBytes []byte) {
		if limit == 0 {
			t.Skip("zero is not a valid MaxOutput")
		}
		sizes := []int{1}
		for _, b := range patternBytes {
			sizes = append(sizes, int(b)+1)
		}

		g := guardOver(&zerosReader{left: int64(size)}, noLimitsExceptOutput(t, int64(limit)))
		delivered, err := drainPattern(g, sizes)

		if delivered > int64(limit) {
			t.Fatalf("delivered %d > limit %d", delivered, limit)
		}
		switch {
		case int64(size) <= int64(limit):
			if err != io.EOF || delivered != int64(size) {
				t.Fatalf("fitting stream: got (%d, %v)", delivered, err)
			}
		default:
			if !errors.Is(err, ErrOutputLimit) {
				t.Fatalf("oversized stream: got (%d, %v)", delivered, err)
			}
		}
		requireSticky(t, g, err)
	})
}
