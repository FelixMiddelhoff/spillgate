package spillgate

import (
	"errors"
	"io"
	"testing"
)

// zerosReader yields `left` zero bytes and then io.EOF.
type zerosReader struct{ left int64 }

func (z *zerosReader) Read(p []byte) (int, error) {
	if z.left == 0 {
		return 0, io.EOF
	}
	n := min(int64(len(p)), z.left)
	clear(p[:n])
	z.left -= n
	return int(n), nil
}

// readerFunc turns a function into an io.Reader.
type readerFunc func(p []byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

// countingSource hands out `size` bytes and records how many it gave away.
type countingSource struct {
	size   int
	handed int
}

func (c *countingSource) Read(p []byte) (int, error) {
	if c.handed >= c.size {
		return 0, io.EOF
	}
	n := min(len(p), c.size-c.handed)
	clear(p[:n])
	c.handed += n
	return n, nil
}

// noLimitsExceptOutput returns resolved limits with the ratio check off, so
// tests of the output limit cannot be disturbed by the ratio.
func noLimitsExceptOutput(t *testing.T, maxOutput int64) effectiveLimits {
	t.Helper()
	return mustResolve(t, Limits{MaxOutput: maxOutput, DisableRatioLimit: true})
}

func mustResolve(t *testing.T, l Limits) effectiveLimits {
	t.Helper()
	e, err := l.resolve()
	if err != nil {
		t.Fatalf("resolve(%+v): %v", l, err)
	}
	return e
}

// guardOver wraps codec in a layerGuard whose input meter reads from an empty
// source. Suitable when the test does not care about consumed input.
func guardOver(codec io.Reader, limits effectiveLimits) *layerGuard {
	return newLayerGuard(codec, newInputMeter(&zerosReader{}, 0, 1), 1, limits)
}

// drain reads r with buffers of readSize bytes until the first error and
// returns the number of bytes delivered and that error.
func drain(r io.Reader, readSize int) (delivered int64, err error) {
	buf := make([]byte, readSize)
	for {
		n, err := r.Read(buf)
		delivered += int64(n)
		if err != nil {
			return delivered, err
		}
	}
}

// drainPattern is like drain but cycles through the given read sizes.
func drainPattern(r io.Reader, sizes []int) (delivered int64, err error) {
	buffers := make([][]byte, len(sizes)) // one buffer per size, reused
	for i, size := range sizes {
		buffers[i] = make([]byte, size)
	}
	for i := 0; ; i++ {
		n, err := r.Read(buffers[i%len(buffers)])
		delivered += int64(n)
		if err != nil {
			return delivered, err
		}
	}
}

// requireSticky checks that a reader keeps returning want and no data
// (SG-R-LAY-05).
func requireSticky(t *testing.T, r io.Reader, want error) {
	t.Helper()
	buf := make([]byte, 16)
	for range 3 {
		n, err := r.Read(buf)
		if n != 0 || !errors.Is(err, want) {
			t.Fatalf("not sticky: Read = (%d, %v), want (0, %v)", n, err, want)
		}
	}
}
