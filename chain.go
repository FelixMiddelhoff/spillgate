package spillgate

import (
	"errors"
	"io"
)

// chainReader is the reader a Decoder returns. It sits on top of the last
// layer's guard and adds what only the whole chain can check: the end-to-end
// ratio (SG-R-RAT-03) and the lifecycle (SG-R-RDR-06).
type chainReader struct {
	top     io.Reader   // guard of the last layer
	source  *inputMeter // meter of layer 1: what the chain took from the caller's source
	limits  effectiveLimits
	closers []io.Closer // codec readers that need releasing

	produced int64 // bytes delivered to the caller
	done     error // sticky terminal condition
	closed   bool
}

// Read implements io.Reader. Bytes may be returned together with a terminal
// error; treat any error as failure of the whole body.
func (c *chainReader) Read(p []byte) (int, error) {
	if c.closed {
		return 0, ErrClosed
	}
	if c.done != nil {
		return 0, c.done
	}
	n, err := c.top.Read(p)
	c.produced += int64(n)

	// A layer that already failed has reported its own, more specific error.
	// The end-to-end check only judges streams that are still fine or just ended.
	layerFailed := err != nil && !errors.Is(err, io.EOF)
	if n > 0 && !layerFailed && c.limits.ratioExceeded(c.produced, c.source.Consumed()) {
		c.done = &Error{Kind: KindRatioLimit, Limit: c.limits.maxRatio,
			Cause: errors.New("end-to-end expansion over the whole chain")}
		return n, c.done
	}
	if err != nil {
		c.done = err
	}
	return n, err
}

// Close releases the codecs of all layers. It is idempotent, never closes the
// caller's source, and makes later reads fail with ErrClosed.
func (c *chainReader) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true

	var first error
	for _, closer := range c.closers {
		if err := closer.Close(); err != nil && first == nil {
			first = err
		}
	}
	c.closers = nil
	return first
}
