package spillgate

import (
	"context"
	"errors"
	"fmt"
	"io"
)

// errCodecContract describes a codec that returned an impossible byte count.
var errCodecContract = errors.New("codec returned an invalid byte count")

// layerGuard wraps the output of one decoding layer and enforces everything
// the specification demands of a layer: the output limit, the ratio limit,
// sticky terminal conditions, and containment of misbehaving codecs.
//
// Whatever the codec does, the guard never hands out more than MaxOutput
// bytes in total (SG-I-01), never turns a limit hit into io.EOF (SG-I-02),
// and keeps returning the same terminal condition once one occurred (SG-I-03).
// It is not safe for concurrent use.
type layerGuard struct {
	codec  io.Reader   // the layer's decoder output
	input  *inputMeter // the decoder's input, for consumption and source errors
	layer  int         // 1-based layer index, for error reporting
	limits effectiveLimits
	ctx    context.Context // optional; nil means the reader is never canceled

	produced int64 // bytes the codec has produced and the guard has accounted for
	done     error // sticky terminal condition: io.EOF or an error
}

// canceledError returns a KindCanceled error if ctx has ended, else nil. The
// context's own error stays reachable through errors.Is (SG-R-API-04).
func canceledError(ctx context.Context, layer int) error {
	if ctx == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return &Error{Kind: KindCanceled, Layer: layer, Cause: err}
	}
	return nil
}

// newLayerGuard guards codec, which reads its compressed bytes from input.
func newLayerGuard(codec io.Reader, input *inputMeter, layer int, limits effectiveLimits) *layerGuard {
	return &layerGuard{codec: codec, input: input, layer: layer, limits: limits}
}

// Read implements io.Reader with the guarantees described on layerGuard.
// Bytes may be returned together with the terminal error.
func (g *layerGuard) Read(p []byte) (int, error) {
	if g.done != nil {
		return 0, g.done
	}
	if len(p) == 0 {
		return 0, nil // SG-R-RDR-02: no state change
	}
	if err := canceledError(g.ctx, g.layer); err != nil {
		g.done = err
		return 0, err
	}
	remaining := g.limits.maxOutput - g.produced
	if remaining == 0 {
		return 0, g.probeBeyondLimit()
	}
	if int64(len(p)) > remaining {
		p = p[:remaining] // never let the codec write past the budget
	}

	n, err := g.readCodec(p)
	g.produced += int64(n)
	return n, g.settle(n, err)
}

// probeBeyondLimit is called when the budget is used up. It asks the codec for
// one more byte: if there is one, the limit is exceeded and the byte is thrown
// away; if the stream ends cleanly, the output was exactly at the limit and
// everything is fine (SG-R-LAY-03). The codec's own validation, such as a
// trailer checksum, still runs and can still report corruption.
func (g *layerGuard) probeBeyondLimit() error {
	var probe [1]byte
	n, err := g.readCodec(probe[:])
	switch {
	case n > 0:
		g.done = &Error{Kind: KindOutputLimit, Layer: g.layer, Limit: g.limits.maxOutput}
	case err == io.EOF: // exactly io.EOF as the io.Reader contract says; a wrapped EOF is an error
		g.done = io.EOF
	default:
		g.done = g.classify(err)
	}
	return g.done
}

// settle turns the result of one codec read into the guard's state. The ratio
// is checked before the codec's own end condition because the bytes that broke
// the ratio were produced first (SG-R-LAY-07).
func (g *layerGuard) settle(n int, err error) error {
	if n > 0 && g.limits.ratioExceeded(g.produced, g.input.Consumed()) {
		g.done = &Error{Kind: KindRatioLimit, Layer: g.layer, Limit: g.limits.maxRatio}
		return g.done
	}
	switch {
	case err == nil:
		return nil
	case err == io.EOF: // exactly io.EOF as the io.Reader contract says; a wrapped EOF is an error
		g.done = io.EOF
	default:
		g.done = g.classify(err)
	}
	return g.done
}

// readCodec reads from the codec, retrying a bounded number of times if it
// returns nothing at all (SG-R-RDR-03).
func (g *layerGuard) readCodec(p []byte) (int, error) {
	for range maxEmptyReads {
		n, err := g.callCodec(p)
		if n > 0 || err != nil {
			return n, err
		}
	}
	return 0, &Error{Kind: KindInternal, Layer: g.layer, Cause: io.ErrNoProgress}
}

// callCodec performs one codec read and contains its failures: a panic or an
// impossible byte count becomes KindInternal (SG-R-CDC-08). Only the panic's
// type is reported, never its value, which may contain attacker data.
func (g *layerGuard) callCodec(p []byte) (n int, err error) {
	defer func() {
		if r := recover(); r != nil {
			n = 0
			err = &Error{Kind: KindInternal, Layer: g.layer, Cause: fmt.Errorf("codec panicked (%T)", r)}
		}
	}()
	n, err = g.codec.Read(p)
	if n < 0 || n > len(p) {
		return 0, &Error{Kind: KindInternal, Layer: g.layer, Cause: errCodecContract}
	}
	// End of the codec step: a codec that took the MaxInput+1-th byte has
	// violated SG-R-INP-01, whatever it returned, and whether or not it
	// looks at the source again. The violation came before this step's output.
	if limitErr := g.input.checkTaken(); limitErr != nil {
		return 0, limitErr
	}
	return n, err
}

// classify maps an error from the codec to the outcome class it stands for:
// our own errors pass through, a failing source is KindSource, anything else
// means the compressed stream itself is invalid or truncated.
func (g *layerGuard) classify(err error) error {
	var known *Error
	if errors.As(err, &known) {
		return withLayer(known, g.layer)
	}
	if srcErr := g.input.SourceErr(); srcErr != nil {
		return &Error{Kind: KindSource, Layer: g.layer, Cause: srcErr}
	}
	return &Error{Kind: KindCorrupt, Layer: g.layer, Cause: err}
}
