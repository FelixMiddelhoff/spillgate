package spillgate

import (
	"errors"
	"fmt"
)

// Kind classifies why decoding was refused or failed. The names returned by
// String are the outcome classes of spec/SPEC.md section 2 and are used
// verbatim by the conformance corpus.
type Kind uint8

// The zero Kind is deliberately not a valid class, so an uninitialized Error
// is easy to spot.
const (
	// KindInvalidLimits: the Limits given by the caller are unusable (SG-R-LIM-*).
	KindInvalidLimits Kind = iota + 1
	// KindOutputLimit: a layer would produce more than MaxOutput bytes (SG-R-LAY-03).
	KindOutputLimit
	// KindRatioLimit: a layer expands more than MaxRatio times its input (SG-R-RAT-01).
	KindRatioLimit
	// KindLayerLimit: the Content-Encoding chain is too long (SG-R-HDR-06, SG-R-HDR-11).
	KindLayerLimit
	// KindInputLimit: the codec needs more compressed bytes than MaxInput (SG-R-INP-01).
	KindInputLimit
	// KindMemoryLimit: a stream asks for a decoder window above the cap (SG-R-CDC-04, SG-R-CDC-05).
	KindMemoryLimit
	// KindUnsupportedEncoding: a well-formed encoding name that is not supported (SG-R-HDR-08).
	KindUnsupportedEncoding
	// KindMalformedEncoding: the Content-Encoding value itself is invalid (SG-R-HDR-02..04).
	KindMalformedEncoding
	// KindCorrupt: the compressed stream is invalid or truncated (SG-R-CDC-06).
	KindCorrupt
	// KindInternal: a codec or source broke its contract or panicked (SG-R-CDC-08, SG-R-RDR-03).
	KindInternal
	// KindCanceled: the caller's context ended (SG-R-API-04).
	KindCanceled
	// KindSource: reading from the caller's source failed (SG-R-RDR-05).
	KindSource
)

var kindNames = map[Kind]string{
	KindInvalidLimits:       "invalid_limits",
	KindOutputLimit:         "output_limit",
	KindRatioLimit:          "ratio_limit",
	KindLayerLimit:          "layer_limit",
	KindInputLimit:          "input_limit",
	KindMemoryLimit:         "memory_limit",
	KindUnsupportedEncoding: "unsupported_encoding",
	KindMalformedEncoding:   "malformed_encoding",
	KindCorrupt:             "corrupt",
	KindInternal:            "internal",
	KindCanceled:            "canceled",
	KindSource:              "source_error",
}

// String returns the outcome class name, for example "output_limit".
func (k Kind) String() string {
	if name, ok := kindNames[k]; ok {
		return name
	}
	return fmt.Sprintf("kind(%d)", uint8(k))
}

// Error is the single error type spillgate returns for refusals and failures.
// Use errors.Is with one of the Err* sentinels, or errors.As to inspect Kind.
type Error struct {
	// Kind is the outcome class.
	Kind Kind
	// Layer is the 1-based index of the failing layer (layer 1 reads the
	// source, see spec section 2), or 0 when no layer is involved.
	Layer int
	// Limit is the limit that was exceeded, when the Kind has one.
	Limit int64
	// Cause is the underlying error, if any. It is never attacker-controlled
	// text beyond what SG-R-HDR-13 allows.
	Cause error
}

// Sentinels for errors.Is. They match any *Error of the same Kind; if the
// target names a Layer, the layer must match as well.
var (
	ErrInvalidLimits       error = &Error{Kind: KindInvalidLimits}
	ErrOutputLimit         error = &Error{Kind: KindOutputLimit}
	ErrRatioLimit          error = &Error{Kind: KindRatioLimit}
	ErrLayerLimit          error = &Error{Kind: KindLayerLimit}
	ErrInputLimit          error = &Error{Kind: KindInputLimit}
	ErrMemoryLimit         error = &Error{Kind: KindMemoryLimit}
	ErrUnsupportedEncoding error = &Error{Kind: KindUnsupportedEncoding}
	ErrMalformedEncoding   error = &Error{Kind: KindMalformedEncoding}
	ErrCorrupt             error = &Error{Kind: KindCorrupt}
	ErrInternal            error = &Error{Kind: KindInternal}
	ErrCanceled            error = &Error{Kind: KindCanceled}
	ErrSource              error = &Error{Kind: KindSource}
)

// ErrClosed is returned by reads after Close (SG-R-RDR-06). It is not an
// outcome class of the stream, so it is a plain error.
var ErrClosed = errors.New("spillgate: reader is closed")

// Error describes the failure in one line without echoing untrusted data.
func (e *Error) Error() string {
	msg := "spillgate: " + e.Kind.String()
	if e.Layer > 0 {
		msg += fmt.Sprintf(" in layer %d", e.Layer)
	}
	if e.Limit > 0 {
		msg += fmt.Sprintf(" (limit %d)", e.Limit)
	}
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

// Unwrap exposes the underlying cause to errors.Is and errors.As.
func (e *Error) Unwrap() error { return e.Cause }

// Is makes the Err* sentinels match by Kind (and by Layer when the target
// names one), regardless of the other fields.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	if !ok || t.Kind != e.Kind {
		return false
	}
	return t.Layer == 0 || t.Layer == e.Layer
}

// withLayer returns err with its Layer set when err is an *Error that does
// not name a layer yet. Other errors are returned unchanged.
func withLayer(err error, layer int) error {
	var e *Error
	if !errors.As(err, &e) || e.Layer != 0 {
		return err
	}
	stamped := *e
	stamped.Layer = layer
	return &stamped
}
