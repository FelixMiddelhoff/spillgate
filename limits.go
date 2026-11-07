package spillgate

import "fmt"

// Defaults for optional Limits fields left at zero (SG-R-LIM-03..05).
// MaxOutput has no default on purpose (SG-R-LIM-01).
const (
	// DefaultMaxLayers is the longest Content-Encoding chain accepted by default.
	DefaultMaxLayers = 5
	// DefaultMaxRatio is the default expansion limit: output bytes per input byte.
	//
	// Measured with the standard library's gzip: the best a deflate stream can
	// do on zeros is about 1029:1, repetitive JSON reaches about 350:1. 1000
	// therefore stops every maximal deflate bomb while staying well above
	// ordinary data; stronger codecs (brotli, zstd) and chains can reach far
	// higher ratios and are caught earlier by it. Callers with unusually
	// sparse but legitimate data can raise MaxRatio or set DisableRatioLimit.
	DefaultMaxRatio = 1000
	// DefaultRatioGrace is the output size below which the ratio is not checked,
	// so that tiny inputs cannot trigger false alarms.
	DefaultRatioGrace = 64 << 10
)

// Hard bounds that no configuration can exceed.
const (
	// HardMaxLayers is the highest MaxLayers a caller may ask for.
	HardMaxLayers = 16
	// HardMaxRatio is the highest MaxRatio a caller may ask for.
	HardMaxRatio = 1<<31 - 1
)

// Limits are the restrictions applied to every decoding layer.
//
// There is no unlimited value for MaxOutput and no way to switch it off:
// that is the central design rule of this library (SG-R-LIM-01, SG-R-LIM-07).
// The zero Limits is invalid for exactly that reason.
type Limits struct {
	// MaxOutput is the most bytes any single layer may produce. Required, > 0.
	// Intermediate layers of a chain are bounded by it too (SG-R-LAY-01).
	MaxOutput int64

	// MaxLayers is the longest chain of non-identity encodings.
	// Zero means DefaultMaxLayers. Valid range 1..HardMaxLayers.
	MaxLayers int

	// MaxRatio is the most output bytes a layer may produce per input byte it
	// consumed. Zero means DefaultMaxRatio. Valid range 1..HardMaxRatio.
	// It must be left zero when DisableRatioLimit is set.
	MaxRatio int64

	// RatioGrace is the output size, in bytes, up to which the ratio is not
	// checked. Zero means DefaultRatioGrace (a grace of 1 byte checks the
	// ratio from the first byte on). It must not be negative.
	RatioGrace int64

	// DisableRatioLimit switches the ratio check off. It is the only way to
	// do so; no value of MaxRatio has that effect (SG-R-LIM-04). All other
	// limits stay in force (SG-R-RAT-04).
	DisableRatioLimit bool
}

// Validate reports whether the limits are usable. The error, if any, is an
// *Error of KindInvalidLimits that names the offending field.
func (l Limits) Validate() error {
	_, err := l.resolve()
	return err
}

// effectiveLimits are Limits with defaults applied and all values checked.
// Everything downstream works with this type, so no code path ever sees an
// unvalidated or zero-meaning-unlimited value.
type effectiveLimits struct {
	maxOutput  int64
	maxLayers  int
	maxRatio   int64 // 0 means the ratio check is disabled
	ratioGrace int64
}

// resolve validates l and applies the defaults (SG-R-LIM-08).
func (l Limits) resolve() (effectiveLimits, error) {
	if l.MaxOutput <= 0 {
		return effectiveLimits{}, invalidLimits(
			"MaxOutput must be greater than zero (it has no default and no unlimited value), got %d", l.MaxOutput)
	}

	maxLayers := l.MaxLayers
	if maxLayers == 0 {
		maxLayers = DefaultMaxLayers
	}
	if maxLayers < 1 || maxLayers > HardMaxLayers {
		return effectiveLimits{}, invalidLimits("MaxLayers must be in 1..%d, got %d", HardMaxLayers, l.MaxLayers)
	}

	maxRatio, err := l.resolveRatio()
	if err != nil {
		return effectiveLimits{}, err
	}

	grace := l.RatioGrace
	if grace == 0 {
		grace = DefaultRatioGrace
	}
	if grace < 0 {
		return effectiveLimits{}, invalidLimits("RatioGrace must not be negative, got %d", l.RatioGrace)
	}

	return effectiveLimits{
		maxOutput:  l.MaxOutput,
		maxLayers:  maxLayers,
		maxRatio:   maxRatio,
		ratioGrace: grace,
	}, nil
}

// resolveRatio returns the effective MaxRatio, with 0 meaning "disabled".
func (l Limits) resolveRatio() (int64, error) {
	if l.DisableRatioLimit {
		if l.MaxRatio != 0 {
			return 0, invalidLimits("MaxRatio (%d) contradicts DisableRatioLimit; set only one", l.MaxRatio)
		}
		return 0, nil
	}
	if l.MaxRatio == 0 {
		return DefaultMaxRatio, nil
	}
	if l.MaxRatio < 1 || l.MaxRatio > HardMaxRatio {
		return 0, invalidLimits("MaxRatio must be in 1..%d, got %d", int64(HardMaxRatio), l.MaxRatio)
	}
	return l.MaxRatio, nil
}

// ratioExceeded reports whether a layer that produced `produced` bytes from
// `consumed` input bytes breaks the ratio limit (SG-R-RAT-01).
//
// The test is produced > maxRatio*max(consumed,1), rearranged as
// (produced-1)/maxRatio >= consumed so that it cannot overflow.
func (e effectiveLimits) ratioExceeded(produced, consumed int64) bool {
	if e.maxRatio == 0 || produced <= e.ratioGrace {
		return false
	}
	consumed = max(consumed, 1)
	return (produced-1)/e.maxRatio >= consumed
}

func invalidLimits(format string, args ...any) error {
	return &Error{Kind: KindInvalidLimits, Cause: fmt.Errorf(format, args...)}
}
