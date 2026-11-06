package spillgate

import (
	"errors"
	"fmt"
	"io"
)

// Source is the input a Codec reads from. It is an io.Reader that is also an
// io.ByteReader, so a codec built on compress/flate does not need a
// read-ahead buffer of its own, and it counts exactly what the codec takes
// (SG-R-RAT-02). Codecs must read only from it.
type Source interface {
	io.Reader
	io.ByteReader
}

// Codec decodes one Content-Encoding. Built-in codecs cover gzip and deflate;
// the br and zstd modules and callers add others with WithCodec.
//
// Whatever a Codec does, spillgate bounds its output, ratio and panics
// (SG-R-CDC-01), so even a careless codec cannot defeat the limits.
type Codec interface {
	// NewReader returns a reader that yields the decoded bytes of the
	// compressed stream in src. It must not read from src yet: validation of
	// the stream happens on the first Read, so that construction never
	// touches the caller's data (SG-R-API-03).
	//
	// If the returned reader also implements io.Closer, it is closed when the
	// decoding chain is closed (SG-R-RDR-06). Closing must not close src.
	//
	// Errors that should surface as a specific outcome class (for example
	// KindMemoryLimit) may be returned as *Error; any other error from Read
	// means the stream is invalid or truncated and is reported as KindCorrupt.
	NewReader(src Source) (io.Reader, error)
}

// ErrInvalidOption is returned for unusable options, such as registering a
// codec under a reserved name. It is a programming error, not a stream error.
var ErrInvalidOption = errors.New("spillgate: invalid option")

// ErrNilSource is returned when no source reader was given.
var ErrNilSource = errors.New("spillgate: nil source")

// Names that extension codecs may not take: the built-in codecs and the alias
// resolved by the header parser (SG-R-CDC-09, SG-R-HDR-07).
var reservedCodecNames = map[string]bool{
	identityEncoding: true,
	"gzip":           true,
	"deflate":        true,
	"x-gzip":         true,
}

// checkCodecRegistration validates a WithCodec registration against the names
// already taken.
func checkCodecRegistration(name string, codec Codec, taken map[string]Codec) error {
	switch {
	case codec == nil:
		return fmt.Errorf("%w: codec %q is nil", ErrInvalidOption, name)
	case !isValidToken(name) || name != toLowerASCII(name):
		return fmt.Errorf("%w: codec name %s must be a lower-case token", ErrInvalidOption, quoteUntrusted(name))
	case reservedCodecNames[name]:
		return fmt.Errorf("%w: codec name %q is reserved", ErrInvalidOption, name)
	}
	if _, dup := taken[name]; dup {
		return fmt.Errorf("%w: codec %q is registered twice", ErrInvalidOption, name)
	}
	return nil
}

// toLowerASCII lower-cases ASCII letters only; callers have validated the
// string as a token, so nothing else can occur.
func toLowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
