package spillgate

import (
	"fmt"
	"strconv"
	"strings"
)

// Hard bounds of the Content-Encoding header, independent of Limits
// (SG-R-HDR-02, SG-R-HDR-04, SG-R-HDR-06).
const (
	// maxHeaderLength is the longest joined header list accepted, in bytes.
	maxHeaderLength = 1024
	// maxTokenLength is the longest single encoding name accepted, in bytes.
	maxTokenLength = 32
	// maxElements is the most non-empty list elements accepted, identity included.
	maxElements = 16
	// maxQuotedBytes is how much attacker-controlled text an error message may
	// contain (SG-R-HDR-13).
	maxQuotedBytes = 32
)

const identityEncoding = "identity"

// parseContentEncoding turns the Content-Encoding header field values into the
// list of codec names to apply, in decoding order: the first name is layer 1,
// the one that reads the source (SG-R-HDR-12). identity is not part of the result.
//
// The checks run in the order the specification fixes, so the outcome class is
// the same for every implementation even when a header has several faults:
//
//  1. total length                         -> malformed_encoding
//  2. element grammar, left to right       -> malformed_encoding
//  3. number of non-empty elements         -> layer_limit
//  4. aliases and support, over all items  -> unsupported_encoding
//  5. number of layers against maxLayers   -> layer_limit
//
// Nothing is decoded before the whole header has passed (SG-R-HDR-09).
func parseContentEncoding(values []string, supported func(name string) bool, maxLayers int) ([]string, error) {
	if err := checkHeaderLength(values); err != nil {
		return nil, err
	}
	elements, err := splitElements(values)
	if err != nil {
		return nil, err
	}
	if len(elements) > maxElements {
		return nil, &Error{Kind: KindLayerLimit, Limit: maxElements,
			Cause: fmt.Errorf("%d encodings listed, at most %d are accepted", len(elements), maxElements)}
	}
	names, err := resolveNames(elements, supported)
	if err != nil {
		return nil, err
	}
	layers := dropIdentity(names)
	if len(layers) > maxLayers {
		return nil, &Error{Kind: KindLayerLimit, Limit: int64(maxLayers),
			Cause: fmt.Errorf("%d encoding layers, at most %d are accepted", len(layers), maxLayers)}
	}
	return reversed(layers), nil
}

// checkHeaderLength enforces SG-R-HDR-02 on the list as it will be joined.
func checkHeaderLength(values []string) error {
	total := 0
	for _, v := range values {
		total += len(v)
	}
	if len(values) > 1 {
		total += len(values) - 1 // the joining commas
	}
	if total > maxHeaderLength {
		return &Error{Kind: KindMalformedEncoding, Limit: maxHeaderLength,
			Cause: fmt.Errorf("Content-Encoding is %d bytes long, at most %d are accepted", total, maxHeaderLength)}
	}
	return nil
}

// splitElements joins the field values into one list (SG-R-HDR-01), splits it
// at commas, trims space and tab, ignores empty elements (SG-R-HDR-03) and
// returns the remaining names in lower case after checking their grammar
// (SG-R-HDR-04, SG-R-HDR-05).
func splitElements(values []string) ([]string, error) {
	var elements []string
	for _, part := range strings.Split(strings.Join(values, ","), ",") {
		part = strings.Trim(part, " \t")
		if part == "" {
			continue
		}
		if !isValidToken(part) {
			return nil, &Error{Kind: KindMalformedEncoding,
				Cause: fmt.Errorf("invalid encoding name %s", quoteUntrusted(part))}
		}
		elements = append(elements, strings.ToLower(part)) // safe: only ASCII passed the grammar
	}
	return elements, nil
}

// isValidToken reports whether s matches [A-Za-z0-9][A-Za-z0-9._-]{0,31}.
func isValidToken(s string) bool {
	if len(s) == 0 || len(s) > maxTokenLength || !isAlphanumeric(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !isAlphanumeric(c) && c != '.' && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

func isAlphanumeric(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// resolveNames applies the alias table (SG-R-HDR-07) and checks that every
// name is supported (SG-R-HDR-08, SG-R-HDR-09).
func resolveNames(elements []string, supported func(name string) bool) ([]string, error) {
	names := make([]string, len(elements))
	for i, name := range elements {
		if name == "x-gzip" {
			name = "gzip"
		}
		if name != identityEncoding && !supported(name) {
			return nil, &Error{Kind: KindUnsupportedEncoding,
				Cause: fmt.Errorf("encoding %s is not supported", quoteUntrusted(name))}
		}
		names[i] = name
	}
	return names, nil
}

// dropIdentity removes the no-op encoding (SG-R-HDR-10).
func dropIdentity(names []string) []string {
	var layers []string
	for _, name := range names {
		if name != identityEncoding {
			layers = append(layers, name)
		}
	}
	return layers
}

// reversed returns a copy of names in reverse order (SG-R-HDR-12).
func reversed(names []string) []string {
	out := make([]string, len(names))
	for i, name := range names {
		out[len(names)-1-i] = name
	}
	return out
}

// quoteUntrusted renders attacker-controlled text for an error message: cut to
// maxQuotedBytes, then quoted and escaped so that control characters cannot
// forge log lines (SG-R-HDR-13).
func quoteUntrusted(s string) string {
	if len(s) > maxQuotedBytes {
		return strconv.Quote(s[:maxQuotedBytes]) + "..."
	}
	return strconv.Quote(s)
}
