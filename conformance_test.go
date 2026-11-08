package spillgate_test

import (
	"testing"

	"github.com/FelixMiddelhoff/spillgate/internal/conformance"
)

// The core module runs the conformance corpus with its built-in codecs.
// Vectors that need brotli or zstd are skipped here and run in the testsuite
// module, which has those codecs.

func TestConformanceManifestIsWellFormed(t *testing.T) {
	conformance.CheckManifest(t, conformance.Config{Root: "."})
}

func TestConformance(t *testing.T) {
	conformance.Run(t, conformance.Config{Root: "."})
}
