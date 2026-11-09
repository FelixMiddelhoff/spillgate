// Package testsuite holds the tests that need more than one module of the
// repository: the conformance corpus with brotli and zstd enabled, and the
// advisory tests that involve those codecs.
package testsuite

import (
	"testing"

	"github.com/FelixMiddelhoff/spillgate"
	"github.com/FelixMiddelhoff/spillgate/br"
	"github.com/FelixMiddelhoff/spillgate/internal/conformance"
	"github.com/FelixMiddelhoff/spillgate/zstd"
)

// config enables every optional codec. A vector's memory_cap, in bytes, is
// turned into each codec's own setting.
func config() conformance.Config {
	return conformance.Config{
		Root:    "..",
		NoSkips: true,
		Codecs: map[string]func(uint64) spillgate.Option{
			"br": func(memoryCap uint64) spillgate.Option {
				if memoryCap == 0 {
					return br.Enable()
				}
				return br.Enable(br.MaxWindowBits(windowBitsWithin(memoryCap)))
			},
			"zstd": func(memoryCap uint64) spillgate.Option {
				if memoryCap == 0 {
					return zstd.Enable()
				}
				return zstd.Enable(zstd.MaxWindowBytes(memoryCap))
			},
		},
	}
}

// windowBitsWithin returns the largest brotli window bits n (10..24) whose
// window, 2^n-16 bytes, fits into limit bytes.
func windowBitsWithin(limit uint64) int {
	bits := br.MinWindowBits
	for n := br.MinWindowBits; n <= br.DefaultMaxWindowBits; n++ {
		if uint64(1)<<n-16 <= limit {
			bits = n
		}
	}
	return bits
}

func TestWindowBitsWithin(t *testing.T) {
	for limit, want := range map[uint64]int{1 << 10: 10, 1 << 20: 20, 1<<21 - 16: 21, 1 << 24: 24, 1 << 40: 24, 5: 10} {
		if got := windowBitsWithin(limit); got != want {
			t.Errorf("windowBitsWithin(%d) = %d, want %d", limit, got, want)
		}
	}
}

func TestConformanceManifestIsWellFormed(t *testing.T) {
	conformance.CheckManifest(t, config())
}

// TestConformance runs every vector, including those for brotli and zstd.
func TestConformance(t *testing.T) {
	conformance.Run(t, config())
}
