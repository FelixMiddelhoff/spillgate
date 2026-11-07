package spillgate

import (
	"bytes"
	"io"
	"sync"
	"testing"

	"github.com/FelixMiddelhoff/spillgate/internal/corpus"
)

// Helpers for the advisory regression tests (cve_*_test.go). Every test there
// names the advisory it answers; the map of advisories, their primary sources
// and the reasoning is kept in the planning notes (spillgate-cve-map.md).

// gigabyteMatches makes ZerosDeflate decode to about 1 GiB.
const gigabyteMatches = 4_161_000

var (
	bombMu    sync.Mutex
	bombCache = map[string][]byte{}
)

// bombStream returns a stream of about 1 GiB of zeros in the given generator
// codec ("gzip", "zlib" or "raw"), built once per test run.
func bombStream(codec string) []byte {
	bombMu.Lock()
	defer bombMu.Unlock()
	if stream, ok := bombCache[codec]; ok {
		return stream
	}
	stream, err := corpus.Generate(corpus.Zeros(codec, gigabyteMatches))
	if err != nil {
		panic(err)
	}
	bombCache[codec] = stream
	return stream
}

// bombCodec describes one way to carry a zeros bomb.
type bombCodec struct {
	name     string // generator codec
	encoding string // Content-Encoding that names it
}

var bombCodecs = []bombCodec{{"gzip", "gzip"}, {"zlib", "deflate"}, {"raw", "deflate"}}

// repeatedLines returns n copies of one header field value.
func repeatedLines(line string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = line
	}
	return out
}

// kindOf returns the outcome class of an error, "ok" for nil and io.EOF.
func kindOf(err error) string {
	if err == nil || err == io.EOF {
		return "ok"
	}
	if e, ok := err.(*Error); ok {
		return e.Kind.String()
	}
	return "other: " + err.Error()
}

// readSizePatterns are the read buffer sizes every streaming advisory is
// replayed with (SG-R-RDR-01): byte by byte, 64 KiB, a buffer larger than the
// limit, and a fixed mixed sequence.
var readSizePatterns = map[string][]int{
	"1 byte":     {1},
	"64 KiB":     {64 << 10},
	"huge":       {8 << 20},
	"mixed":      {1, 7, 4096, 3, 65536, 2, 100000},
	"odd primes": {13, 257, 4099},
}

// chunkedSource hands out its data in pieces of at most `chunk` bytes, the way
// a network connection delivers a body.
type chunkedSource struct {
	data  []byte
	chunk int
}

func (c *chunkedSource) Read(p []byte) (int, error) {
	if len(c.data) == 0 {
		return 0, io.EOF
	}
	n := min(len(p), c.chunk, len(c.data))
	copy(p, c.data[:n])
	c.data = c.data[n:]
	return n, nil
}

func newChunkedSource(data []byte, chunk int) io.Reader {
	return &chunkedSource{data: bytes.Clone(data), chunk: chunk}
}

// requireOutputLimitAfter reads r with the pattern and requires exactly
// `limit` bytes followed by an output-limit error.
func requireOutputLimitAfter(t *testing.T, label string, r io.Reader, pattern []int, limit int64) {
	t.Helper()
	delivered, err := drainPattern(r, pattern)
	if delivered != limit || kindOf(err) != "output_limit" {
		t.Fatalf("%s: delivered %d bytes then %v, want exactly %d bytes then output_limit", label, delivered, err, limit)
	}
}
