package testsuite

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"math/rand"
	"strings"
	"testing"

	"github.com/FelixMiddelhoff/spillgate"
	"github.com/FelixMiddelhoff/spillgate/internal/corpus"
	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"go.uber.org/goleak"
)

// Differential tests: encode with a reference encoder, decode with spillgate,
// compare with the original. Valid data inside the limits must come back
// byte for byte whatever the codec, chain depth and read pattern; the same data
// with a limit one byte too small must end in output_limit, never in a
// short success.

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

// encoders maps a Content-Encoding name to a reference encoder.
var encoders = map[string]func([]byte) []byte{
	"gzip": func(b []byte) []byte {
		var o bytes.Buffer
		w := gzip.NewWriter(&o)
		w.Write(b)
		w.Close()
		return o.Bytes()
	},
	"deflate": func(b []byte) []byte {
		var o bytes.Buffer
		w := zlib.NewWriter(&o)
		w.Write(b)
		w.Close()
		return o.Bytes()
	},
	"raw-deflate": func(b []byte) []byte {
		var o bytes.Buffer
		w, _ := flate.NewWriter(&o, flate.BestCompression)
		w.Write(b)
		w.Close()
		return o.Bytes()
	},
	"br": func(b []byte) []byte {
		var o bytes.Buffer
		w := brotli.NewWriterLevel(&o, 5)
		w.Write(b)
		w.Close()
		return o.Bytes()
	},
	"zstd": func(b []byte) []byte {
		var o bytes.Buffer
		w, _ := zstd.NewWriter(&o, zstd.WithEncoderConcurrency(1))
		w.Write(b)
		w.Close()
		return o.Bytes()
	},
}

// payloads returns varied plain data: empty, tiny, random, text, zeros, mixed.
func payloads(rng *rand.Rand) [][]byte {
	random := func(n int) []byte { b := make([]byte, n); rng.Read(b); return b }
	text := []byte(strings.Repeat("the quick brown fox jumps over the lazy dog\n", 3000))
	mixed := append(append(random(5000), make([]byte, 40000)...), text[:7000]...)
	return [][]byte{{}, {0}, []byte("a"), random(1), random(777), random(70000), text, make([]byte, 100000), mixed}
}

func chainName(n string) string {
	if n == "raw-deflate" {
		return "deflate"
	}
	return n
}

func TestDifferentialSingleLayer(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	patterns := [][]int{{1}, {7, 1000}, {64 << 10}, {3, 0, 5}}
	for name, enc := range encoders {
		for i, p := range payloads(rng) {
			stream := enc(p)
			limits := spillgate.Limits{MaxOutput: int64(len(p)) + 1, DisableRatioLimit: true}
			d := allCodecs(t, limits)
			for _, sizes := range patterns {
				r, err := d.Reader(bytes.NewReader(stream), chainName(name))
				if err != nil {
					t.Fatal(err)
				}
				var got bytes.Buffer
				buf := make([]byte, 4096)
				for j := 0; ; j++ {
					n, err := r.Read(buf[:min(len(buf), max(sizes[j%len(sizes)], 0))])
					got.Write(buf[:n])
					if err == io.EOF {
						break
					}
					if err != nil {
						t.Fatalf("%s #%d: %v", name, i, err)
					}
				}
				r.Close()
				if !bytes.Equal(got.Bytes(), p) {
					t.Fatalf("%s #%d pattern %v: output differs (%d vs %d bytes)", name, i, sizes, got.Len(), len(p))
				}
			}
			if len(p) == 0 {
				continue
			}
			tight := spillgate.Limits{MaxOutput: int64(len(p)), DisableRatioLimit: true}
			if out, err := allCodecs(t, tight).ReadAll(bytes.NewReader(stream), chainName(name)); err != nil || !bytes.Equal(out, p) {
				t.Errorf("%s #%d: exact limit must succeed: %v", name, i, err)
			}
			under := spillgate.Limits{MaxOutput: int64(len(p)) - 1, DisableRatioLimit: true}
			if under.MaxOutput == 0 {
				continue
			}
			if _, err := allCodecs(t, under).ReadAll(bytes.NewReader(stream), chainName(name)); kind(err) != "output_limit" {
				t.Errorf("%s #%d: limit-1 gave %s", name, i, kind(err))
			}
		}
	}
}

func TestDifferentialChains(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	names := []string{"gzip", "deflate", "br", "zstd"}
	for round := 0; round < 60; round++ {
		p := payloads(rng)[rng.Intn(9)]
		depth := 1 + rng.Intn(3)
		layers := make([]string, depth) // header order: first applied first
		stream := p
		for i := range layers {
			layers[i] = names[rng.Intn(len(names))]
			stream = encoders[layers[i]](stream)
		}
		limits := spillgate.Limits{MaxOutput: int64(len(stream)) + int64(len(p)) + 1024, DisableRatioLimit: true}
		out, err := allCodecs(t, limits).ReadAll(bytes.NewReader(stream), layers...)
		if err != nil || !bytes.Equal(out, p) {
			t.Fatalf("chain %v: err=%v equal=%v", layers, err, bytes.Equal(out, p))
		}
	}
}

// Multi-member gzip and concatenated zstd frames decode like the references.
func TestDifferentialConcatenation(t *testing.T) {
	a, b := []byte("first member "), []byte("second member")
	limits := spillgate.Limits{MaxOutput: 1 << 10}
	for _, name := range []string{"gzip", "zstd"} {
		stream := append(encoders[name](a), encoders[name](b)...)
		out, err := allCodecs(t, limits).ReadAll(bytes.NewReader(stream), name)
		if err != nil || string(out) != string(a)+string(b) {
			t.Errorf("%s: %q %v", name, out, err)
		}
	}
}

// Decoding hostile corpus bombs must not leak goroutines (goleak in TestMain
// checks at exit; this exercises early Close on every codec).
func TestNoLeakOnEarlyClose(t *testing.T) {
	for _, b := range bombs() {
		data, err := corpus.Generate(b.spec)
		if err != nil {
			t.Fatal(err)
		}
		r, err := allCodecs(t, spillgate.Limits{MaxOutput: 1 << 20}).Reader(bytes.NewReader(data), b.encoding)
		if err != nil {
			t.Fatal(err)
		}
		io.CopyN(io.Discard, r, 100)
		r.Close()
	}
}

// FuzzDifferential fuzzes the plain data; every codec must round-trip it.
func FuzzDifferential(f *testing.F) {
	f.Add([]byte("hello"), uint8(0))
	f.Add(make([]byte, 5000), uint8(3))
	names := []string{"gzip", "deflate", "raw-deflate", "br", "zstd"}
	f.Fuzz(func(t *testing.T, data []byte, pick uint8) {
		name := names[int(pick)%len(names)]
		stream := encoders[name](data)
		limits := spillgate.Limits{MaxOutput: int64(len(data)) + 1, DisableRatioLimit: true}
		out, err := allCodecs(t, limits).ReadAll(bytes.NewReader(stream), chainName(name))
		if err != nil || !bytes.Equal(out, data) {
			t.Fatalf("%s: err=%v", name, err)
		}
	})
}
