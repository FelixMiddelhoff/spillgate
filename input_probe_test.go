package spillgate

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"testing"
	"testing/iotest"

	"github.com/FelixMiddelhoff/spillgate/internal/corpus"
)

// Tests of SG-R-INP-01 as written: a codec TAKING the MaxInput+1-th byte is
// input_limit; looking at it is not. Every case runs against every source
// shape (whole, byte at a time, halves, odd chunks, data together with EOF)
// and every read pattern.

// probeSource wraps a source and records how many bytes it handed out.
type probeSource struct {
	r      io.Reader
	handed int
}

func (p *probeSource) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.handed += n
	return n, err
}

// chunked hands out at most `size` bytes per Read.
type chunked struct {
	r    io.Reader
	size int
}

func (c chunked) Read(p []byte) (int, error) { return c.r.Read(p[:min(len(p), c.size)]) }

var probeSourceShapes = []struct {
	name string
	wrap func(io.Reader) io.Reader
}{
	{"whole", func(r io.Reader) io.Reader { return r }},
	{"one-byte", iotest.OneByteReader},
	{"half", iotest.HalfReader},
	{"chunks-of-7", func(r io.Reader) io.Reader { return chunked{r, 7} }},
	{"data-with-eof", iotest.DataErrReader},
}

var probeReadPatterns = [][]int{{1}, {3}, {4096}, {1 << 20}, {1, 7, 4096, 1}}

// decodeProbe decodes stream with the given encodings under maxInput and
// returns the outcome kind, the bytes delivered and the bytes the source
// handed out.
func decodeProbe(t *testing.T, stream []byte, maxInput int64, shape int, pattern []int, encodings ...string) (kind string, got []byte, handed int) {
	t.Helper()
	d, err := NewDecoder(Limits{MaxOutput: 1 << 30, DisableRatioLimit: true}, WithMaxInput(maxInput))
	if err != nil {
		t.Fatal(err)
	}
	src := &probeSource{r: probeSourceShapes[shape].wrap(bytes.NewReader(stream))}
	r, err := d.Reader(src, encodings...)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for i := 0; ; i++ {
		buf := make([]byte, pattern[i%len(pattern)])
		n, err := r.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			// sticky: the same class again
			if _, again := r.Read(buf); kindOf(again) != kindOf(err) {
				t.Errorf("terminal condition not sticky: %v then %v", err, again)
			}
			return kindOf(err), got, src.handed
		}
	}
}

type probeStream struct {
	name     string
	encoding string
	plain    []byte
	stream   []byte
}

func probeStreams(t *testing.T) []probeStream {
	t.Helper()
	text := bytes.Repeat([]byte("probe the byte after the limit. "), 300)
	random := corpus.Data(5, 700)

	gz := func(data []byte) []byte {
		var b bytes.Buffer
		w := gzip.NewWriter(&b)
		w.Write(data)
		w.Close()
		return b.Bytes()
	}
	zl := func(data []byte) []byte {
		var b bytes.Buffer
		w := zlib.NewWriter(&b)
		w.Write(data)
		w.Close()
		return b.Bytes()
	}
	raw := func(data []byte) []byte {
		var b bytes.Buffer
		w, _ := flate.NewWriter(&b, 6)
		w.Write(data)
		w.Close()
		return b.Bytes()
	}
	return []probeStream{
		{"gzip", "gzip", text, gz(text)},
		{"gzip stored", "gzip", random, corpus.GzipStored(random)},
		{"gzip two members", "gzip", append(bytes.Clone(text), random...), append(gz(text), gz(random)...)},
		{"zlib", "deflate", text, zl(text)},
		{"zlib stored", "deflate", random, corpus.ZlibStored(random)},
		{"raw deflate", "deflate", text, raw(text)},
		{"raw deflate stored", "deflate", random, corpus.StoredDeflate(random)},
	}
}

// forEachProbeRun runs fn for every source shape and read pattern.
func forEachProbeRun(t *testing.T, fn func(t *testing.T, shape int, pattern []int)) {
	t.Helper()
	for shape := range probeSourceShapes {
		for _, pattern := range probeReadPatterns {
			t.Run(fmt.Sprintf("%s/%v", probeSourceShapes[shape].name, pattern), func(t *testing.T) { fn(t, shape, pattern) })
		}
	}
}

// (1) and (3): a complete stream of exactly MaxInput bytes followed by data is
// corrupt, whatever the data and wherever the first byte after the stream sits.
//
// Covers: SG-R-INP-01 SG-R-INP-02 SG-R-CDC-02 SG-R-CDC-03
func TestProbeByteAfterACompleteStreamIsCorruptNotInputLimit(t *testing.T) {
	for _, s := range probeStreams(t) {
		L := int64(len(s.stream))
		tails := map[string][]byte{
			"one zero byte":   {0},
			"1000 zero bytes": make([]byte, 1000),
			"text":            []byte("trailing garbage that is longer than the probe"),
		}
		for tailName, tail := range tails {
			input := append(bytes.Clone(s.stream), tail...)
			t.Run(s.name+"/"+tailName, func(t *testing.T) {
				forEachProbeRun(t, func(t *testing.T, shape int, pattern []int) {
					for _, maxInput := range []int64{L, L + 1, L + 5} {
						kind, _, handed := decodeProbe(t, input, maxInput, shape, pattern, s.encoding)
						if kind != "corrupt" {
							t.Errorf("MaxInput %d (stream %d bytes): %s, want corrupt", maxInput, L, kind)
						}
						if int64(handed) > maxInput+1 {
							t.Errorf("MaxInput %d: source handed out %d bytes, more than MaxInput+1", maxInput, handed)
						}
					}
				})
			})
		}
	}
}

// A stream of exactly MaxInput bytes with nothing after it is fine, and so is
// one byte more of room.
//
// Covers: SG-R-INP-01
func TestProbeExactStreamWithNothingAfterIsOK(t *testing.T) {
	for _, s := range probeStreams(t) {
		L := int64(len(s.stream))
		t.Run(s.name, func(t *testing.T) {
			forEachProbeRun(t, func(t *testing.T, shape int, pattern []int) {
				for _, maxInput := range []int64{L, L + 1} {
					kind, got, _ := decodeProbe(t, s.stream, maxInput, shape, pattern, s.encoding)
					if kind != "ok" || !bytes.Equal(got, s.plain) {
						t.Errorf("MaxInput %d: %s, %d of %d bytes", maxInput, kind, len(got), len(s.plain))
					}
				}
			})
		})
	}
}

// (2): a stream that needs more than MaxInput bytes, with more source behind
// it, is input_limit, never corrupt, at every cut point; if the source really
// ends there it is truncation (corrupt).
//
// Covers: SG-R-INP-01 SG-R-INP-02 SG-R-CDC-06
func TestProbeTruncatedAtTheLimitDependsOnTheSource(t *testing.T) {
	for _, s := range probeStreams(t) {
		L := len(s.stream)
		cuts := []int{1, 5, 9, 10, 11, L / 3, L / 2, L - 9, L - 5, L - 1}
		t.Run(s.name, func(t *testing.T) {
			forEachProbeRun(t, func(t *testing.T, shape int, pattern []int) {
				for _, k := range cuts {
					if k <= 0 || k >= L {
						continue
					}
					// The real source ends at k: truncated.
					kind, _, _ := decodeProbe(t, s.stream[:k], int64(k), shape, pattern, s.encoding)
					if kind != "corrupt" {
						t.Errorf("source ends at %d = MaxInput: %s, want corrupt", k, kind)
					}
					// The source goes on (the rest of the stream, then more): input_limit.
					kind, _, handed := decodeProbe(t, append(bytes.Clone(s.stream), make([]byte, 50)...), int64(k), shape, pattern, s.encoding)
					if kind != "input_limit" {
						t.Errorf("stream cut at MaxInput %d of %d: %s, want input_limit", k, L, kind)
					}
					if handed > k+1 {
						t.Errorf("MaxInput %d: source handed out %d bytes", k, handed)
					}
					// Garbage instead of the rest: the byte after the limit is
					// taken as part of the stream and the stream cannot finish.
					kind, _, _ = decodeProbe(t, append(bytes.Clone(s.stream[:k]), bytes.Repeat([]byte{0xA5}, 50)...), int64(k), shape, pattern, s.encoding)
					if kind != "input_limit" {
						t.Errorf("garbage after MaxInput %d: %s, want input_limit", k, kind)
					}
				}
			})
		})
	}
}

// A first byte after a gzip member that could begin another member (0x1f) is
// taken as such: the codec needs more bytes than MaxInput allows. With room for
// it, the same input is a truncated header (corrupt).
//
// Covers: SG-R-INP-01
func TestProbeByteThatCouldStartAnotherMemberIsTaken(t *testing.T) {
	s := probeStreams(t)[0]
	L := int64(len(s.stream))
	input := append(bytes.Clone(s.stream), 0x1f)
	forEachProbeRun(t, func(t *testing.T, shape int, pattern []int) {
		if kind, _, _ := decodeProbe(t, input, L, shape, pattern, "gzip"); kind != "input_limit" {
			t.Errorf("MaxInput %d: %s, want input_limit", L, kind)
		}
		if kind, _, _ := decodeProbe(t, input, L+1, shape, pattern, "gzip"); kind != "corrupt" {
			t.Errorf("MaxInput %d: %s, want corrupt", L+1, kind)
		}
	})
}

// Identity consumes everything it passes: one byte more than MaxInput is
// input_limit after exactly MaxInput delivered bytes.
//
// Covers: SG-R-INP-01 SG-R-CDC-10
func TestProbeIdentityStillStopsAtTheLimit(t *testing.T) {
	body := corpus.Data(9, 300)
	for _, encs := range [][]string{nil, {"identity"}} {
		forEachProbeRun(t, func(t *testing.T, shape int, pattern []int) {
			L := int64(len(body)) - 1
			kind, got, handed := decodeProbe(t, body, L, shape, pattern, encs...)
			if kind != "input_limit" || int64(len(got)) != L || !bytes.Equal(got, body[:L]) {
				t.Errorf("%v: %s after %d bytes, want input_limit after %d", encs, kind, len(got), L)
			}
			if int64(handed) > L+1 {
				t.Errorf("source handed out %d bytes", handed)
			}
			long := append(bytes.Clone(body), make([]byte, 1000)...)
			if kind, got, _ := decodeProbe(t, long, int64(len(body)), shape, pattern, encs...); kind != "input_limit" || len(got) != len(body) {
				t.Errorf("%v: %s after %d bytes, want input_limit after %d", encs, kind, len(got), len(body))
			}
			if kind, got, _ := decodeProbe(t, body, int64(len(body)), shape, pattern, encs...); kind != "ok" || !bytes.Equal(got, body) {
				t.Errorf("%v: body of exactly MaxInput bytes: %s", encs, kind)
			}
		})
	}
}

// Only layer 1 carries MaxInput. The inner layer takes more bytes than MaxInput
// (here the outer layer expands a lot) without any effect; trailing data after
// the outer stream is corrupt when it is only the probe.
//
// Covers: SG-R-INP-01 SG-R-INP-02
func TestProbeChainsOnlyLayerOneCarriesMaxInput(t *testing.T) {
	zeros := make([]byte, 100000)
	inner := corpus.GzipStored(zeros) // about 100 KB
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write(inner)
	w.Close()
	outer := b.Bytes() // a few hundred bytes
	if len(outer)*10 > len(inner) {
		t.Fatalf("the outer layer does not expand enough: %d to %d", len(outer), len(inner))
	}
	L := int64(len(outer))

	forEachProbeRun(t, func(t *testing.T, shape int, pattern []int) {
		kind, got, _ := decodeProbe(t, outer, L, shape, pattern, "gzip", "gzip")
		if kind != "ok" || len(got) != len(zeros) {
			t.Errorf("exact fit: %s, %d bytes", kind, len(got))
		}
		for _, tail := range [][]byte{{0}, make([]byte, 500)} {
			for _, maxInput := range []int64{L, L + 1} {
				kind, _, handed := decodeProbe(t, append(bytes.Clone(outer), tail...), maxInput, shape, pattern, "gzip", "gzip")
				if kind != "corrupt" {
					t.Errorf("tail %d bytes, MaxInput %d: %s, want corrupt", len(tail), maxInput, kind)
				}
				if int64(handed) > maxInput+1 {
					t.Errorf("source handed out %d bytes", handed)
				}
			}
		}
		if kind, _, _ := decodeProbe(t, outer, L-1, shape, pattern, "gzip", "gzip"); kind != "input_limit" {
			t.Errorf("one byte short: %s, want input_limit", kind)
		}
	})
	// identity in front of a codec
	if kind, _, _ := decodeProbe(t, append(bytes.Clone(outer), 0), L, 0, []int{4096}, "identity", "gzip", "gzip"); kind != "corrupt" {
		t.Errorf("identity,gzip,gzip: %s, want corrupt", kind)
	}
}

// (2) and "checked at the end of every codec step": the check does not depend
// on the codec looking at the source again, and not on which call it used.
//
// Covers: SG-R-INP-01 SG-R-RAT-02
func TestProbeTakingIsCheckedAtTheEndOfTheCodecStep(t *testing.T) {
	const maxInput = 5
	source := corpus.Data(3, 100)

	type step func(src Source) (int, error)
	run := func(t *testing.T, s step, shape int) (string, int) {
		t.Helper()
		codec := codecFunc(func(src Source) (io.Reader, error) {
			return readerFunc(func(p []byte) (int, error) { return s(src) }), nil
		})
		d, err := NewDecoder(Limits{MaxOutput: 1 << 20, DisableRatioLimit: true}, WithMaxInput(maxInput), WithCodec("x", codec))
		if err != nil {
			t.Fatal(err)
		}
		src := &probeSource{r: probeSourceShapes[shape].wrap(bytes.NewReader(source))}
		r, err := d.Reader(src, "x")
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		_, err = io.ReadAll(r)
		return kindOf(err), src.handed
	}

	takeByte := func(n int) func(Source) {
		return func(src Source) {
			for range n {
				if _, err := src.ReadByte(); err != nil {
					panic(err)
				}
			}
		}
	}
	steps := map[string]struct {
		step step
		want string
	}{
		"takes MaxInput+1 bytes and returns data": {func(src Source) (int, error) { takeByte(maxInput + 1)(src); return 1, nil }, "input_limit"},
		"takes MaxInput+1 bytes and ends cleanly": {func(src Source) (int, error) { takeByte(maxInput + 1)(src); return 0, io.EOF }, "input_limit"},
		"takes MaxInput+1 bytes and reports corrupt": {func(src Source) (int, error) {
			takeByte(maxInput + 1)(src)
			return 0, corrupt("made up")
		}, "input_limit"},
		"takes MaxInput+1 bytes with one Read": {func(src Source) (int, error) {
			var b [maxInput + 1]byte
			if _, err := io.ReadFull(src, b[:]); err != nil {
				return 0, err
			}
			return 0, io.EOF
		}, "input_limit"},
		"asks for a buffer much larger than MaxInput and keeps it": {func(src Source) (int, error) {
			if n := readUpTo(src, 64); n != maxInput+1 {
				panic(fmt.Sprintf("Read handed out %d bytes, want %d", n, maxInput+1))
			}
			return 0, io.EOF
		}, "input_limit"},
		"takes MaxInput bytes and ends cleanly": {func(src Source) (int, error) { takeByte(maxInput)(src); return 0, io.EOF }, "ok"},
		"looks at the probe with ReadByte and gives it back": {func(src Source) (int, error) {
			takeByte(maxInput)(src)
			if _, err := src.ReadByte(); err != nil {
				panic(err)
			}
			if err := src.(io.ByteScanner).UnreadByte(); err != nil {
				panic(err)
			}
			return 0, io.EOF
		}, "ok"},
		"looks at the probe with Read and gives it back": {func(src Source) (int, error) {
			if readUpTo(src, 64) != maxInput+1 {
				panic("probe not handed out")
			}
			if err := src.(io.ByteScanner).UnreadByte(); err != nil {
				panic(err)
			}
			return 0, io.EOF
		}, "ok"},
		"finds trailing data behind the probe and reports it": {func(src Source) (int, error) {
			takeByte(maxInput)(src)
			if _, err := src.ReadByte(); err != nil {
				panic(err)
			}
			src.(io.ByteScanner).UnreadByte()
			return 0, corrupt("trailing data")
		}, "corrupt"},
		"cannot go on without the probe and asks for more": {func(src Source) (int, error) {
			takeByte(maxInput + 1)(src)
			_, err := src.ReadByte() // MaxInput+2: never available
			return 0, err
		}, "input_limit"},
	}
	for name, tc := range steps {
		for shape := range probeSourceShapes {
			t.Run(fmt.Sprintf("%s/%s", name, probeSourceShapes[shape].name), func(t *testing.T) {
				kind, handed := run(t, tc.step, shape)
				if kind != tc.want {
					t.Errorf("got %s, want %s", kind, tc.want)
				}
				if handed > maxInput+1 {
					t.Errorf("source handed out %d bytes, more than MaxInput+1", handed)
				}
			})
		}
	}
}

// A source that ends exactly where the stream does gives EOF, not a limit: the
// source's end is what makes a short stream truncated (SG-R-INP-01, SG-R-CDC-06).
func TestProbeSourceEndingAtTheLimitIsEndOfInput(t *testing.T) {
	s := probeStreams(t)[0]
	L := int64(len(s.stream))
	forEachProbeRun(t, func(t *testing.T, shape int, pattern []int) {
		if kind, _, _ := decodeProbe(t, s.stream[:L-1], L-1, shape, pattern, "gzip"); kind != "corrupt" {
			t.Errorf("source ends one byte before the stream does: %s, want corrupt", kind)
		}
	})
}

// readUpTo calls Read with a buffer of the given size until it fails, and
// returns how many bytes it got in total.
func readUpTo(src Source, size int) int {
	buf := make([]byte, size)
	total := 0
	for total < size {
		n, err := src.Read(buf[total:])
		total += n
		if err != nil {
			break
		}
	}
	return total
}
