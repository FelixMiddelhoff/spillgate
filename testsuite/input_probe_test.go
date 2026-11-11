package testsuite

import (
	"bytes"
	"io"
	"testing"
	"testing/iotest"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"

	"github.com/FelixMiddelhoff/spillgate"
	spillbr "github.com/FelixMiddelhoff/spillgate/br"
	spillzstd "github.com/FelixMiddelhoff/spillgate/zstd"
)

// SG-R-INP-01 for the optional codecs: the byte after MaxInput is looked at,
// not taken. A stream of exactly MaxInput bytes followed by data is corrupt;
// a stream cut at the limit with more source behind it is input_limit; a
// source that ends at the cut is corrupt.
//
// Covers: SG-R-INP-01 SG-R-INP-02 SG-R-CDC-04 SG-R-CDC-05
func TestProbeByteForBrotliAndZstd(t *testing.T) {
	text := bytes.Repeat([]byte("the byte after the limit "), 400)

	var bb bytes.Buffer
	bw := brotli.NewWriterLevel(&bb, 5)
	bw.Write(text)
	bw.Close()
	var zb bytes.Buffer
	zw, _ := zstd.NewWriter(&zb, zstd.WithEncoderConcurrency(1))
	zw.Write(text)
	zw.Close()

	shapes := map[string]func(io.Reader) io.Reader{
		"whole": func(r io.Reader) io.Reader { return r }, "one-byte": iotest.OneByteReader,
		"half": iotest.HalfReader, "data+eof": iotest.DataErrReader,
	}
	for _, c := range []struct {
		enc    string
		opt    spillgate.Option
		stream []byte
	}{{"br", spillbr.Enable(), bb.Bytes()}, {"zstd", spillzstd.Enable(), zb.Bytes()}} {
		L := int64(len(c.stream))
		run := func(input []byte, maxInput int64, shape func(io.Reader) io.Reader, readSize int) (string, int) {
			d, err := spillgate.NewDecoder(spillgate.Limits{MaxOutput: 1 << 30, DisableRatioLimit: true}, spillgate.WithMaxInput(maxInput), c.opt)
			if err != nil {
				t.Fatal(err)
			}
			handed := 0
			shaped := shape(bytes.NewReader(input))
			src := readerFunc(func(p []byte) (int, error) {
				n, err := shaped.Read(p)
				handed += n
				return n, err
			})
			r, err := d.Reader(src, c.enc)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			buf := make([]byte, readSize)
			for {
				if _, err := r.Read(buf); err != nil {
					if err == io.EOF {
						return "ok", handed
					}
					if e, ok := err.(*spillgate.Error); ok {
						return e.Kind.String(), handed
					}
					return "other: " + err.Error(), handed
				}
			}
		}
		for name, shape := range shapes {
			for _, readSize := range []int{1, 7, 4096, 1 << 20} {
				for _, tail := range [][]byte{{0}, make([]byte, 1000)} {
					input := append(bytes.Clone(c.stream), tail...)
					for _, maxInput := range []int64{L, L + 1} {
						kind, handed := run(input, maxInput, shape, readSize)
						if kind != "corrupt" || int64(handed) > maxInput+1 {
							t.Errorf("%s %s read %d tail %d MaxInput %d: %s, handed %d", c.enc, name, readSize, len(tail), maxInput, kind, handed)
						}
					}
				}
				if kind, _ := run(c.stream, L, shape, readSize); kind != "ok" {
					t.Errorf("%s %s read %d: exact stream: %s", c.enc, name, readSize, kind)
				}
				for _, k := range []int64{1, 5, L / 2, L - 1} {
					if kind, _ := run(c.stream[:k], k, shape, readSize); kind != "corrupt" {
						t.Errorf("%s %s read %d: source ends at MaxInput %d: %s, want corrupt", c.enc, name, readSize, k, kind)
					}
					if kind, handed := run(append(bytes.Clone(c.stream), make([]byte, 50)...), k, shape, readSize); kind != "input_limit" || int64(handed) > k+1 {
						t.Errorf("%s %s read %d: cut at MaxInput %d: %s, handed %d, want input_limit", c.enc, name, readSize, k, kind, handed)
					}
				}
			}
		}
	}
}

type readerFunc func(p []byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }
