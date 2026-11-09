package spillgate_test

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"strings"

	"github.com/FelixMiddelhoff/spillgate"
)

func gzipped(data []byte) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write(data)
	w.Close()
	return b.Bytes()
}

// Decode a body that carries "Content-Encoding: gzip". MaxOutput is the only
// required limit.
func ExampleDecodeAll() {
	body := gzipped([]byte("hello, gate"))

	data, err := spillgate.DecodeAll(bytes.NewReader(body), []string{"gzip"},
		spillgate.Limits{MaxOutput: 1 << 20})
	fmt.Printf("%s %v\n", data, err)
	// Output: hello, gate <nil>
}

// A decompression bomb ends in a typed error and no data.
func ExampleDecodeAll_bomb() {
	// 64 MiB of zeros compress to about 64 KiB.
	body := gzipped(make([]byte, 64<<20))

	data, err := spillgate.DecodeAll(bytes.NewReader(body), []string{"gzip"},
		spillgate.Limits{MaxOutput: 1 << 20})
	fmt.Println(len(data), errors.Is(err, spillgate.ErrOutputLimit) || errors.Is(err, spillgate.ErrRatioLimit))
	// Output: 0 true
}

// Inspect why decoding was refused.
func ExampleError() {
	_, err := spillgate.DecodeAll(strings.NewReader("x"), []string{"compress"},
		spillgate.Limits{MaxOutput: 1024})

	var e *spillgate.Error
	if errors.As(err, &e) {
		fmt.Println(e.Kind)
	}
	// Output: unsupported_encoding
}

// A Decoder is built once and shared; it is safe for concurrent use.
func ExampleNewDecoder() {
	d, err := spillgate.NewDecoder(spillgate.Limits{MaxOutput: 1 << 20, MaxLayers: 2})
	if err != nil {
		fmt.Println(err)
		return
	}
	// Header "Content-Encoding: gzip, gzip" lists layers in the order applied.
	body := gzipped(gzipped([]byte("twice")))
	data, err := d.ReadAll(bytes.NewReader(body), "gzip, gzip")
	fmt.Printf("%s %v\n", data, err)
	// Output: twice <nil>
}
