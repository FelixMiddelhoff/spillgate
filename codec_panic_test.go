package spillgate_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/FelixMiddelhoff/spillgate"
)

type panicCloseCodec struct{ panicNew bool }

type panicCloseReader struct{}

func (panicCloseReader) Read(p []byte) (int, error) { return 0, io.EOF }
func (panicCloseReader) Close() error               { panic("codec Close panics") }

func (c panicCloseCodec) NewReader(src spillgate.Source) (io.Reader, error) {
	if c.panicNew {
		panic("codec NewReader panics")
	}
	return panicCloseReader{}, nil
}

func expectNoPanic(t *testing.T, what string, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s: panic escaped the library (SG-R-CDC-08, SG-I-05): %v", what, r)
		}
	}()
	f()
}

// A panic in a codec Close does not escape the library; Close still finishes.
//
// Covers: SG-R-CDC-08 SG-I-05
func TestCodecClosePanicIsContained(t *testing.T) {
	d, err := spillgate.NewDecoder(smallLimits(), spillgate.WithCodec("pc", panicCloseCodec{}))
	if err != nil {
		t.Fatal(err)
	}
	r, err := d.Reader(bytes.NewReader([]byte("x")), "pc")
	if err != nil {
		t.Fatal(err)
	}
	expectNoPanic(t, "Close", func() { r.Close() })
}

// A panic in a codec NewReader becomes an error while the chain is built.
//
// Covers: SG-R-CDC-08 SG-I-05
func TestCodecNewReaderPanicIsContained(t *testing.T) {
	d, err := spillgate.NewDecoder(smallLimits(), spillgate.WithCodec("pc", panicCloseCodec{panicNew: true}))
	if err != nil {
		t.Fatal(err)
	}
	expectNoPanic(t, "Reader", func() { d.Reader(bytes.NewReader([]byte("x")), "pc") })
}
