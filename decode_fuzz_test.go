package spillgate

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// FuzzDecode throws arbitrary header text and arbitrary bytes at the whole
// pipeline. For every input, the library must stay inside its contract: no
// panic, never more than `limit` bytes, only the expected outcome classes
// (never "internal", which would mean a codec misbehaved), a sticky end, and
// the same bytes from the streaming and the whole-body API.
//
// Covers: SG-I-01 SG-I-02 SG-I-03 SG-I-05 SG-I-06 SG-I-09
func FuzzDecode(f *testing.F) {
	good := sampleData(300)
	var b testing.TB = f
	f.Add("gzip", gzipBytes(b, good), uint16(1000), uint8(7))
	f.Add("deflate", zlibBytes(b, good), uint16(299), uint8(1))
	f.Add("deflate", rawDeflateBytes(b, good), uint16(300), uint8(200))
	f.Add("gzip, gzip", gzipBytes(b, gzipBytes(b, good)), uint16(500), uint8(3))
	f.Add("", good, uint16(300), uint8(50))
	f.Add("gzip;q=1", []byte{}, uint16(1), uint8(1))
	f.Add("gzip", []byte{0x1f, 0x8b, 8, 0xff}, uint16(10), uint8(1))
	f.Add("deflate", []byte{0x08, 0x1d, 0x00, 0xe2, 0xff}, uint16(10), uint8(1))

	f.Fuzz(func(t *testing.T, encoding string, body []byte, limit uint16, readSize uint8) {
		if limit == 0 {
			t.Skip("zero is not a valid MaxOutput")
		}
		limits := Limits{MaxOutput: int64(limit)}
		d, err := NewDecoder(limits)
		if err != nil {
			t.Fatalf("valid limits rejected: %v", err)
		}

		r, err := d.Reader(bytes.NewReader(body), encoding)
		if err != nil {
			requireOneOf(t, err, ErrMalformedEncoding, ErrUnsupportedEncoding, ErrLayerLimit)
			return
		}
		defer r.Close()

		streamed, endErr := drainCollect(r, int(readSize)+1)
		if len(streamed) > int(limit) {
			t.Fatalf("delivered %d bytes, limit %d", len(streamed), limit)
		}
		if endErr != io.EOF {
			requireOneOf(t, endErr, ErrOutputLimit, ErrRatioLimit, ErrCorrupt)
		}
		requireSticky(t, r, endErr)

		whole, wholeErr := d.ReadAll(bytes.NewReader(body), encoding)
		if (wholeErr == nil) != (endErr == io.EOF) {
			t.Fatalf("streaming ended with %v but ReadAll returned %v", endErr, wholeErr)
		}
		if wholeErr == nil && !bytes.Equal(whole, streamed) {
			t.Fatal("streaming and whole-body output differ")
		}
		if wholeErr != nil && whole != nil {
			t.Fatal("ReadAll returned data together with an error")
		}
	})
}

func requireOneOf(t *testing.T, err error, allowed ...error) {
	t.Helper()
	for _, a := range allowed {
		if errors.Is(err, a) {
			return
		}
	}
	t.Fatalf("unexpected outcome class: %v", err)
}

// drainCollect reads with a fixed buffer size and keeps the bytes.
func drainCollect(r io.Reader, readSize int) ([]byte, error) {
	var out bytes.Buffer
	buf := make([]byte, readSize)
	for {
		n, err := r.Read(buf)
		out.Write(buf[:n])
		if err != nil {
			return out.Bytes(), err
		}
	}
}
