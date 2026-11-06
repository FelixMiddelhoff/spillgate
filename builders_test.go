package spillgate

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/binary"
	"hash/crc32"
	"io"
	"testing"
)

// Test builders for compressed streams. They use the standard library's
// writers, which are independent of the code under test.

func gzipBytes(t testing.TB, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	mustWrite(t, w, data)
	return buf.Bytes()
}

func zlibBytes(t testing.TB, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	mustWrite(t, w, data)
	return buf.Bytes()
}

func rawDeflateBytes(t testing.TB, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, w, data)
	return buf.Bytes()
}

// mustWrite writes data and closes w, which flushes the stream trailer.
func mustWrite(t testing.TB, w io.WriteCloser, data []byte) {
	t.Helper()
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

// gzipWithHeader builds a single gzip member with the given optional header
// fields, so tests can produce headers the standard library writer refuses
// (long names, header CRC, reserved flags).
type gzipHeader struct {
	flags     byte
	extra     []byte
	name      []byte // written followed by a NUL when non-nil
	comment   []byte // written followed by a NUL when non-nil
	headerCRC bool
}

func gzipMember(t testing.TB, h gzipHeader, data []byte) []byte {
	t.Helper()
	flags := h.flags
	var header []byte
	header = append(header, 0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255)
	if h.extra != nil {
		flags |= gzipFlagExtra
		header = binary.LittleEndian.AppendUint16(header, uint16(len(h.extra)))
		header = append(header, h.extra...)
	}
	if h.name != nil {
		flags |= gzipFlagName
		header = append(append(header, h.name...), 0)
	}
	if h.comment != nil {
		flags |= gzipFlagComment
		header = append(append(header, h.comment...), 0)
	}
	if h.headerCRC {
		flags |= gzipFlagHeaderCRC
	}
	header[3] = flags
	if h.headerCRC {
		header = binary.LittleEndian.AppendUint16(header, uint16(crc32.ChecksumIEEE(header)))
	}

	body := rawDeflateBytes(t, data)
	trailer := binary.LittleEndian.AppendUint32(nil, crc32.ChecksumIEEE(data))
	trailer = binary.LittleEndian.AppendUint32(trailer, uint32(len(data)))
	return bytes.Join([][]byte{header, body, trailer}, nil)
}

// sampleData returns n bytes that compress moderately and are not all equal.
func sampleData(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte((i*31)>>3) ^ byte(i/251)
	}
	return out
}

// zerosGzip compresses n zero bytes into a gzip stream without holding the
// zeros in memory.
func zerosGzip(t testing.TB, n int64) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(w, &zerosReader{left: n}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
