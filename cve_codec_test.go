package spillgate

import (
	"bytes"
	"compress/flate"
	"errors"
	"fmt"
	"io"
	"testing"
)

// Advisories where a limit existed but did not reach every codec or every
// buffer: Netty CVE-2026-42587 (limit for gzip, none for br, zstd, snappy),
// Netty CVE-2021-37136 (bzip2 without any limit), go-grpc-compression
// GHSA-87m9-rv8p-rgmg (limit not passed to the zstd decoder), nats-server
// CVE-2026-27571 (unbounded inflate of compressed WebSocket messages).

var bombLimits = Limits{MaxOutput: 1 << 20, DisableRatioLimit: true}

// unboundedFakes registers fake extension codecs under the names of the
// codecs Netty forgot, each of which produces zeros forever.
func unboundedFakes() []Option {
	return []Option{
		WithCodec("br", unboundedCodec()),
		WithCodec("zstd", unboundedCodec()),
		WithCodec("snappy", unboundedCodec()),
	}
}

// CVE-2026-42587 (Netty): with a 1 MiB cap, a gzip bomb was stopped but the
// same bomb sent as br, zstd or snappy was not. Here every codec, built-in or
// registered, ends in the same outcome, and the whole-body call returns no data.
//
// Covers: SG-R-CDC-01 SG-R-LAY-02 SG-R-LAY-04 SG-R-API-02 SG-I-01 SG-I-02
func TestCVE_2026_42587_EveryCodecIsBoundedAlike(t *testing.T) {
	type attempt struct {
		name      string
		encoding  string
		source    []byte
		wantAfter string
	}
	attempts := []attempt{}
	for _, c := range bombCodecs {
		attempts = append(attempts, attempt{c.name, c.encoding, bombStream(c.name), "output_limit"})
	}
	for _, name := range []string{"br", "zstd", "snappy"} {
		attempts = append(attempts, attempt{"fake " + name, name, []byte("x"), "output_limit"})
	}

	d, err := NewDecoder(bombLimits, unboundedFakes()...)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range attempts {
		whole, err := d.ReadAll(bytes.NewReader(a.source), a.encoding)
		if kindOf(err) != a.wantAfter || whole != nil {
			t.Errorf("%s: ReadAll = (%d bytes, %v), want no data and %s", a.name, len(whole), err, a.wantAfter)
		}
		r, err := d.Reader(bytes.NewReader(a.source), a.encoding)
		if err != nil {
			t.Fatal(err)
		}
		requireOutputLimitAfter(t, a.name, r, []int{4096}, 1<<20)
	}
}

// The same bombs under a ratio limit end in a ratio error for every codec,
// including the fake ones that read almost nothing and produce everything.
//
// Covers: SG-R-CDC-01 SG-R-RAT-01 SG-I-02
func TestCVE_2026_42587_EveryCodecIsRatioLimitedAlike(t *testing.T) {
	limits := Limits{MaxOutput: 1 << 30, MaxRatio: 100, RatioGrace: 1}
	d, err := NewDecoder(limits, unboundedFakes()...)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range bombCodecs {
		if _, err := d.ReadAll(bytes.NewReader(bombStream(c.name)), c.encoding); kindOf(err) != "ratio_limit" {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	for _, name := range []string{"br", "zstd", "snappy"} {
		if _, err := d.ReadAll(bytes.NewReader([]byte("x")), name); kindOf(err) != "ratio_limit" {
			t.Errorf("fake %s: %v", name, err)
		}
	}
}

// Netty's other half: the zstd decoder had a 4 MB cap per buffer, which does
// not bound the total. The limiter counts every delivered byte, however the
// codec chops its output into buffers.
//
// Covers: SG-R-LAY-02 SG-I-01
func TestCVE_2026_42587_PerBufferCapDoesNotBoundTheTotal(t *testing.T) {
	for _, bufferSize := range []int{1, 100, 4 << 10, 4 << 20, 64 << 20} {
		chunky := codecFunc(func(Source) (io.Reader, error) {
			return readerFunc(func(p []byte) (int, error) {
				n := min(len(p), bufferSize)
				clear(p[:n])
				return n, nil
			}), nil
		})
		d, _ := NewDecoder(bombLimits, WithCodec("chunky", chunky))
		r, _ := d.Reader(bytes.NewReader([]byte("x")), "chunky")
		requireOutputLimitAfter(t, fmt.Sprintf("codec buffer of %d bytes", bufferSize), r, []int{1 << 20, 3, 70000}, 1<<20)
	}
}

// CVE-2021-37136 (Netty bzip2): a decoder with no output control. A codec that
// ignores the size of the buffer it is given cannot get past the guard, and
// an encoding spillgate does not know is refused before the source is read.
//
// Covers: SG-R-CDC-01 SG-R-CDC-08 SG-R-HDR-08 SG-R-HDR-09 SG-I-01 SG-I-05
func TestCVE_2021_37136_BzipLikeCodecWithoutLimits(t *testing.T) {
	if _, err := Decode(untouchedSource(t), []string{"bzip2"}, bombLimits); !errors.Is(err, ErrUnsupportedEncoding) {
		t.Fatalf("bzip2: %v", err)
	}

	// A codec that reports more bytes than the buffer holds is a broken codec.
	liar := codecFunc(func(Source) (io.Reader, error) {
		return readerFunc(func(p []byte) (int, error) { return len(p) + 1<<20, nil }), nil
	})
	d, _ := NewDecoder(bombLimits, WithCodec("bz2x", liar))
	r, _ := d.Reader(bytes.NewReader([]byte("x")), "bz2x")
	if _, err := r.Read(make([]byte, 100)); !errors.Is(err, ErrInternal) {
		t.Fatalf("lying codec: %v", err)
	}

	// A codec that decodes a whole 64 MiB block in one call still gets only the remaining budget as buffer.
	var biggestBuffer int
	block := codecFunc(func(Source) (io.Reader, error) {
		return readerFunc(func(p []byte) (int, error) {
			biggestBuffer = max(biggestBuffer, len(p))
			clear(p)
			return len(p), nil
		}), nil
	})
	d, _ = NewDecoder(bombLimits, WithCodec("bz2x", block))
	r, _ = d.Reader(bytes.NewReader([]byte("x")), "bz2x")
	requireOutputLimitAfter(t, "big block", r, []int{64 << 20}, 1<<20)
	if biggestBuffer > 1<<20 {
		t.Fatalf("the codec was offered a buffer of %d bytes, more than the whole budget", biggestBuffer)
	}
}

// GHSA-87m9-rv8p-rgmg (go-grpc-compression): the zstd path used DecodeAll and
// ignored the message limit. spillgate's whole-body API is built on the
// limited reader, so it cannot read past MaxOutput either.
//
// Covers: SG-R-API-01 SG-R-API-02 SG-R-CDC-01
func TestGHSA_87m9_rv8p_rgmg_WholeBodyCallsAreLimitedToo(t *testing.T) {
	d, _ := NewDecoder(bombLimits, unboundedFakes()...)
	for _, name := range []string{"br", "zstd", "snappy"} {
		got, err := d.ReadAll(bytes.NewReader([]byte("x")), name)
		if got != nil || !errors.Is(err, ErrOutputLimit) {
			t.Errorf("%s: (%d bytes, %v)", name, len(got), err)
		}
	}
}

// CVE-2026-27571 (nats-server): permessage-deflate messages are raw DEFLATE
// without a final block. A bomb in that format is stopped by the limit, and a
// message cut off without its final block is corruption: spillgate never
// treats a missing end marker as a clean end.
//
// Covers: SG-R-CDC-03 SG-R-CDC-06 SG-R-LAY-04 SG-I-01
func TestCVE_2026_27571_SyncFlushedRawDeflate(t *testing.T) {
	// Raw deflate bomb: the limit applies.
	r, err := Decode(bytes.NewReader(bombStream("raw")), []string{"deflate"}, bombLimits)
	if err != nil {
		t.Fatal(err)
	}
	requireOutputLimitAfter(t, "raw bomb", r, []int{4096}, 1<<20)

	// A sync-flushed stream that was never closed has no final block.
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	w.Write(sampleData(5000))
	w.Flush() // permessage-deflate style: flush, never Close
	got, err := DecodeAll(bytes.NewReader(buf.Bytes()), []string{"deflate"}, loose)
	if !errors.Is(err, ErrCorrupt) || got != nil {
		t.Fatalf("stream without final block: (%d bytes, %v), want corrupt and no data", len(got), err)
	}
}
