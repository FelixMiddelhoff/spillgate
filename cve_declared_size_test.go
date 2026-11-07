package spillgate

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"testing"
	"time"

	"github.com/FelixMiddelhoff/spillgate/internal/corpus"
)

// Advisories where a size, a count or a zero value taken from the attacker's
// data decided what the decoder allowed or allocated: adm-zip
// GHSA-rcw4-f5rp-g42v (declared size 0 switched the cap off) and
// CVE-2026-39244 (allocation from a declared size), snappy-java
// CVE-2023-43642, lz4-java CVE-2026-106453 and CVE-2026-106450, Netty
// CVE-2026-42583, klever-go CVE-2026-44697, and the Python zlib trap where
// max_length=0 means "unlimited".

// adm-zip GHSA-rcw4-f5rp-g42v (no CVE): the cap was derived from
// the declared size, and a declared size of 0 removed it. A gzip trailer
// states the size too; whatever it says, the allowance is MaxOutput.
//
// Covers: SG-R-CDC-07 SG-R-LAY-08 SG-R-LAY-07 SG-I-04
func TestGHSA_rcw4_f5rp_g42v_DeclaredSizeNeverChangesTheAllowance(t *testing.T) {
	stream := bombStream("gzip")
	limits := Limits{MaxOutput: 1 << 20, DisableRatioLimit: true}

	for _, declared := range []uint32{0, 1, 1 << 20, 1<<20 + 1, 1 << 31, math.MaxUint32} {
		lying := bytes.Clone(stream)
		binary.LittleEndian.PutUint32(lying[len(lying)-4:], declared)
		r, err := Decode(bytes.NewReader(lying), []string{"gzip"}, limits)
		if err != nil {
			t.Fatal(err)
		}
		requireOutputLimitAfter(t, fmt.Sprintf("ISIZE %d", declared), r, []int{4096}, 1<<20)
	}

	// Declared size equal to the limit while the real size is one byte more.
	data := sampleData(1001)
	member := corpus.GzipStored(data)
	binary.LittleEndian.PutUint32(member[len(member)-4:], 1000)
	if _, err := DecodeAll(bytes.NewReader(member), []string{"gzip"}, Limits{MaxOutput: 1000, DisableRatioLimit: true}); !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("declared = limit, real = limit+1: %v", err)
	}

	// MaxOutput zero must not mean unlimited, and nothing is read.
	if _, err := Decode(untouchedSource(t), []string{"gzip"}, Limits{}); !errors.Is(err, ErrInvalidLimits) {
		t.Fatalf("MaxOutput 0: %v", err)
	}
}

// CVE-2026-39244 (adm-zip): the buffer was allocated from the declared size
// before anything was checked. Header fields that name sizes never size an
// allocation here, and the unterminated name that would need an unbounded
// buffer is refused after 512 bytes.
//
// Covers: SG-R-MEM-01 SG-R-MEM-02 SG-R-CDC-02 SG-R-CDC-07 SG-I-04 SG-I-08
func TestCVE_2026_39244_NoAllocationFromHeaderSizes(t *testing.T) {
	// An extra field of 65535 bytes (the maximum) with a 1 MiB name that never ends.
	header := []byte{0x1f, 0x8b, 8, gzipFlagExtra | gzipFlagName, 0, 0, 0, 0, 0, 255, 0xff, 0xff}
	header = append(header, bytes.Repeat([]byte("e"), 65535)...)
	header = append(header, bytes.Repeat([]byte("n"), 1<<20)...)

	allocated := allocatedDuring(func() {
		got, err := DecodeAll(bytes.NewReader(header), []string{"gzip"}, loose)
		if !errors.Is(err, ErrCorrupt) || got != nil {
			t.Errorf("got (%d bytes, %v)", len(got), err)
		}
	})
	if allocated > 512<<10 {
		t.Fatalf("allocated %d bytes for a hostile header", allocated)
	}
}

// Python's zlib treats max_length=0 as "no limit", lzma and bz2 treat -1 as
// "no limit". Here no value of any limit parameter disables a limit except the
// one explicit switch, and a zero or negative value is either invalid or the
// documented default, never "unlimited".
//
// Covers: SG-R-LIM-01 SG-R-LIM-04 SG-R-LIM-06 SG-R-LIM-07
func TestPythonZlibMaxLengthZeroTrap(t *testing.T) {
	for _, maxOutput := range []int64{0, -1, math.MinInt64} {
		if err := (Limits{MaxOutput: maxOutput}).Validate(); !errors.Is(err, ErrInvalidLimits) {
			t.Errorf("MaxOutput %d: %v", maxOutput, err)
		}
	}
	for _, n := range []int64{0, -1, math.MinInt64} {
		if _, err := NewDecoder(Limits{MaxOutput: 1}, WithMaxInput(n)); !errors.Is(err, ErrInvalidLimits) {
			t.Errorf("MaxInput %d: %v", n, err)
		}
	}
	if err := (Limits{MaxOutput: 1, MaxLayers: -1}).Validate(); !errors.Is(err, ErrInvalidLimits) {
		t.Errorf("MaxLayers -1: %v", err)
	}
	if err := (Limits{MaxOutput: 1, MaxRatio: -1}).Validate(); !errors.Is(err, ErrInvalidLimits) {
		t.Errorf("MaxRatio -1: %v", err)
	}

	// MaxRatio 0 is the default, which is active: it does not disable the check.
	d, _ := NewDecoder(Limits{MaxOutput: 1 << 30, MaxRatio: 0, RatioGrace: 1}, WithCodec("x5000", repeatCodec(5000)))
	if _, err := d.ReadAll(bytes.NewReader(bytes.Repeat([]byte("a"), 100)), "x5000"); !errors.Is(err, ErrRatioLimit) {
		t.Errorf("MaxRatio 0 must not disable the ratio check: %v", err)
	}
}

// snappy-java CVE-2023-43642, Netty CVE-2026-42583 and lz4-java
// CVE-2026-106453: a codec trusted a length in the stream and allocated from
// it. The limiter's own buffers never depend on what a codec reads from its
// input, whatever the codec does with it.
//
// Covers: SG-R-MEM-01 SG-R-CDC-01 SG-I-04
func TestCVE_2023_43642_CodecThatTrustsADeclaredLength(t *testing.T) {
	// The codec reads a 4-byte "declared length" and then serves that many zeros.
	declaring := codecFunc(func(src Source) (io.Reader, error) {
		var left int64 = -1
		return readerFunc(func(p []byte) (int, error) {
			if left < 0 {
				var header [4]byte
				if _, err := io.ReadFull(src, header[:]); err != nil {
					return 0, err
				}
				left = int64(binary.LittleEndian.Uint32(header[:]))
			}
			if left == 0 {
				return 0, io.EOF
			}
			n := int(min(int64(len(p)), left))
			clear(p[:n])
			left -= int64(n)
			return n, nil
		}), nil
	})
	d, _ := NewDecoder(Limits{MaxOutput: 1 << 20, DisableRatioLimit: true}, WithCodec("decl", declaring))
	hostile := []byte{0xff, 0xff, 0xff, 0x7f} // 0x7fffffff bytes declared, nothing behind it

	allocated := allocatedDuring(func() {
		_, err := d.ReadAll(bytes.NewReader(hostile), "decl")
		if !errors.Is(err, ErrOutputLimit) {
			t.Errorf("got %v", err)
		}
	})
	if allocated > 8<<20 { // ReadAll grows to the 1 MiB it really produced, plus slack
		t.Fatalf("allocated %d bytes for a declared length of 2 GiB", allocated)
	}
}

// lz4-java CVE-2026-106450: 10,000 empty frames cost seconds because each
// frame allocated its buffers. The gzip equivalent is a stream of 100,000
// empty members. They produce no output, so only the input limit bounds them;
// the decoder must at least spend no more than a moment per member.
//
// Covers: SG-R-CDC-02 SG-R-INP-01 SG-I-08
func TestCVE_2026_106450_ManyEmptyMembers(t *testing.T) {
	stream := bytes.Repeat(corpus.GzipStored(nil), 100000) // 2.3 MB, no output at all

	start := time.Now()
	got, err := DecodeAll(bytes.NewReader(stream), []string{"gzip"}, loose)
	elapsed := time.Since(start)
	if err != nil || len(got) != 0 {
		t.Fatalf("100000 empty members: (%d bytes, %v)", len(got), err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("100000 empty members took %v", elapsed)
	}
	t.Logf("100000 empty gzip members (2.3 MB, no output) decoded in %v", elapsed)

	// With an input cap the same stream is refused: the only bound that can see empty members.
	if _, err := DecodeAll(bytes.NewReader(stream), []string{"gzip"}, loose, WithMaxInput(1<<20)); !errors.Is(err, ErrInputLimit) {
		t.Fatalf("with MaxInput 1 MiB: %v", err)
	}
}

// klever-go CVE-2026-44697: the payload declared its own size and the decoder
// ignored it while reading everything. Declared sizes anywhere (here in the
// gzip extra field, which applications use for such labels) change nothing,
// and the whole-body call returns no partial data when the limit is hit.
//
// Covers: SG-R-CDC-07 SG-R-API-02 SG-I-04
func TestCVE_2026_44697_DeclaredPayloadSizeIsIgnored(t *testing.T) {
	label := []byte("DataSize=4611686018427387904") // 2^62
	data := sampleData(10000)
	member := corpus.GzipStoredWith(corpus.GzipHeader{Extra: label}, data)

	got, err := DecodeAll(bytes.NewReader(member), []string{"gzip"}, loose)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("with a huge declared size: %v", err)
	}
	got, err = DecodeAll(bytes.NewReader(member), []string{"gzip"}, Limits{MaxOutput: 5000, DisableRatioLimit: true})
	if got != nil || !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("over the limit: (%d bytes, %v)", len(got), err)
	}
}
