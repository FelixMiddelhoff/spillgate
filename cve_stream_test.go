package spillgate

import (
	"bytes"
	"compress/flate"
	"errors"
	"fmt"
	"testing"

	"github.com/FelixMiddelhoff/spillgate/internal/corpus"
)

// Advisories about streaming, about limits on the wrong quantity, and about
// the ratio: Zapros CVE-2026-61652, urllib3 CVE-2025-66471, aiohttp
// CVE-2025-69223, axios CVE-2026-42036 and CVE-2026-44488, tornado
// CVE-2026-49855, jwcrypto CVE-2024-28102 and CVE-2026-39373, Authlib
// CVE-2025-62706, go-jose CVE-2024-28180, httplib2 CVE-2026-59939, Rekor
// CVE-2026-48702, ultimate-sitemap-parser GHSA-8823-qg2x-pv9f.

// CVE-2026-61652 (Zapros) and CVE-2025-66471 (urllib3): the decoder ignored
// the size of the caller's read and expanded a whole response at once. Here
// the same bomb is read with every buffer size and always ends after exactly
// MaxOutput bytes with the same error.
//
// Covers: SG-R-RDR-01 SG-R-LAY-02 SG-R-LAY-03 SG-I-01 SG-I-09
func TestCVE_2026_61652_ReadSizeNeverChangesTheOutcome(t *testing.T) {
	for _, c := range bombCodecs {
		for name, pattern := range readSizePatterns {
			r, err := Decode(bytes.NewReader(bombStream(c.name)), []string{c.encoding}, bombLimits)
			if err != nil {
				t.Fatal(err)
			}
			requireOutputLimitAfter(t, c.name+", reads of "+name, r, pattern, 1<<20)
		}
	}
	// Two layers, byte by byte.
	nested := corpus.GzipStored(bombStream("gzip"))
	r, _ := Decode(bytes.NewReader(nested), []string{"gzip", "gzip"}, bombLimits)
	requireOutputLimitAfter(t, "two layers, 1-byte reads", r, []int{1}, 1<<20)
}

// A one-byte read of a 1 GiB bomb must cost a constant amount of memory, not
// the size of the expansion.
//
// Covers: SG-R-MEM-02 SG-I-08
func TestCVE_2025_66471_OneByteReadOfAGigabyteCostsAlmostNothing(t *testing.T) {
	stream := bombStream("gzip")
	allocated := allocatedDuring(func() {
		r, _ := Decode(bytes.NewReader(stream), []string{"gzip"}, Limits{MaxOutput: 1 << 30, DisableRatioLimit: true})
		if n, err := r.Read(make([]byte, 1)); n != 1 || err != nil {
			t.Errorf("Read = (%d, %v)", n, err)
		}
		r.Close()
	})
	if allocated > 256<<10 {
		t.Fatalf("one byte read allocated %d bytes", allocated)
	}
}

// urllib3 2.6.3 had to fix a redirect path that kept a decoder with stale
// limits. Every reader from one Decoder starts with a fresh budget and shares
// no state with the others, in sequence or interleaved.
//
// Covers: SG-R-RDR-07 SG-R-LAY-02 SG-I-01
func TestCVE_2025_66471_ReadersFromOneDecoderDoNotShareABudget(t *testing.T) {
	d, _ := NewDecoder(bombLimits)
	first, _ := d.Reader(bytes.NewReader(bombStream("gzip")), "gzip")
	second, _ := d.Reader(bytes.NewReader(bombStream("gzip")), "gzip")

	// Interleave the two readers.
	buf := make([]byte, 100000)
	var a, b int64
	var errA, errB error
	for errA == nil || errB == nil {
		if errA == nil {
			var n int
			n, errA = first.Read(buf)
			a += int64(n)
		}
		if errB == nil {
			var n int
			n, errB = second.Read(buf)
			b += int64(n)
		}
	}
	if a != 1<<20 || b != 1<<20 || kindOf(errA) != "output_limit" || kindOf(errB) != "output_limit" {
		t.Fatalf("got (%d, %v) and (%d, %v)", a, errA, b, errB)
	}
	// A reader created after both ended gets a full budget again.
	third, _ := d.Reader(bytes.NewReader(bombStream("gzip")), "gzip")
	requireOutputLimitAfter(t, "third reader", third, []int{4096}, 1<<20)
}

// CVE-2025-69223 (aiohttp), CVE-2026-42036 and CVE-2026-44488 (axios): the
// limit held for the whole-body path but not for streaming, or not for one
// adapter. Streaming and whole-body reading give the same bytes and the same
// outcome class for success, corruption and limit hits alike, and an
// unencoded body is bounded too.
//
// Covers: SG-I-09 SG-R-CDC-10 SG-R-API-02 SG-R-LAY-06
func TestCVE_2026_42036_StreamingEqualsWholeBody(t *testing.T) {
	good := sampleData(3000)
	cases := map[string]struct {
		stream   []byte
		encoding []string
		limits   Limits
	}{
		"fits":          {gzipBytes(t, good), []string{"gzip"}, Limits{MaxOutput: 5000, DisableRatioLimit: true}},
		"exactly fits":  {gzipBytes(t, good), []string{"gzip"}, Limits{MaxOutput: 3000, DisableRatioLimit: true}},
		"one over":      {gzipBytes(t, good), []string{"gzip"}, Limits{MaxOutput: 2999, DisableRatioLimit: true}},
		"corrupt":       {gzipBytes(t, good)[:100], []string{"gzip"}, loose},
		"bomb":          {bombStream("gzip"), []string{"gzip"}, bombLimits},
		"identity body": {sampleData(4096), nil, Limits{MaxOutput: 16, DisableRatioLimit: true}},
	}
	for name, tc := range cases {
		d, err := NewDecoder(tc.limits)
		if err != nil {
			t.Fatal(err)
		}
		r, _ := d.Reader(bytes.NewReader(tc.stream), tc.encoding...)
		streamed, streamErr := drainCollect(r, 1000)
		whole, wholeErr := d.ReadAll(bytes.NewReader(tc.stream), tc.encoding...)

		if kindOf(streamErr) != kindOf(wholeErr) {
			t.Errorf("%s: streaming ended with %v, whole body with %v", name, streamErr, wholeErr)
		}
		if wholeErr == nil && !bytes.Equal(streamed, whole) {
			t.Errorf("%s: different bytes", name)
		}
		if wholeErr != nil && whole != nil {
			t.Errorf("%s: whole-body call returned data with an error", name)
		}
		if int64(len(streamed)) > tc.limits.MaxOutput {
			t.Errorf("%s: streaming delivered %d bytes over the limit %d", name, len(streamed), tc.limits.MaxOutput)
		}
	}

	// axios: a limit of 16 bytes against an unencoded 4 KiB body delivers exactly 16.
	r, _ := Decode(bytes.NewReader(sampleData(4096)), nil, Limits{MaxOutput: 16, DisableRatioLimit: true})
	requireOutputLimitAfter(t, "identity body", r, []int{1000}, 16)
}

// CVE-2026-59939 (httplib2): a gzip response of about 153 KB expanded to 150
// MiB, about 1029 to 1, which is as far as DEFLATE goes. With a MaxRatio well
// below that the stream is refused early; with only an output limit it is
// refused at the limit; with default limits it is refused one way or the
// other. In no case does it succeed or come out truncated without an error.
//
// Covers: SG-R-RAT-01 SG-R-RAT-05 SG-R-LAY-04 SG-I-02
func TestCVE_2026_59939_BombAtTheBestDeflateRatio(t *testing.T) {
	const matches = 150 << 20 / 258
	stream := corpus.GzipZeros(matches)
	for name, limits := range map[string]struct {
		limits Limits
		want   string
	}{
		"ratio 100":  {Limits{MaxOutput: 1 << 30, MaxRatio: 100}, "ratio_limit"},
		"output cap": {Limits{MaxOutput: 1 << 20, DisableRatioLimit: true}, "output_limit"},
	} {
		got, err := DecodeAll(bytes.NewReader(stream), []string{"gzip"}, limits.limits)
		if kindOf(err) != limits.want || got != nil {
			t.Errorf("%s: (%d bytes, %v), want %s", name, len(got), err, limits.want)
		}
	}
	got, err := DecodeAll(bytes.NewReader(stream), []string{"gzip"}, Limits{MaxOutput: 1 << 20})
	if err == nil || got != nil {
		t.Errorf("default ratio: (%d bytes, %v), want an error and no data", len(got), err)
	}
}

// CVE-2025-62706 (Authlib), CVE-2024-28180 (go-jose), CVE-2024-28176 (panva
// jose): JWE payloads are raw DEFLATE, without a zlib header. A raw bomb is
// caught whichever way the limit is set, a legitimate stream with an ordinary
// ratio is not a false alarm, and a stream that starts like a zlib header
// with a dictionary flag is corrupt, not data.
//
// Covers: SG-R-CDC-03 SG-R-RAT-01 SG-R-RAT-05 SG-R-LAY-04 SG-I-02
func TestCVE_2025_62706_RawDeflateBombsAndFairUse(t *testing.T) {
	raw := corpus.ZerosDeflate(50 << 20 / 258) // about 50 MiB of zeros, 50 KiB compressed
	if _, err := DecodeAll(bytes.NewReader(raw), []string{"deflate"}, Limits{MaxOutput: 1 << 30, MaxRatio: 100}); !errors.Is(err, ErrRatioLimit) {
		t.Errorf("ratio: %v", err)
	}
	if _, err := DecodeAll(bytes.NewReader(raw), []string{"deflate"}, bombLimits); !errors.Is(err, ErrOutputLimit) {
		t.Errorf("output limit: %v", err)
	}

	// Fair use: ordinary repetitive text compresses by a good factor, far below the default ratio.
	text := bytes.Repeat([]byte(`{"name":"example","id":12345,"tags":["a","b","c"]},`), 20000) // about 1 MiB
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.BestCompression)
	w.Write(text)
	w.Close()
	t.Logf("fair-use stream: %d bytes from %d, ratio %.0f:1", buf.Len(), len(text), float64(len(text))/float64(buf.Len()))
	got, err := DecodeAll(bytes.NewReader(buf.Bytes()), []string{"deflate"}, Limits{MaxOutput: 4 << 20})
	if err != nil || !bytes.Equal(got, text) {
		t.Errorf("fair use under default limits: %v", err)
	}

	dictionary := append([]byte{0x78, 0x20, 1, 2, 3, 4}, corpus.StoredDeflate([]byte("x"))...)
	if _, err := DecodeAll(bytes.NewReader(dictionary), []string{"deflate"}, loose); !errors.Is(err, ErrCorrupt) {
		t.Errorf("FDICT: %v", err)
	}
}

// CVE-2024-28102 and CVE-2026-39373 (jwcrypto), CVE-2026-49855 (tornado),
// GHSA-8823-qg2x-pv9f (sitemap parser), CVE-2026-48702 (Rekor): the cap was on
// the compressed size, so a 130 KB token still inflated to 100 MB. Here a cap
// on the input is no substitute for the output limit, and the output limit is
// mandatory.
//
// Covers: SG-R-LIM-01 SG-R-LIM-06 SG-R-INP-01 SG-R-LAY-01 SG-I-01
func TestCVE_2026_39373_CompressedSizeCapIsNoSubstituteForTheOutputLimit(t *testing.T) {
	bomb := corpus.ZerosDeflate(520_000) // about 130 KB compressed, 134 MB decoded
	t.Logf("bomb: %d bytes compressed", len(bomb))

	// Input cap far above the bomb, output cap 1 MiB: the output limit decides.
	_, err := DecodeAll(bytes.NewReader(bomb), []string{"deflate"}, bombLimits, WithMaxInput(256<<10))
	if !errors.Is(err, ErrOutputLimit) {
		t.Errorf("input cap above the bomb: %v", err)
	}
	// Input cap below the bomb: refused by the input limit, whichever comes first in the stream.
	_, err = DecodeAll(bytes.NewReader(bomb), []string{"deflate"}, Limits{MaxOutput: 1 << 30, DisableRatioLimit: true}, WithMaxInput(100<<10))
	if !errors.Is(err, ErrInputLimit) {
		t.Errorf("input cap below the bomb: %v", err)
	}
	// An input cap alone does not make a configuration: the output limit stays mandatory.
	if _, err := NewDecoder(Limits{}, WithMaxInput(1<<20)); !errors.Is(err, ErrInvalidLimits) {
		t.Errorf("MaxInput without MaxOutput: %v", err)
	}
}

// CVE-2026-49855 (tornado): the limit must hold however the bytes arrive.
// The same bomb delivered by a source that hands out one byte, 64 bytes or a
// few kilobytes at a time ends the same way.
//
// Covers: SG-R-RDR-01 SG-R-LAY-02 SG-I-09
func TestCVE_2026_49855_SourceChunkingDoesNotMatter(t *testing.T) {
	stream := bombStream("gzip")[:200000] // a bomb prefix is enough to hit the limit
	for _, chunk := range []int{1, 2, 64, 1000, 4096, 100000} {
		r, err := Decode(newChunkedSource(stream, chunk), []string{"gzip"}, bombLimits)
		if err != nil {
			t.Fatal(err)
		}
		requireOutputLimitAfter(t, fmt.Sprintf("source chunks of %d bytes", chunk), r, []int{4096}, 1<<20)
	}
}

// CVE-2026-48702 (Rekor): many gzip members, each innocent, together a bomb.
// All members share one budget.
//
// Covers: SG-R-CDC-02 SG-R-LAY-01 SG-I-01
func TestCVE_2026_48702_ManyMembersShareOneBudget(t *testing.T) {
	member := corpus.GzipZeros(4000) // 1 MiB of zeros each
	stream := bytes.Repeat(member, 1000)
	r, err := Decode(bytes.NewReader(stream), []string{"gzip"}, Limits{MaxOutput: 4 << 20, DisableRatioLimit: true})
	if err != nil {
		t.Fatal(err)
	}
	requireOutputLimitAfter(t, "1000 members", r, []int{65536}, 4<<20)
}

// Req CVE-2026-49755 (gzip chains in default steps): each layer expands
// 1000-fold. The intermediate layer exceeds the budget even though a later
// layer might shrink the data again, so the first over-budget layer decides.
//
// Covers: SG-R-LAY-01 SG-R-HDR-12 SG-I-01
func TestCVE_2026_49755_EachLayerOfANestedBombIsBounded(t *testing.T) {
	inner := corpus.GzipZeros(4000)                              // 1 MiB of zeros
	middle := corpus.GzipStored(inner)                           // stored: layer 2 output is the compressed inner
	outer := corpus.GzipStored(middle)                           // stored around that
	limits := Limits{MaxOutput: 100000, DisableRatioLimit: true} // smaller than inner's output

	r, err := Decode(bytes.NewReader(outer), []string{"gzip", "gzip", "gzip"}, limits)
	if err != nil {
		t.Fatal(err)
	}
	delivered, endErr := drainPattern(r, []int{4096})
	var e *Error
	if !errors.As(endErr, &e) || e.Kind != KindOutputLimit {
		t.Fatalf("got (%d, %v)", delivered, endErr)
	}
	if delivered > 100000 {
		t.Fatalf("delivered %d bytes over the limit", delivered)
	}
	if e.Layer < 1 || e.Layer > 3 {
		t.Fatalf("layer %d", e.Layer)
	}
}
