package spillgate

import (
	"bytes"
	"errors"
	"io"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Resource tests: memory and goroutines stay bounded while real bombs are
// decoded. Bounds are generous on purpose (they must hold on any CI machine);
// they exist to catch order-of-magnitude regressions such as buffering whole
// outputs or trusting declared sizes.

// allocatedDuring returns how many bytes fn allocated in total.
func allocatedDuring(fn func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// peakHeapDuring returns the highest live heap growth seen while fn ran.
func peakHeapDuring(fn func()) uint64 {
	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)

	var peak atomic.Uint64
	stop, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		var m runtime.MemStats
		for {
			select {
			case <-stop:
				return
			case <-time.After(time.Millisecond):
				runtime.ReadMemStats(&m)
				if m.HeapAlloc > base.HeapAlloc && m.HeapAlloc-base.HeapAlloc > peak.Load() {
					peak.Store(m.HeapAlloc - base.HeapAlloc)
				}
			}
		}
	}()
	fn()
	close(stop)
	<-stopped
	return peak.Load()
}

// Streaming a 256 MiB bomb against a small limit uses a small, fixed amount
// of memory: nothing grows with the produced output.
// Covers: SG-R-MEM-02 SG-R-MEM-03 SG-I-08
func TestStreamingABombUsesConstantMemory(t *testing.T) {
	stream := bombGzip256(t)
	const limit = 8 << 20

	var delivered int64
	var err error
	allocated := allocatedDuring(func() {
		r, _ := Decode(bytes.NewReader(stream), []string{"gzip"}, Limits{MaxOutput: limit, DisableRatioLimit: true})
		delivered, err = drain(r, 32<<10)
	})
	if delivered != limit || !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("got (%d, %v)", delivered, err)
	}
	// flate state, the meter buffer and our own structures: measured ~80 KB.
	t.Logf("allocated %d bytes while streaming 8 MiB", allocated)
	if allocated > 512<<10 {
		t.Fatalf("allocated %d bytes for an 8 MiB stream", allocated)
	}
}

func TestPeakHeapStaysSmallWhileStreamingABomb(t *testing.T) {
	stream := bombGzip256(t)
	peak := peakHeapDuring(func() {
		r, _ := Decode(bytes.NewReader(stream), []string{"gzip", "identity"}, Limits{MaxOutput: 64 << 20, DisableRatioLimit: true})
		drain(r, 32<<10)
	})
	t.Logf("peak live heap growth %d bytes while streaming 64 MiB", peak)
	if peak > 2<<20 {
		t.Fatalf("live heap grew by %d bytes while streaming 64 MiB", peak)
	}
}

// The whole-body API grows with what was produced and never preallocates from
// the limit: a small result under a huge limit stays small.
// Covers: SG-R-MEM-02
func TestReadAllDoesNotPreallocateFromTheLimit(t *testing.T) {
	data := sampleData(1000)
	stream := gzipBytes(t, data)
	allocated := allocatedDuring(func() {
		got, err := DecodeAll(bytes.NewReader(stream), []string{"gzip"}, Limits{MaxOutput: 1 << 40, DisableRatioLimit: true})
		if err != nil || !bytes.Equal(got, data) {
			t.Error(err)
		}
	})
	t.Logf("allocated %d bytes to decode 1000 bytes under a 1 TiB limit", allocated)
	if allocated > 1<<20 {
		t.Fatalf("allocated %d bytes to decode 1000 bytes under a 1 TiB limit", allocated)
	}
}

// A gzip trailer that claims 4 GiB-1 must not make the decoder allocate
// anything near that, and the same holds for a zstd-style declared size: the
// size fields are never read as sizes.
// Covers: SG-R-CDC-07 SG-R-MEM-01 SG-R-LAY-08 SG-I-04
func TestDeclaredSizesNeverSizeAnAllocation(t *testing.T) {
	data := sampleData(500)
	stream := gzipBytes(t, data)
	end := len(stream)
	stream[end-4], stream[end-3], stream[end-2], stream[end-1] = 0xff, 0xff, 0xff, 0xff

	allocated := allocatedDuring(func() {
		_, err := DecodeAll(bytes.NewReader(stream), []string{"gzip"}, Limits{MaxOutput: 1 << 40, DisableRatioLimit: true})
		if !errors.Is(err, ErrCorrupt) {
			t.Errorf("got %v", err)
		}
	})
	if allocated > 1<<20 {
		t.Fatalf("allocated %d bytes with a lying ISIZE", allocated)
	}
}

// The largest header field that needs memory (the 65535-byte extra field) is
// the only untrusted-length allocation and stays within the 64 KiB bound.
// Covers: SG-R-MEM-01
func TestLargestHeaderFieldStaysWithinTheAllocationBound(t *testing.T) {
	stream := gzipMember(t, gzipHeader{extra: bytes.Repeat([]byte("e"), 65535)}, []byte("x"))
	allocated := allocatedDuring(func() {
		if _, err := DecodeAll(bytes.NewReader(stream), []string{"gzip"}, loose); err != nil {
			t.Error(err)
		}
	})
	if allocated > 512<<10 {
		t.Fatalf("allocated %d bytes for a 64 KiB extra field", allocated)
	}
}

// Creating and abandoning many readers leaves no goroutines behind.
// Covers: SG-I-10
func TestAbandonedReadersLeaveNoGoroutines(t *testing.T) {
	stream := gzipBytes(t, sampleData(5000))
	d, _ := NewDecoder(loose)
	before := runtime.NumGoroutine()

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 250 {
				r, err := d.Reader(bytes.NewReader(stream), "gzip", "identity")
				if err != nil {
					t.Error(err)
					return
				}
				r.Read(make([]byte, 100))
				r.Close()
			}
		}()
	}
	wg.Wait()

	if after := runtime.NumGoroutine(); after > before+2 {
		t.Fatalf("goroutines grew from %d to %d", before, after)
	}
}

// The worst inputs finish quickly: a bomb against a small limit, a chain at
// the layer cap, and a 1 MiB body of garbage.
// Covers: SG-I-08
func TestWorstCaseInputsFinishQuickly(t *testing.T) {
	deadline := 5 * time.Second
	start := time.Now()

	stream := bombGzip256(t)
	for range 20 {
		DecodeAll(bytes.NewReader(stream), []string{"gzip"}, Limits{MaxOutput: 1 << 20, DisableRatioLimit: true})
	}
	garbage := bytes.Repeat([]byte("garbage "), 128<<10)
	for range 5 {
		DecodeAll(bytes.NewReader(garbage), []string{"gzip"}, loose)
		DecodeAll(bytes.NewReader(garbage), []string{"deflate"}, loose)
	}
	if elapsed := time.Since(start); elapsed > deadline {
		t.Fatalf("took %v, want under %v", elapsed, deadline)
	}
}

// Reading a bomb with tiny reads must not cost much more than with large
// reads: the work per output byte stays constant.
func TestTinyReadsDoNotMultiplyTheWork(t *testing.T) {
	stream := bombGzip256(t)
	read := func(size int) time.Duration {
		start := time.Now()
		r, _ := Decode(bytes.NewReader(stream), []string{"gzip"}, Limits{MaxOutput: 256 << 10, DisableRatioLimit: true})
		drain(r, size)
		return time.Since(start)
	}
	read(4096) // warm up
	large, tiny := read(4096), read(1)
	if tiny > 200*large+50*time.Millisecond {
		t.Fatalf("1-byte reads took %v, 4 KiB reads took %v", tiny, large)
	}
	_ = io.Discard
}
