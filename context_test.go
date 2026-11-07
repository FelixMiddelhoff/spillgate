package spillgate

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

// bombDecoder returns a decoder whose limits are so high that only the
// context can stop the 256 MiB bomb.
func bombDecoder(t *testing.T) *Decoder {
	t.Helper()
	d, err := NewDecoder(Limits{MaxOutput: 1 << 40, DisableRatioLimit: true})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// Covers: SG-R-API-04 SG-I-03
func TestCancelBeforeTheFirstRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	r, err := bombDecoder(t).ReaderContext(ctx, bytes.NewReader(bombGzip256(t)), "gzip")
	if err != nil {
		t.Fatal(err)
	}
	cancel()

	_, err = r.Read(make([]byte, 100))
	if !errors.Is(err, ErrCanceled) || !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	var e *Error
	if !errors.As(err, &e) || e.Layer != 1 {
		t.Fatalf("the error should name the layer that noticed it, got %+v", err)
	}
	requireSticky(t, r, ErrCanceled)
}

// Covers: SG-R-API-04
func TestCancelWhileStreamingABomb(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	r, err := bombDecoder(t).ReaderContext(ctx, bytes.NewReader(bombGzip256(t)), "gzip")
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 64<<10)
	var delivered int64
	for range 3 {
		n, err := r.Read(buf)
		delivered += int64(n)
		if err != nil {
			t.Fatal(err)
		}
	}
	cancel()

	n, err := r.Read(buf)
	if n != 0 || !errors.Is(err, ErrCanceled) {
		t.Fatalf("read after cancel: (%d, %v)", n, err)
	}
	if delivered >= 1<<20 {
		t.Fatalf("delivered %d bytes", delivered)
	}
}

// Covers: SG-R-API-04
func TestDeadlineExceededIsReachable(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	_, err := bombDecoder(t).ReadAllContext(ctx, bytes.NewReader(gzipBytes(t, sampleData(100))), "gzip")
	if !errors.Is(err, ErrCanceled) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
}

// The meter looks at the context while it takes input, even if the codec
// itself never returns to the guard in between.
// Covers: SG-R-API-04
func TestCancelIsSeenWhileConsumingInput(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	consumeEverything := codecFunc(func(src Source) (io.Reader, error) {
		return readerFunc(func([]byte) (int, error) {
			cancel() // the context ends while the codec is busy with its input
			for {
				if _, err := src.ReadByte(); err != nil {
					return 0, err
				}
			}
		}), nil
	})
	d, err := NewDecoder(Limits{MaxOutput: 1 << 20}, WithCodec("eat", consumeEverything))
	if err != nil {
		t.Fatal(err)
	}
	src := &countingSource{size: 64 << 20}

	r, _ := d.ReaderContext(ctx, src, "eat")
	_, err = r.Read(make([]byte, 10))
	if !errors.Is(err, ErrCanceled) {
		t.Fatalf("got %v", err)
	}
	if src.handed > 2*meterBufferSize {
		t.Fatalf("source read %d bytes after the cancel", src.handed)
	}
}

// Covers: SG-R-API-04 SG-R-API-02
func TestReadAllContextReturnsNoDataWhenCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := bombDecoder(t).ReadAllContext(ctx, bytes.NewReader(gzipBytes(t, sampleData(100))), "gzip")
	if got != nil || !errors.Is(err, ErrCanceled) {
		t.Fatalf("got (%d bytes, %v)", len(got), err)
	}
}

func TestAContextThatNeverEndsChangesNothing(t *testing.T) {
	data := sampleData(5000)
	got, err := bombDecoder(t).ReadAllContext(context.Background(), bytes.NewReader(gzipBytes(t, data)), "gzip")
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("got %v", err)
	}
}

func TestZeroLengthReadDoesNotLookAtTheContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	r, _ := bombDecoder(t).ReaderContext(ctx, bytes.NewReader(gzipBytes(t, sampleData(10))), "gzip")
	cancel()
	if n, err := r.Read(nil); n != 0 || err != nil {
		t.Fatalf("Read(nil) = (%d, %v)", n, err)
	}
	if _, err := r.Read(make([]byte, 4)); !errors.Is(err, ErrCanceled) {
		t.Fatalf("got %v", err)
	}
}

func TestANilContextIsRejected(t *testing.T) {
	var noContext context.Context
	_, err := bombDecoder(t).ReaderContext(noContext, bytes.NewReader(nil), "gzip")
	if !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("got %v", err)
	}
}
