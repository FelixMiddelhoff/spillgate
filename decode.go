package spillgate

import (
	"context"
	"fmt"
	"io"
	"maps"
)

// Option adjusts a Decoder. Options never weaken the limits: there is no
// option that raises, disables or bypasses MaxOutput or MaxLayers.
type Option func(*config)

// config collects the options. The first problem found is kept in err and
// reported by NewDecoder.
type config struct {
	strictZlib bool
	maxInput   int64 // 0 means no cap; WithMaxInput never stores 0
	codecs     map[string]Codec
	err        error
}

func (c *config) fail(err error) {
	if c.err == nil {
		c.err = err
	}
}

// WithStrictZlib makes the deflate codec accept only zlib-wrapped streams.
// Without it, a stream that does not start with a valid zlib header is
// decoded as raw deflate (SG-R-CDC-03).
func WithStrictZlib() Option {
	return func(c *config) { c.strictZlib = true }
}

// WithMaxInput caps the number of compressed bytes the first layer may take
// from the source. n must be greater than zero; there is no "unlimited" value
// (SG-R-LIM-06). Without this option the caller is responsible for bounding
// the compressed input.
func WithMaxInput(n int64) Option {
	return func(c *config) {
		if n <= 0 {
			c.fail(invalidLimits("MaxInput must be greater than zero, got %d", n))
			return
		}
		c.maxInput = n
	}
}

// WithCodec makes an additional codec available under name, for example the
// br and zstd codecs from the nested modules. The name must be a lower-case
// token and may not be identity, gzip, deflate or x-gzip. The codec runs
// behind the same limits as the built-in ones (SG-R-CDC-01).
func WithCodec(name string, codec Codec) Option {
	return func(c *config) {
		if err := checkCodecRegistration(name, codec, c.codecs); err != nil {
			c.fail(err)
			return
		}
		c.codecs[name] = codec
	}
}

// Decoder turns Content-Encoding chains into bounded readers. It is immutable
// after NewDecoder and safe for concurrent use; the readers it returns are not
// (SG-R-RDR-07).
type Decoder struct {
	limits   effectiveLimits
	maxInput int64
	codecs   map[string]Codec
}

// NewDecoder validates limits and options and returns a Decoder. It reads no
// data (SG-R-LIM-08).
func NewDecoder(limits Limits, opts ...Option) (*Decoder, error) {
	effective, err := limits.resolve()
	if err != nil {
		return nil, err
	}
	cfg := &config{codecs: map[string]Codec{}}
	for _, opt := range opts {
		opt(cfg)
	}
	if cfg.err != nil {
		return nil, cfg.err
	}

	codecs := map[string]Codec{
		"gzip":    gzipCodec{},
		"deflate": deflateCodec{strict: cfg.strictZlib},
	}
	maps.Copy(codecs, cfg.codecs)
	return &Decoder{limits: effective, maxInput: cfg.maxInput, codecs: codecs}, nil
}

// Reader returns a reader for the decoded bytes of src, whose
// Content-Encoding header values are given in encodings, as received.
//
// All checks that depend only on the header and the limits happen here and
// before any byte is read from src: an invalid, unsupported or too long chain
// is refused without touching the data (SG-R-HDR-09, SG-R-API-03).
//
// Reading may deliver bytes and then fail. Treat any error as failure of the
// whole body. Close the reader when done; this does not close src.
func (d *Decoder) Reader(src io.Reader, encodings ...string) (io.ReadCloser, error) {
	return d.ReaderContext(context.Background(), src, encodings...)
}

// ReaderContext is Reader with cancellation. Once ctx ends, the next Read
// fails with KindCanceled (errors.Is(err, ErrCanceled), and the context's own
// error stays reachable). The context is checked on every Read and every
// 4 KiB taken from the source (SG-R-API-04).
//
// Cancellation cannot interrupt a Read of the source that is already blocked,
// nor a single step inside a codec; the output, ratio and input limits are
// what bound the work.
func (d *Decoder) ReaderContext(ctx context.Context, src io.Reader, encodings ...string) (io.ReadCloser, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: nil context", ErrInvalidOption)
	}
	if src == nil {
		return nil, ErrNilSource
	}
	layers, err := parseContentEncoding(encodings, d.supports, d.limits.maxLayers)
	if err != nil {
		return nil, err
	}
	return d.buildChain(ctx, src, layers)
}

// ReadAll decodes src completely and returns the whole body, or an error and
// no data at all (SG-R-API-02). Memory grows with the bytes actually produced,
// never from declared sizes (SG-R-MEM-02).
func (d *Decoder) ReadAll(src io.Reader, encodings ...string) ([]byte, error) {
	return d.ReadAllContext(context.Background(), src, encodings...)
}

// ReadAllContext is ReadAll with cancellation; see ReaderContext.
func (d *Decoder) ReadAllContext(ctx context.Context, src io.Reader, encodings ...string) ([]byte, error) {
	r, err := d.ReaderContext(ctx, src, encodings...)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	body, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return body, nil
}

// Decode is a shortcut for NewDecoder followed by Decoder.Reader.
func Decode(src io.Reader, encodings []string, limits Limits, opts ...Option) (io.ReadCloser, error) {
	d, err := NewDecoder(limits, opts...)
	if err != nil {
		return nil, err
	}
	return d.Reader(src, encodings...)
}

// DecodeAll is a shortcut for NewDecoder followed by Decoder.ReadAll.
func DecodeAll(src io.Reader, encodings []string, limits Limits, opts ...Option) ([]byte, error) {
	d, err := NewDecoder(limits, opts...)
	if err != nil {
		return nil, err
	}
	return d.ReadAll(src, encodings...)
}

// supports tells the header parser which encodings have a codec.
func (d *Decoder) supports(name string) bool {
	_, ok := d.codecs[name]
	return ok
}

// buildChain stacks one metered, guarded layer per codec name. Layer 1 reads
// the source; every further layer reads the guarded output of the one before.
// Without any codec (empty or identity-only header) a single identity layer
// still bounds the body (SG-R-CDC-10).
func (d *Decoder) buildChain(ctx context.Context, src io.Reader, layers []string) (io.ReadCloser, error) {
	chain := &chainReader{limits: d.limits}
	current := src

	for i := range max(len(layers), 1) {
		index := i + 1
		maxInput := int64(0)
		if index == 1 {
			maxInput = d.maxInput // the cap applies to the chain's source only
		}
		meter := newInputMeter(current, maxInput, index)
		meter.ctx = ctx
		if index == 1 {
			chain.source = meter
		}

		var codec io.Reader = meter // identity: bytes pass through the guard unchanged; taking = passing, so the strict meter
		if len(layers) > 0 {
			var err error
			if codec, err = newContained(d.codecs[layers[i]], codecSource{meter}); err != nil {
				chain.Close()
				return nil, &Error{Kind: KindInternal, Layer: index, Cause: fmt.Errorf("creating the %s decoder: %w", layers[i], err)}
			}
			if closer, ok := codec.(io.Closer); ok {
				chain.closers = append(chain.closers, closer)
			}
		}

		guard := newLayerGuard(codec, meter, index, d.limits)
		guard.ctx = ctx
		chain.top = guard
		current = guard
	}
	return chain, nil
}

// newContained calls codec.NewReader and turns a panic into an error, so a
// misbehaving codec cannot crash the host while the chain is built
// (SG-R-CDC-08, SG-I-05). Only the panic type is reported.
func newContained(codec Codec, src Source) (r io.Reader, err error) {
	defer func() {
		if p := recover(); p != nil {
			r, err = nil, fmt.Errorf("codec panicked (%T)", p)
		}
	}()
	return codec.NewReader(src)
}
