// Package httpx connects spillgate to net/http.
//
// Client side: [NewTransport] wraps an [http.RoundTripper] so every response
// body is decoded through a [spillgate.Decoder]. The Go transport's own
// transparent gzip is never in play, because the wrapper always sends an
// explicit Accept-Encoding header: net/http only decodes by itself when it
// added that header, and it would do so without any limit.
//
// Server side: [Middleware] decodes request bodies the same way and
// [StatusFor] maps a decoding error to the HTTP status a server should answer.
//
// The package uses nothing but the standard library and the spillgate core.
package httpx

import (
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/FelixMiddelhoff/spillgate"
)

// DefaultAcceptEncoding is what the client transport offers when none is
// configured: the encodings the core supports without optional modules.
var DefaultAcceptEncoding = []string{"gzip", "deflate"}

// bodyless reports whether a response cannot carry a body to decode.
func bodyless(req *http.Request, resp *http.Response) bool {
	return req.Method == http.MethodHead ||
		resp.StatusCode == http.StatusNoContent ||
		resp.StatusCode == http.StatusNotModified ||
		(resp.StatusCode >= 100 && resp.StatusCode < 200) ||
		resp.Body == nil || resp.Body == http.NoBody
}

// Transport is an [http.RoundTripper] that decodes response bodies with
// limits. Use [NewTransport].
type Transport struct {
	base           http.RoundTripper
	decoder        *spillgate.Decoder
	acceptEncoding string
}

// NewTransport panics if decoder is nil. It wraps base (nil means [http.DefaultTransport]). Every response
// body, with or without a Content-Encoding header, is bounded by the decoder's
// limits. acceptEncoding lists the encodings sent in Accept-Encoding; it must
// only name encodings the decoder supports (default [DefaultAcceptEncoding]).
//
// A request that already carries an Accept-Encoding header keeps it. A
// response with an unsupported or malformed Content-Encoding fails the
// round trip: the body is closed and an error satisfying
// errors.Is(err, spillgate.ErrUnsupportedEncoding) (or ErrMalformedEncoding)
// is returned. The decoded body returns spillgate errors from Read; any error
// means the whole body is unusable.
//
// On success the response has Content-Encoding and Content-Length removed,
// ContentLength -1 and Uncompressed true, as with the standard transport.
func NewTransport(base http.RoundTripper, decoder *spillgate.Decoder, acceptEncoding ...string) *Transport {
	if decoder == nil {
		panic("httpx: nil decoder")
	}
	if base == nil {
		base = http.DefaultTransport
	}
	if len(acceptEncoding) == 0 {
		acceptEncoding = DefaultAcceptEncoding
	}
	return &Transport{base: base, decoder: decoder, acceptEncoding: strings.Join(acceptEncoding, ", ")}
}

// RoundTrip implements [http.RoundTripper].
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("Accept-Encoding") == "" {
		req = req.Clone(req.Context()) // never modify the caller's request
		if req.Header == nil {
			req.Header = http.Header{} // Clone keeps a nil map
		}
		req.Header.Set("Accept-Encoding", t.acceptEncoding)
	}
	resp, err := t.base.RoundTrip(req)
	if err != nil || bodyless(req, resp) {
		return resp, err
	}
	decoded, err := t.decoder.ReaderContext(req.Context(), resp.Body, resp.Header.Values("Content-Encoding")...)
	if err != nil {
		resp.Body.Close()
		return nil, err
	}
	resp.Body = &closeBoth{decoded, resp.Body}
	resp.Header.Del("Content-Encoding")
	resp.Header.Del("Content-Length")
	resp.ContentLength = -1
	resp.Uncompressed = true
	return resp, nil
}

// closeBoth closes the decoder and then the network body.
type closeBoth struct {
	io.ReadCloser
	src io.Closer
}

func (c *closeBoth) Close() error {
	err := c.ReadCloser.Close()
	if err2 := c.src.Close(); err == nil {
		err = err2
	}
	return err
}

// StatusFor returns the HTTP status a server should answer for err from
// decoding a request body:
//
//	413  output, ratio, input or layer limit exceeded
//	415  unsupported content encoding
//	400  malformed encoding header, corrupt data, failed read of the connection
//	503  memory limit, canceled
//	500  anything else
//
// It returns 0 for a nil error.
func StatusFor(err error) int {
	if err == nil {
		return 0
	}
	var e *spillgate.Error
	if !errors.As(err, &e) {
		return http.StatusInternalServerError
	}
	switch e.Kind {
	case spillgate.KindOutputLimit, spillgate.KindRatioLimit, spillgate.KindInputLimit, spillgate.KindLayerLimit:
		return http.StatusRequestEntityTooLarge
	case spillgate.KindUnsupportedEncoding:
		return http.StatusUnsupportedMediaType
	case spillgate.KindMalformedEncoding, spillgate.KindCorrupt, spillgate.KindSource:
		return http.StatusBadRequest
	case spillgate.KindMemoryLimit, spillgate.KindCanceled:
		return http.StatusServiceUnavailable
	}
	return http.StatusInternalServerError
}

// Middleware decodes request bodies with decoder before next sees them. It
// panics if decoder is nil.
//
// A request whose Content-Encoding the decoder refuses (unsupported,
// malformed, too many layers) is answered with the status from [StatusFor]
// and never reaches next. Otherwise next gets a body that delivers the
// decoded bytes (also for requests without Content-Encoding, which are bounded
// the same way), with Content-Encoding and Content-Length removed and
// ContentLength -1.
//
// Limit errors appear while next reads the body, after it has started. The
// handler should answer them with [StatusFor]; [Fail] does that:
//
//	body, err := io.ReadAll(r.Body)
//	if err != nil { httpx.Fail(w, err); return }
func Middleware(decoder *spillgate.Decoder) func(http.Handler) http.Handler {
	if decoder == nil {
		panic("httpx: nil decoder")
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body == nil || r.Body == http.NoBody {
				next.ServeHTTP(w, r)
				return
			}
			decoded, err := decoder.ReaderContext(r.Context(), r.Body, r.Header.Values("Content-Encoding")...)
			if err != nil {
				Fail(w, err)
				return
			}
			defer decoded.Close()
			r = r.Clone(r.Context())
			r.Body = decoded
			r.Header.Del("Content-Encoding")
			r.Header.Del("Content-Length")
			r.ContentLength = -1
			next.ServeHTTP(w, r)
		})
	}
}

// Fail answers err with the status from [StatusFor] and a fixed short text.
// The text never contains attacker-controlled data.
func Fail(w http.ResponseWriter, err error) {
	code := StatusFor(err)
	http.Error(w, http.StatusText(code), code)
}
