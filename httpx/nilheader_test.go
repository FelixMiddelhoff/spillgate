package httpx_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/FelixMiddelhoff/spillgate/httpx"
)

type okRT struct{}

func (okRT) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Header: http.Header{}, Body: http.NoBody, Request: r}, nil
}

// A request with a nil Header must not make Transport.RoundTrip panic
// (Clone keeps the nil map, then Header.Set assigns into it). The standard
// transport returns an error instead.
func TestTransportNilHeaderDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("RoundTrip panicked on a request with nil Header: %v", r)
		}
	}()
	u, _ := url.Parse("http://example.invalid/")
	tr := httpx.NewTransport(okRT{}, decoder(t, 1<<20))
	tr.RoundTrip(&http.Request{Method: "GET", URL: u})
}

// A nil decoder is a programming error and fails at construction, not on the
// first request.
func TestNilDecoderPanicsAtConstruction(t *testing.T) {
	for name, f := range map[string]func(){
		"NewTransport": func() { httpx.NewTransport(nil, nil) },
		"Middleware":   func() { httpx.Middleware(nil) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: no panic", name)
				}
			}()
			f()
		}()
	}
}
