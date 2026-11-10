package httpx_test

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/FelixMiddelhoff/spillgate/httpx"
)

type cannedRT struct {
	status int
	body   io.ReadCloser
}

func (c cannedRT) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: c.status,
		Header:     http.Header{"Content-Encoding": {"compress"}}, // unsupported on purpose
		Body:       c.body,
		Request:    r,
	}, nil
}

// Informational responses (1xx) carry no body to decode; 200 does. The edges
// are 100, 199 (passed through) and 99, 200 (decoded, so refused here).
func TestOnlyInformationalStatusesAreBodyless(t *testing.T) {
	for status, passes := range map[int]bool{99: false, 100: true, 199: true, 200: false, 204: true, 304: true} {
		tr := httpx.NewTransport(cannedRT{status, io.NopCloser(strings.NewReader("x"))}, decoder(t, 100))
		req, _ := http.NewRequest("GET", "http://example.invalid/", nil)
		resp, err := tr.RoundTrip(req)
		if resp != nil {
			resp.Body.Close()
		}
		if passes != (err == nil) {
			t.Errorf("status %d: err = %v, want pass-through=%v", status, err, passes)
		}
	}
}

type failingCloser struct {
	io.Reader
	err error
}

func (f failingCloser) Close() error { return f.err }

// Closing the decoded body reports the close error of the network body when
// the decoder itself closed cleanly.
func TestClosingTheBodyReportsTheNetworkCloseError(t *testing.T) {
	boom := errors.New("close failed")
	tr := httpx.NewTransport(plainRT{failingCloser{strings.NewReader("hi"), boom}}, decoder(t, 100))
	req, _ := http.NewRequest("GET", "http://example.invalid/", nil)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(resp.Body)
	if err := resp.Body.Close(); !errors.Is(err, boom) {
		t.Fatalf("Close() = %v, want the network close error", err)
	}
}

type plainRT struct{ body io.ReadCloser }

func (p plainRT) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Header: http.Header{}, Body: p.body, Request: r}, nil
}
