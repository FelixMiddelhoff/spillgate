package httpx_test

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/FelixMiddelhoff/spillgate"
	"github.com/FelixMiddelhoff/spillgate/httpx"
	"github.com/FelixMiddelhoff/spillgate/internal/corpus"
)

func decoder(t *testing.T, max int64) *spillgate.Decoder {
	t.Helper()
	d, err := spillgate.NewDecoder(spillgate.Limits{MaxOutput: max})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func gz(b []byte) []byte {
	var o bytes.Buffer
	w := gzip.NewWriter(&o)
	w.Write(b)
	w.Close()
	return o.Bytes()
}

// bomb is a gzip stream of about 4 GB of zeros in 4 MB.
func bomb(t *testing.T) []byte {
	t.Helper()
	b, err := corpus.Generate(corpus.Zeros("gzip", 4_161_000))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// server sends body with the given Content-Encoding header values and records
// the Accept-Encoding it received.
func server(t *testing.T, body []byte, encodings ...string) (*httptest.Server, *string) {
	t.Helper()
	var accept string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accept = r.Header.Get("Accept-Encoding")
		for _, e := range encodings {
			w.Header().Add("Content-Encoding", e)
		}
		w.Write(body)
	}))
	t.Cleanup(s.Close)
	return s, &accept
}

func client(d *spillgate.Decoder) *http.Client {
	return &http.Client{Transport: httpx.NewTransport(&http.Transport{}, d)}
}

func TestClientDecodesAndRewritesResponse(t *testing.T) {
	s, accept := server(t, gz([]byte("hello")), "gzip")
	resp, err := client(decoder(t, 1<<20)).Get(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil || string(got) != "hello" {
		t.Fatalf("%q %v", got, err)
	}
	if *accept != "gzip, deflate" {
		t.Errorf("Accept-Encoding = %q", *accept)
	}
	if resp.Header.Get("Content-Encoding") != "" || resp.Header.Get("Content-Length") != "" ||
		resp.ContentLength != -1 || !resp.Uncompressed {
		t.Errorf("response not rewritten: %+v", resp.Header)
	}
}

// The standard transport must never decode first: with an explicit
// Accept-Encoding it hands the raw bytes to spillgate. A bomb therefore ends
// in a limit error instead of filling memory.
func TestClientBombEndsInLimit(t *testing.T) {
	s, _ := server(t, bomb(t), "gzip")
	resp, err := client(decoder(t, 1<<20)).Get(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	n, err := io.Copy(io.Discard, resp.Body)
	if !errors.Is(err, spillgate.ErrOutputLimit) && !errors.Is(err, spillgate.ErrRatioLimit) {
		t.Fatalf("err = %v after %d bytes", err, n)
	}
	if n > 1<<20 {
		t.Errorf("delivered %d bytes, limit 1 MiB", n)
	}
}

// A server that sends plain bytes and claims no encoding is bounded too.
func TestClientPlainBodyStillBounded(t *testing.T) {
	s, _ := server(t, bytes.Repeat([]byte("x"), 3<<20))
	resp, err := client(decoder(t, 1<<20)).Get(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); !errors.Is(err, spillgate.ErrOutputLimit) {
		t.Fatalf("err = %v", err)
	}
}

func TestClientRefusesBadEncodingHeaders(t *testing.T) {
	for name, tc := range map[string]struct {
		enc  []string
		want error
	}{
		"unsupported": {[]string{"compress"}, spillgate.ErrUnsupportedEncoding},
		"malformed":   {[]string{"gzip;q=1"}, spillgate.ErrMalformedEncoding},
		"too deep":    {[]string{strings.Repeat("gzip, ", 8) + "gzip"}, spillgate.ErrLayerLimit},
		"unknown dcz": {[]string{"gzip", "dcz"}, spillgate.ErrUnsupportedEncoding},
	} {
		s, _ := server(t, []byte("whatever"), tc.enc...)
		resp, err := client(decoder(t, 1<<20)).Get(s.URL)
		if resp != nil {
			resp.Body.Close()
		}
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", name, err, tc.want)
		}
	}
}

func TestClientKeepsCallerAcceptEncodingAndRequest(t *testing.T) {
	s, accept := server(t, []byte("plain"))
	req, _ := http.NewRequest("GET", s.URL, nil)
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := client(decoder(t, 100)).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if *accept != "gzip" {
		t.Errorf("caller header replaced: %q", *accept)
	}

	req2, _ := http.NewRequest("GET", s.URL, nil)
	resp, err = client(decoder(t, 100)).Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if req2.Header.Get("Accept-Encoding") != "" {
		t.Error("caller's request was modified")
	}
}

func TestClientBodylessResponsesPassThrough(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "compress") // meaningless on HEAD and 204
		if r.Method == "GET" {
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer s.Close()
	c := client(decoder(t, 100))
	for _, m := range []string{"HEAD", "GET"} {
		req, _ := http.NewRequest(m, s.URL, nil)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", m, err)
		}
		resp.Body.Close()
	}
}

// The server middleware.

func app(t *testing.T, max int64) http.Handler {
	t.Helper()
	return httpx.Middleware(decoder(t, max))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Encoding") != "" || r.ContentLength != -1 {
			t.Errorf("headers not rewritten: %q %d", r.Header.Get("Content-Encoding"), r.ContentLength)
		}
		b, err := io.ReadAll(r.Body)
		if err != nil {
			httpx.Fail(w, err)
			return
		}
		w.Write(b)
	}))
}

func post(h http.Handler, body []byte, encodings ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/", bytes.NewReader(body))
	for _, e := range encodings {
		req.Header.Add("Content-Encoding", e)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestMiddlewareStatuses(t *testing.T) {
	tests := []struct {
		name string
		body []byte
		enc  []string
		code int
	}{
		{"ok gzip", gz([]byte("hi")), []string{"gzip"}, 200},
		{"ok identity", []byte("hi"), nil, 200},
		{"bomb", bomb(t), []string{"gzip"}, 413},
		{"plain too big", bytes.Repeat([]byte("x"), 3<<20), nil, 413},
		{"unsupported", []byte("x"), []string{"compress"}, 415},
		{"malformed", []byte("x"), []string{"gzip;q=1"}, 400},
		{"too deep", []byte("x"), []string{strings.Repeat("gzip,", 9) + "gzip"}, 413},
		{"corrupt", []byte("not gzip at all"), []string{"gzip"}, 400},
		{"truncated", gz(bytes.Repeat([]byte("abc"), 1000))[:20], []string{"gzip"}, 400},
	}
	h := app(t, 1<<20)
	for _, tc := range tests {
		rec := post(h, tc.body, tc.enc...)
		if rec.Code != tc.code {
			t.Errorf("%s: status %d, want %d (%q)", tc.name, rec.Code, tc.code, rec.Body.String())
		}
	}
}

func TestMiddlewareEmptyBodyPassesThrough(t *testing.T) {
	called := false
	h := httpx.Middleware(decoder(t, 10))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	req := httptest.NewRequest("GET", "/", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)
	if !called {
		t.Error("handler not called")
	}
}

func TestStatusForAndFail(t *testing.T) {
	if httpx.StatusFor(nil) != 0 {
		t.Error("nil")
	}
	if httpx.StatusFor(errors.New("boom")) != 500 {
		t.Error("foreign error")
	}
	for err, want := range map[error]int{
		spillgate.ErrOutputLimit: 413, spillgate.ErrRatioLimit: 413, spillgate.ErrInputLimit: 413,
		spillgate.ErrLayerLimit: 413, spillgate.ErrUnsupportedEncoding: 415, spillgate.ErrMalformedEncoding: 400,
		spillgate.ErrCorrupt: 400, spillgate.ErrSource: 400, spillgate.ErrMemoryLimit: 503,
		spillgate.ErrCanceled: 503, spillgate.ErrInternal: 500,
	} {
		if got := httpx.StatusFor(err); got != want {
			t.Errorf("%v: %d, want %d", err, got, want)
		}
	}
	rec := httptest.NewRecorder()
	httpx.Fail(rec, spillgate.ErrOutputLimit)
	if rec.Code != 413 || strings.TrimSpace(rec.Body.String()) != "Request Entity Too Large" {
		t.Errorf("Fail: %d %q", rec.Code, rec.Body.String())
	}
}
