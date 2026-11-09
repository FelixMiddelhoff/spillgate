package testsuite

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/FelixMiddelhoff/spillgate"
	"github.com/FelixMiddelhoff/spillgate/httpx"
)

// The httpx adapter with all five codecs: a bomb server answers with each
// encoding, the client and the server middleware both end in a limit error.
func TestHTTPXWithAllCodecs(t *testing.T) {
	limits := spillgate.Limits{MaxOutput: 1 << 20, DisableRatioLimit: true}
	for _, b := range bombs() {
		data := stream(t, b)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Encoding", b.encoding)
			w.Write(data)
		}))
		client := &http.Client{Transport: httpx.NewTransport(&http.Transport{}, allCodecs(t, limits), "gzip", "deflate", "br", "zstd")}
		resp, err := client.Get(srv.URL)
		if err != nil {
			t.Fatalf("%s: %v", b.name, err)
		}
		n, err := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		srv.Close()
		if kind(err) != "output_limit" || n != limits.MaxOutput {
			t.Errorf("%s client: %d bytes, %s", b.name, n, kind(err))
		}

		h := httpx.Middleware(allCodecs(t, limits))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := io.Copy(io.Discard, r.Body); err != nil {
				httpx.Fail(w, err)
			}
		}))
		req := httptest.NewRequest("POST", "/", bytes.NewReader(data))
		req.Header.Set("Content-Encoding", b.encoding)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("%s server: status %d", b.name, rec.Code)
		}
	}
}
