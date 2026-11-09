package httpx_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"

	"github.com/FelixMiddelhoff/spillgate"
	"github.com/FelixMiddelhoff/spillgate/httpx"
)

// Server: limit and decode request bodies, answer limit errors with 413.
func ExampleMiddleware() {
	decoder, _ := spillgate.NewDecoder(spillgate.Limits{MaxOutput: 1 << 20})

	handler := httpx.Middleware(decoder)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			httpx.Fail(w, err) // 413, 415 or 400, fixed text
			return
		}
		fmt.Fprintf(w, "got %d bytes", len(body))
	}))

	req := httptest.NewRequest("POST", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	fmt.Println(rec.Code)
	// Output: 200
}

// Client: every response body is decoded under the same limits.
func ExampleNewTransport() {
	decoder, _ := spillgate.NewDecoder(spillgate.Limits{MaxOutput: 8 << 20})
	client := &http.Client{Transport: httpx.NewTransport(nil, decoder)}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "plain")
	}))
	defer srv.Close()

	resp, err := client.Get(srv.URL)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Println(string(body))
	// Output: plain
}
