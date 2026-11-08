package conformance

import (
	"errors"
	"strings"
	"testing"

	"github.com/FelixMiddelhoff/spillgate"
)

// Sanity of the runner's own helpers.
func TestRunnerHelpers(t *testing.T) {
	if got := outcomeOf(nil); got != "ok" {
		t.Fatal(got)
	}
	if got := outcomeOf(spillgate.ErrCorrupt); got != "corrupt" {
		t.Fatal(got)
	}
	if got := outcomeOf(errors.New("x")); !strings.HasPrefix(got, "other") {
		t.Fatal(got)
	}

	tiny := vectorSpec{Expect: expectSpec{Length: new(int64)}}
	*tiny.Expect.Length = 100 << 20
	if !skipTiny(tiny, []int{1}) || skipTiny(tiny, []int{4096}) {
		t.Fatal("skipTiny misjudges")
	}

	tagged := vectorSpec{Tags: []string{"bomb", "needs-br", "needs-zstd"}}
	if got := neededCodecs(tagged); len(got) != 2 || got[0] != "br" || got[1] != "zstd" {
		t.Fatalf("neededCodecs = %v", got)
	}
}
