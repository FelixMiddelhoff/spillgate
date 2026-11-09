package conformance

import (
	"errors"
	"os"
	"os/exec"
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

// Negative controls. A runner that cannot fail proves nothing, so the corpus is
// run against decoders whose limits were weakened on purpose; each run must
// end in failures. The weakened run happens in a child process (this test
// binary) because a failing Run would fail this test as well.
const negativeEnv = "SPILLGATE_RUNNER_NEGATIVE"

var tampers = map[string]func(*spillgate.Limits){
	"output limit doubled":   func(l *spillgate.Limits) { l.MaxOutput *= 2 },
	"output limit minus one": func(l *spillgate.Limits) { l.MaxOutput-- },
	"ratio limit disabled":   func(l *spillgate.Limits) { l.DisableRatioLimit = true },
	"ratio limit raised":     func(l *spillgate.Limits) { l.MaxRatio = 1 << 30; l.DisableRatioLimit = false },
	"layers raised":          func(l *spillgate.Limits) { l.MaxLayers = spillgate.HardMaxLayers },
}

func TestRunnerNegativeControlChild(t *testing.T) {
	name := os.Getenv(negativeEnv)
	if name == "" {
		t.Skip("only runs as a child of TestRunnerFailsOnWeakenedLimits")
	}
	Run(t, Config{Root: "../..", Tamper: tampers[name]})
}

func TestRunnerFailsOnWeakenedLimits(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns the corpus run several times")
	}
	for name := range tampers {
		cmd := exec.Command(os.Args[0], "-test.run=^TestRunnerNegativeControlChild$", "-test.short")
		cmd.Env = append(os.Environ(), negativeEnv+"="+name)
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Errorf("%s: the corpus still passes, so the runner would not notice this weakening", name)
			continue
		}
		if !strings.Contains(string(out), "--- FAIL: TestRunnerNegativeControlChild/SG-V-") {
			t.Errorf("%s: child failed, but not on a vector:\n%.500s", name, out)
		}
	}
}
