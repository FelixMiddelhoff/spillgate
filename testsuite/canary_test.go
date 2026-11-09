package testsuite

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/FelixMiddelhoff/spillgate"
)

// Resource canaries: each bomb is decoded in a child process (this test
// binary, re-run) that has a hard Go memory limit and reports its peak memory.
// The parent checks that the peak stays far below the bomb's output size and
// that the child ends in output_limit. A regression that buffers output (or
// forgets a limit on one codec) shows up here as a failed or oversized child.

const canaryEnv = "SPILLGATE_CANARY_BOMB"

// canaryBudget is the allowed peak (runtime Sys) per codec: window state plus
// read buffers plus runtime overhead, never anywhere near the 1 GiB output.
const canaryBudget = 96 << 20

func TestCanaryChild(t *testing.T) {
	name := os.Getenv(canaryEnv)
	if name == "" {
		t.Skip("only runs as a child of TestCanaryBombs")
	}
	for _, b := range bombs() {
		if b.name != name {
			continue
		}
		data := stream(t, b)
		limits := spillgate.Limits{MaxOutput: 32 << 20, DisableRatioLimit: true}
		// Repeat to catch memory that grows per request.
		var peak uint64
		for i := 0; i < 8; i++ {
			r, err := allCodecs(t, limits).Reader(bytes.NewReader(data), b.encoding)
			if err != nil {
				t.Fatal(err)
			}
			n, err := io.Copy(io.Discard, r)
			r.Close()
			if kind(err) != "output_limit" || n != limits.MaxOutput {
				t.Fatalf("%s: delivered %d, %s", name, n, kind(err))
			}
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			peak = max(peak, m.Sys)
		}
		fmt.Printf("CANARY-PEAK %d\n", peak)
		return
	}
	t.Fatalf("unknown bomb %q", name)
}

func TestCanaryBombs(t *testing.T) {
	if testing.Short() {
		t.Skip("subprocess canaries are skipped with -short")
	}
	for _, b := range bombs() {
		cmd := exec.Command(os.Args[0], "-test.run=^TestCanaryChild$", "-test.v")
		cmd.Env = append(os.Environ(), canaryEnv+"="+b.name, fmt.Sprintf("GOMEMLIMIT=%d", canaryBudget/2))
		done := make(chan struct{})
		var out []byte
		var err error
		go func() { out, err = cmd.CombinedOutput(); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Minute):
			cmd.Process.Kill()
			t.Fatalf("%s: child timed out", b.name)
		}
		if err != nil {
			t.Fatalf("%s: child failed: %v\n%s", b.name, err, out)
		}
		var peak uint64
		for _, line := range strings.Split(string(out), "\n") {
			fmt.Sscanf(line, "CANARY-PEAK %d", &peak)
		}
		if peak == 0 {
			t.Fatalf("%s: no peak reported\n%s", b.name, out)
		}
		t.Logf("%s: peak %d MiB", b.name, peak>>20)
		if peak > canaryBudget {
			t.Errorf("%s: peak %d MiB exceeds %d MiB", b.name, peak>>20, canaryBudget>>20)
		}
	}
}
