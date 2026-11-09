// Package conformance runs the conformance corpus (conformance/manifest.json,
// described in conformance/SCHEMA.md) against a spillgate configuration.
//
// The vectors and their expected outcomes are written by tools/gencorpus from
// the rules of spec/SPEC.md; the runner only checks that the library does what
// the vectors say. The core module runs it without optional codecs, the
// testsuite module runs it with brotli and zstd enabled.
package conformance

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/FelixMiddelhoff/spillgate"
	"github.com/FelixMiddelhoff/spillgate/internal/corpus"
)

// Config says where the corpus is and which optional codecs exist.
type Config struct {
	// Root is the repository root, which holds conformance/ and spec/.
	Root string

	// Codecs maps the names of optional codecs ("br", "zstd") to a function
	// that returns the option enabling them. memoryCap is the vector's
	// options.memory_cap in bytes, or 0 for the codec's default. A vector
	// tagged "needs-br" runs only if Codecs has "br".
	Codecs map[string]func(memoryCap uint64) spillgate.Option

	// NoSkips makes a vector that needs a codec missing from Codecs fail
	// instead of being skipped. The suite that is meant to run everything
	// sets it, so a lost codec cannot hide failures behind skips.
	NoSkips bool

	// Tamper, if set, edits every vector's limits before use. It exists for
	// negative controls: a runner whose limits are weakened must fail, which
	// proves it can fail.
	Tamper func(*spillgate.Limits)
}

type manifestFile struct {
	SchemaVersion int          `json:"schema_version"`
	CorpusVersion string       `json:"corpus_version"`
	Vectors       []vectorSpec `json:"vectors"`
}

type vectorSpec struct {
	ID          string         `json:"id"`
	Description string         `json:"description"`
	Rules       []string       `json:"rules"`
	Refs        []string       `json:"refs"`
	Tags        []string       `json:"tags"`
	Tier        string         `json:"tier"`
	Encodings   []string       `json:"encodings"`
	Input       inputSpec      `json:"input"`
	Limits      map[string]any `json:"limits"`
	ReadPattern []int          `json:"read_pattern"`
	Options     map[string]any `json:"options"`
	Expect      expectSpec     `json:"expect"`
}

type inputSpec struct {
	File      string       `json:"file"`
	Generator *corpus.Spec `json:"generator"`
	SHA256    string       `json:"sha256"`
}

type expectSpec struct {
	Outcome          string `json:"outcome"`
	Length           *int64 `json:"length"`
	SHA256           string `json:"sha256"`
	Phase            string `json:"phase"`
	DeliveredAtMost  *int64 `json:"delivered_at_most"`
	DeliveredExactly *int64 `json:"delivered_exactly"`
	Layer            int    `json:"layer"`
}

var errorOutcomes = map[string]bool{
	"output_limit": true, "ratio_limit": true, "layer_limit": true, "input_limit": true, "memory_limit": true,
	"unsupported_encoding": true, "malformed_encoding": true, "invalid_limits": true, "corrupt": true, "internal": true,
}

func loadManifest(t *testing.T, cfg Config) manifestFile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(cfg.Root, "conformance", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	var m manifestFile
	if err := decoder.Decode(&m); err != nil {
		t.Fatalf("manifest.json does not match the schema: %v", err)
	}
	return m
}

// inputBytes returns the compressed stream of a vector and checks its hash.
func inputBytes(t *testing.T, cfg Config, v vectorSpec) []byte {
	t.Helper()
	var data []byte
	switch {
	case v.Input.File != "" && v.Input.Generator == nil:
		var err error
		if data, err = os.ReadFile(filepath.Join(cfg.Root, "conformance", filepath.FromSlash(v.Input.File))); err != nil {
			t.Fatal(err)
		}
	case v.Input.File == "" && v.Input.Generator != nil:
		var err error
		if data, err = corpus.Generate(*v.Input.Generator); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("%s: input must have exactly one of file and generator", v.ID)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != v.Input.SHA256 {
		t.Fatalf("%s: input hash %s does not match the manifest %s (changed encoder or edited file?)", v.ID, got, v.Input.SHA256)
	}
	return data
}

// bigInt reads a manifest number: a JSON number or a decimal string.
func bigInt(t *testing.T, value any) int64 {
	t.Helper()
	text := ""
	switch x := value.(type) {
	case json.Number:
		text = x.String()
	case string:
		text = x
	default:
		t.Fatalf("not a number: %v", value)
	}
	n, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		t.Fatalf("not an integer: %q", text)
	}
	return n
}

// neededCodecs returns the optional codecs a vector is tagged with.
func neededCodecs(v vectorSpec) []string {
	var names []string
	for _, tag := range v.Tags {
		if name, ok := strings.CutPrefix(tag, "needs-"); ok {
			names = append(names, name)
		}
	}
	return names
}

// translate turns the manifest's limits and options into the library's.
func translate(t *testing.T, cfg Config, v vectorSpec) (spillgate.Limits, []spillgate.Option) {
	t.Helper()
	var limits spillgate.Limits
	var opts []spillgate.Option
	for key, value := range v.Limits {
		switch key {
		case "max_output":
			limits.MaxOutput = bigInt(t, value)
		case "max_layers":
			limits.MaxLayers = int(bigInt(t, value))
		case "max_ratio":
			if text, ok := value.(string); ok && text == "none" {
				limits.DisableRatioLimit = true
			} else {
				limits.MaxRatio = bigInt(t, value)
			}
		case "ratio_grace":
			limits.RatioGrace = bigInt(t, value)
		case "max_input":
			opts = append(opts, spillgate.WithMaxInput(bigInt(t, value)))
		default:
			t.Fatalf("%s: unknown limit %q", v.ID, key)
		}
	}

	var memoryCap uint64
	for key, value := range v.Options {
		switch key {
		case "strict_zlib":
			if value == true {
				opts = append(opts, spillgate.WithStrictZlib())
			}
		case "memory_cap":
			memoryCap = uint64(bigInt(t, value))
		default:
			t.Fatalf("%s: unknown option %q", v.ID, key)
		}
	}
	if cfg.Tamper != nil {
		cfg.Tamper(&limits)
	}
	for _, name := range neededCodecs(v) {
		opts = append(opts, cfg.Codecs[name](memoryCap))
	}
	return limits, opts
}

// outcomeOf names the outcome class of a terminal condition.
func outcomeOf(err error) string {
	var e *spillgate.Error
	switch {
	case err == nil || err == io.EOF:
		return "ok"
	case errors.As(err, &e):
		return e.Kind.String()
	default:
		return "other: " + err.Error()
	}
}

// spySource records how much the library takes from the source.
type spySource struct {
	r     io.Reader
	reads int
	total int64
}

func (s *spySource) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	s.reads++
	s.total += int64(n)
	return n, err
}

// specRuleIDs returns the rule and invariant IDs defined in the spec.
func specRuleIDs(t *testing.T, cfg Config) map[string]bool {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(cfg.Root, "spec", "SPEC.md"))
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^(?:- )?\*\*(SG-(?:R-[A-Z]+-[0-9]{2}|I-[0-9]{2}))\*\*`).FindAllStringSubmatch(string(data), -1) {
		ids[m[1]] = true
	}
	return ids
}

// CheckManifest verifies that the manifest follows the schema's rules and its
// own bookkeeping (unique IDs, existing rules, consistent expectations).
func CheckManifest(t *testing.T, cfg Config) {
	t.Helper()
	m := loadManifest(t, cfg)
	if m.SchemaVersion != 1 || !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(m.CorpusVersion) {
		t.Fatalf("bad header: schema %d, corpus %q", m.SchemaVersion, m.CorpusVersion)
	}
	if len(m.Vectors) < 200 {
		t.Fatalf("only %d vectors", len(m.Vectors))
	}
	idPattern := regexp.MustCompile(`^SG-V-[A-Z]+-[0-9]{4}$`)
	hexPattern := regexp.MustCompile(`^[0-9a-f]{64}$`)
	rules := specRuleIDs(t, cfg)
	seen := map[string]bool{}
	referenced := map[string]bool{}

	for _, v := range m.Vectors {
		switch {
		case !idPattern.MatchString(v.ID):
			t.Errorf("bad id %q", v.ID)
		case seen[v.ID]:
			t.Errorf("duplicate id %s", v.ID)
		case v.Description == "" || len(v.Rules) == 0:
			t.Errorf("%s: description and rules are required", v.ID)
		case v.Tier != "small" && v.Tier != "large":
			t.Errorf("%s: bad tier %q", v.ID, v.Tier)
		case v.Encodings == nil:
			t.Errorf("%s: encodings must be a list", v.ID)
		case !hexPattern.MatchString(v.Input.SHA256):
			t.Errorf("%s: bad input hash", v.ID)
		}
		seen[v.ID] = true
		for _, r := range v.Rules {
			if !rules[r] {
				t.Errorf("%s names %s, which the spec does not define", v.ID, r)
			}
			referenced[r] = true
		}

		e := v.Expect
		if e.Outcome == "ok" {
			if e.Length == nil || !hexPattern.MatchString(e.SHA256) || e.Phase != "" {
				t.Errorf("%s: an ok expectation needs length and sha256 and no phase", v.ID)
			}
			continue
		}
		if !errorOutcomes[e.Outcome] || (e.Phase != "construct" && e.Phase != "read") {
			t.Errorf("%s: bad error expectation %+v", v.ID, e)
		}
		if e.Phase == "construct" && (e.DeliveredAtMost != nil || e.DeliveredExactly != nil) {
			t.Errorf("%s: a construction error delivers nothing", v.ID)
		}
		if v.Limits["max_output"] != nil {
			limit := bigInt(t, v.Limits["max_output"])
			for _, bound := range []*int64{e.DeliveredAtMost, e.DeliveredExactly} {
				if bound != nil && *bound > limit {
					t.Errorf("%s: expects %d bytes delivered under MaxOutput %d", v.ID, *bound, limit)
				}
			}
		}
	}
	t.Logf("%d vectors reference %d rules", len(m.Vectors), len(referenced))
}

// Run executes every vector the configuration can run.
func Run(t *testing.T, cfg Config) {
	t.Helper()
	m := loadManifest(t, cfg)
	for _, v := range m.Vectors {
		t.Run(v.ID, func(t *testing.T) {
			if v.Tier == "large" && testing.Short() {
				t.Skip("large vector skipped in short mode")
			}
			for _, name := range neededCodecs(v) {
				if cfg.Codecs[name] == nil {
					if cfg.NoSkips {
						t.Fatalf("needs the optional codec %q, which is not configured", name)
					}
					t.Skipf("needs the optional codec %q", name)
				}
			}
			input := inputBytes(t, cfg, v)
			patterns := append([][]int{v.ReadPattern}, alternativePatterns...)
			if v.ReadPattern == nil {
				patterns[0] = []int{4096}
			}
			for _, pattern := range patterns {
				if skipTiny(v, pattern) {
					continue
				}
				runPattern(t, cfg, v, input, pattern)
			}
		})
	}
}

// Every vector must give the same result for these read sizes (SG-R-RDR-01).
var alternativePatterns = [][]int{{1}, {3}, {4096}, {-1}, {1, 7, 4096, 1}}

// skipTiny leaves out byte-at-a-time patterns for vectors that deliver many
// megabytes, where they would only cost time.
func skipTiny(v vectorSpec, pattern []int) bool {
	var expected int64
	switch {
	case v.Expect.Length != nil:
		expected = *v.Expect.Length
	case v.Expect.DeliveredExactly != nil:
		expected = *v.Expect.DeliveredExactly
	case v.Expect.DeliveredAtMost != nil:
		expected = *v.Expect.DeliveredAtMost
	}
	if expected <= 4<<20 {
		return false
	}
	for _, size := range pattern {
		if size >= 0 && size < 64 {
			return true
		}
	}
	return false
}

func runPattern(t *testing.T, cfg Config, v vectorSpec, input []byte, pattern []int) {
	t.Helper()
	label := fmt.Sprintf("read pattern %v", pattern)
	limits, opts := translate(t, cfg, v)
	source := &spySource{r: bytes.NewReader(input)}

	decoder, err := spillgate.NewDecoder(limits, opts...)
	var reader io.ReadCloser
	if err == nil {
		reader, err = decoder.Reader(source, v.Encodings...)
	}
	if err != nil {
		checkConstructionError(t, v, label, err, source)
		return
	}
	defer reader.Close()
	if v.Expect.Phase == "construct" {
		t.Fatalf("%s: expected a construction error (%s), got none", label, v.Expect.Outcome)
	}

	delivered, digest, endErr := readWithPattern(reader, pattern, limits.MaxOutput)

	if limits.MaxOutput > 0 && delivered > limits.MaxOutput {
		t.Fatalf("%s: delivered %d bytes, more than MaxOutput %d (SG-I-01)", label, delivered, limits.MaxOutput)
	}
	checkOutcome(t, v, label, delivered, digest, endErr)
	checkSticky(t, label, reader, endErr)
	if raw, ok := v.Limits["max_input"]; ok && source.total > bigInt(t, raw)+1 {
		t.Fatalf("%s: took %d bytes from the source, MaxInput %d allows at most one more than that (SG-R-INP-02)", label, source.total, bigInt(t, raw))
	}
}

func checkConstructionError(t *testing.T, v vectorSpec, label string, err error, source *spySource) {
	t.Helper()
	if v.Expect.Phase != "construct" {
		t.Fatalf("%s: unexpected construction error %v, want %s during %s", label, err, v.Expect.Outcome, v.Expect.Phase)
	}
	if got := outcomeOf(err); got != v.Expect.Outcome {
		t.Fatalf("%s: construction error %q, want %q (%v)", label, got, v.Expect.Outcome, err)
	}
	if source.reads != 0 {
		t.Fatalf("%s: the source was read %d times before the construction error (SG-R-HDR-09)", label, source.reads)
	}
}

// readWithPattern reads to the first error, cycling through the buffer sizes,
// and returns the delivered byte count, the SHA-256 of the delivered bytes and
// the terminal error. A size of -1 means a buffer of MaxOutput+1 bytes, capped
// at 32 MiB.
func readWithPattern(r io.Reader, pattern []int, maxOutput int64) (int64, string, error) {
	digest := sha256.New()
	var delivered int64
	for i := 0; ; i++ {
		size := pattern[i%len(pattern)]
		if size < 0 {
			size = int(min(maxOutput, 32<<20-1) + 1) // written so that 2^63-1 cannot overflow
		}
		buf := make([]byte, size)
		n, err := r.Read(buf)
		digest.Write(buf[:n])
		delivered += int64(n)
		if err != nil {
			return delivered, hex.EncodeToString(digest.Sum(nil)), err
		}
	}
}

func checkOutcome(t *testing.T, v vectorSpec, label string, delivered int64, digest string, err error) {
	t.Helper()
	e := v.Expect
	if got := outcomeOf(err); got != e.Outcome {
		t.Fatalf("%s: outcome %q, want %q (delivered %d, error %v)", label, got, e.Outcome, delivered, err)
	}
	if e.Outcome == "ok" {
		if delivered != *e.Length || digest != e.SHA256 {
			t.Fatalf("%s: delivered %d bytes with hash %s, want %d bytes with hash %s", label, delivered, digest, *e.Length, e.SHA256)
		}
		return
	}
	if e.Phase != "read" {
		t.Fatalf("%s: got a read-phase error but %s was expected at construction", label, e.Outcome)
	}
	if e.DeliveredExactly != nil && delivered != *e.DeliveredExactly {
		t.Fatalf("%s: delivered %d bytes before the error, want exactly %d", label, delivered, *e.DeliveredExactly)
	}
	if e.DeliveredAtMost != nil && delivered > *e.DeliveredAtMost {
		t.Fatalf("%s: delivered %d bytes before the error, want at most %d", label, delivered, *e.DeliveredAtMost)
	}
	var se *spillgate.Error
	if e.Layer != 0 && errors.As(err, &se) && se.Layer != e.Layer {
		t.Fatalf("%s: error in layer %d, want layer %d (%v)", label, se.Layer, e.Layer, err)
	}
}

// checkSticky verifies that after the terminal condition further reads return
// the same result and no data.
func checkSticky(t *testing.T, label string, r io.Reader, endErr error) {
	t.Helper()
	buf := make([]byte, 16)
	for range 3 {
		n, err := r.Read(buf)
		if n != 0 || outcomeOf(err) != outcomeOf(endErr) {
			t.Fatalf("%s: not sticky: (%d, %v) after %v (SG-R-LAY-05)", label, n, err, endErr)
		}
	}
}
