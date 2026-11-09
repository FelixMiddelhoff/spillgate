// Command spectrace checks that every rule and invariant ID in spec/SPEC.md
// is named by at least one conformance vector or by the doc comment of a test.
//
// Usage: go run ./tools/spectrace [-root dir] [-allow-uncovered]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var idPattern = regexp.MustCompile(`SG-(?:R-[A-Z]+-[0-9]{2}|I-[0-9]{2})`)

// definitionPattern matches an ID at the start of a bold spec bullet or heading line.
var definitionPattern = regexp.MustCompile(`(?m)^(?:- )?\*\*(SG-(?:R-[A-Z]+-[0-9]{2}|I-[0-9]{2}))\*\*`)

func main() {
	root := flag.String("root", ".", "repository root")
	allowUncovered := flag.Bool("allow-uncovered", false, "report uncovered IDs but exit 0")
	flag.Parse()

	defined, err := definedIDs(filepath.Join(*root, "spec", "SPEC.md"))
	if err != nil {
		fail(err)
	}
	covered, err := coveredIDs(*root)
	if err != nil {
		fail(err)
	}

	var missing []string
	for id := range defined {
		if !covered[id] {
			missing = append(missing, id)
		}
	}
	sort.Strings(missing)

	fmt.Printf("defined: %d, covered: %d, uncovered: %d\n", len(defined), len(defined)-len(missing), len(missing))
	for _, id := range missing {
		fmt.Println("uncovered:", id)
	}
	if len(missing) > 0 && !*allowUncovered {
		os.Exit(1)
	}
}

func definedIDs(specPath string) (map[string]bool, error) {
	data, err := os.ReadFile(specPath)
	if err != nil {
		return nil, err
	}
	return extractDefinitions(string(data))
}

// extractDefinitions returns the IDs defined in the spec text and rejects duplicates.
func extractDefinitions(text string) (map[string]bool, error) {
	ids := map[string]bool{}
	for _, m := range definitionPattern.FindAllStringSubmatch(text, -1) {
		if ids[m[1]] {
			return nil, fmt.Errorf("duplicate definition of %s", m[1])
		}
		ids[m[1]] = true
	}
	return ids, nil
}

// coveredIDs collects IDs named by manifest vectors and by _test.go files.
func coveredIDs(root string) (map[string]bool, error) {
	covered := map[string]bool{}

	manifest, err := os.ReadFile(filepath.Join(root, "conformance", "manifest.json"))
	if err != nil {
		return nil, err
	}
	var m struct {
		Vectors []struct {
			Rules []string `json:"rules"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(manifest, &m); err != nil {
		return nil, fmt.Errorf("manifest.json: %w", err)
	}
	for _, v := range m.Vectors {
		for _, r := range v.Rules {
			covered[r] = true
		}
	}

	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "spectrace") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for _, id := range attachedIDs(string(data)) {
			covered[id] = true
		}
		return nil
	})
	return covered, err
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "spectrace:", err)
	os.Exit(2)
}

// attachedIDs returns the IDs named in the doc comment of a Test, Fuzz or
// Example function. An ID that only appears elsewhere (a stray comment, a
// string, a helper) does not count as coverage: the test that protects the
// rule has to say so in its own doc comment.
func attachedIDs(source string) []string {
	var ids []string
	var comment []string
	for _, line := range strings.Split(source, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "//"):
			comment = append(comment, trimmed)
		case strings.HasPrefix(line, "func Test"), strings.HasPrefix(line, "func Fuzz"), strings.HasPrefix(line, "func Example"):
			ids = append(ids, idPattern.FindAllString(strings.Join(comment, "\n"), -1)...)
			comment = nil
		default:
			comment = nil
		}
	}
	return ids
}
