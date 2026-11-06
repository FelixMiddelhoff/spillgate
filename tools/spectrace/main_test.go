package main

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestExtractDefinitionsFindsBoldBullets(t *testing.T) {
	text := "- **SG-R-LIM-01** text\n- **SG-I-03** text\nplain SG-R-LIM-02 mention\n"
	ids, err := extractDefinitions(text)
	if err != nil {
		t.Fatal(err)
	}
	if !ids["SG-R-LIM-01"] || !ids["SG-I-03"] || ids["SG-R-LIM-02"] {
		t.Fatalf("unexpected ids: %v", ids)
	}
}

func TestExtractDefinitionsRejectsDuplicates(t *testing.T) {
	if _, err := extractDefinitions("- **SG-R-LIM-01** a\n- **SG-R-LIM-01** b\n"); err == nil {
		t.Fatal("duplicate definition not rejected")
	}
}

// The real spec must parse, have unique IDs, and every ID it mentions must be defined.
func TestRealSpecIsWellFormed(t *testing.T) {
	root := filepath.Join("..", "..")
	defined, err := definedIDs(filepath.Join(root, "spec", "SPEC.md"))
	if err != nil {
		t.Fatal(err)
	}
	if len(defined) < 50 {
		t.Fatalf("suspiciously few IDs defined: %d", len(defined))
	}

	text := readFile(t, filepath.Join(root, "spec", "SPEC.md"))
	for _, id := range idPattern.FindAllString(text, -1) {
		if !defined[id] {
			t.Errorf("spec mentions undefined ID %s", id)
		}
	}
}

func TestIDFormat(t *testing.T) {
	valid := regexp.MustCompile(`^SG-(R-[A-Z]+-[0-9]{2}|I-[0-9]{2})$`)
	defined, err := definedIDs(filepath.Join("..", "..", "spec", "SPEC.md"))
	if err != nil {
		t.Fatal(err)
	}
	for id := range defined {
		if !valid.MatchString(id) {
			t.Errorf("bad ID format %q", id)
		}
	}
}
