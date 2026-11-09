package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/FelixMiddelhoff/spillgate/internal/corpus"
)

// The committed corpus must be exactly what the generator produces: nobody
// edits a vector file or the manifest by hand, and the generator is
// deterministic. If this fails after an intended change, run
// `go run ./tools/gencorpus` and commit the result.
func TestCommittedCorpusIsWhatTheGeneratorProduces(t *testing.T) {
	fresh := t.TempDir()
	b := &builder{files: map[string][]byte{}, large: map[string][]byte{}, counters: map[string]int{}}
	defineVectors(b)
	if err := b.check(); err != nil {
		t.Fatal(err)
	}
	if err := b.write(fresh, ""); err != nil {
		t.Fatal(err)
	}

	repo := filepath.Join("..", "..")
	compare(t, filepath.Join(repo, "conformance", "manifest.json"), filepath.Join(fresh, "conformance", "manifest.json"))
	for path := range b.files {
		compare(t, filepath.Join(repo, "conformance", filepath.FromSlash(path)), filepath.Join(fresh, "conformance", filepath.FromSlash(path)))
	}

	// No stray files in the committed vector directory.
	entries, err := os.ReadDir(filepath.Join(repo, "conformance", "vectors", "small"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(b.files) {
		t.Fatalf("%d committed vector files, generator produces %d", len(entries), len(b.files))
	}
}

func compare(t *testing.T, committed, generated string) {
	t.Helper()
	want, err := os.ReadFile(generated)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(committed)
	if err != nil {
		t.Fatalf("committed file missing: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s differs from the generator output", committed)
	}
}

func TestBuilderRejectsBrokenVectors(t *testing.T) {
	b := &builder{files: map[string][]byte{}, large: map[string][]byte{}, counters: map[string]int{}}
	b.addFile("X", vector{Description: "d", Rules: []string{"SG-R-LIM-01"}, Expect: refused("invalid_limits")}, nil)
	if err := b.check(); err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]vector{
		"no rules":       {Description: "d", Expect: refused("corrupt")},
		"no description": {Rules: []string{"SG-R-LIM-01"}, Expect: refused("corrupt")},
		"no outcome":     {Description: "d", Rules: []string{"SG-R-LIM-01"}},
	} {
		bad := &builder{files: map[string][]byte{}, large: map[string][]byte{}, counters: map[string]int{}}
		bad.addFile("X", v, nil)
		if err := bad.check(); err == nil {
			t.Errorf("%s: not rejected", name)
		}
	}
	dup := &builder{files: map[string][]byte{}, large: map[string][]byte{}, counters: map[string]int{}}
	dup.addFile("X", vector{Description: "d", Rules: []string{"SG-R-LIM-01"}, Expect: refused("corrupt")}, nil)
	dup.vectors = append(dup.vectors, dup.vectors[0])
	if err := dup.check(); err == nil {
		t.Error("duplicate id not rejected")
	}
}

// The frozen source of the MaxInput-on-the-source vectors must still decode to
// the stored gzip stream of 100000 zeros that its description promises.
func TestInputLimitSourceIsFrozen(t *testing.T) {
	zr, err := gzip.NewReader(bytes.NewReader(inputLimitSource))
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	if want := corpus.GzipStored(make([]byte, 100000)); !bytes.Equal(got, want) {
		t.Fatalf("frozen source decodes to %d bytes, not the expected stream of %d", len(got), len(want))
	}
	if len(inputLimitSource) > 1000 {
		t.Errorf("source is %d bytes; it should stay tiny", len(inputLimitSource))
	}
}
