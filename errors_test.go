package spillgate

import (
	"errors"
	"io"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

// The outcome class names in code and in the spec must be the same set.
// Covers: SG-R-API-05
func TestKindNamesMatchTheSpec(t *testing.T) {
	data, err := os.ReadFile("spec/SPEC.md")
	if err != nil {
		t.Fatal(err)
	}
	line := regexp.MustCompile(`\*\*Outcome class\*\*: one of ([^\n]+)`).FindStringSubmatch(string(data))
	if line == nil {
		t.Fatal("outcome class list not found in spec")
	}
	var specNames []string
	for _, m := range regexp.MustCompile("`([a-z_]+)`").FindAllStringSubmatch(line[1], -1) {
		if m[1] != "ok" { // success is not an error kind
			specNames = append(specNames, m[1])
		}
	}
	var codeNames []string
	for _, name := range kindNames {
		codeNames = append(codeNames, name)
	}
	sort.Strings(specNames)
	sort.Strings(codeNames)
	if !slices.Equal(specNames, codeNames) {
		t.Fatalf("spec classes %v != code classes %v", specNames, codeNames)
	}
}

func TestEveryKindHasASentinel(t *testing.T) {
	sentinels := map[Kind]error{
		KindInvalidLimits: ErrInvalidLimits, KindOutputLimit: ErrOutputLimit, KindRatioLimit: ErrRatioLimit,
		KindLayerLimit: ErrLayerLimit, KindInputLimit: ErrInputLimit, KindMemoryLimit: ErrMemoryLimit,
		KindUnsupportedEncoding: ErrUnsupportedEncoding, KindMalformedEncoding: ErrMalformedEncoding,
		KindCorrupt: ErrCorrupt, KindInternal: ErrInternal, KindCanceled: ErrCanceled, KindSource: ErrSource,
	}
	if len(sentinels) != len(kindNames) {
		t.Fatalf("%d sentinels for %d kinds", len(sentinels), len(kindNames))
	}
	for kind, sentinel := range sentinels {
		if !errors.Is(&Error{Kind: kind}, sentinel) {
			t.Errorf("%v does not match its sentinel", kind)
		}
		for other, otherSentinel := range sentinels {
			if other != kind && errors.Is(&Error{Kind: kind}, otherSentinel) {
				t.Errorf("%v wrongly matches the sentinel of %v", kind, other)
			}
		}
	}
}

func TestKindString(t *testing.T) {
	if got := KindOutputLimit.String(); got != "output_limit" {
		t.Fatalf("got %q", got)
	}
	if got := Kind(0).String(); got != "kind(0)" {
		t.Fatalf("zero Kind should be recognizable, got %q", got)
	}
	if got := Kind(200).String(); got != "kind(200)" {
		t.Fatalf("got %q", got)
	}
}

func TestErrorIsMatchesLayerOnlyWhenTheTargetNamesOne(t *testing.T) {
	err := &Error{Kind: KindOutputLimit, Layer: 2}
	if !errors.Is(err, ErrOutputLimit) {
		t.Error("sentinel without layer must match any layer")
	}
	if !errors.Is(err, &Error{Kind: KindOutputLimit, Layer: 2}) {
		t.Error("same layer must match")
	}
	if errors.Is(err, &Error{Kind: KindOutputLimit, Layer: 3}) {
		t.Error("different layer must not match")
	}
	if errors.Is(err, io.EOF) {
		t.Error("an unrelated error must not match")
	}
}

func TestErrorWrapsItsCause(t *testing.T) {
	cause := errors.New("boom")
	err := &Error{Kind: KindSource, Layer: 1, Cause: cause}
	if !errors.Is(err, cause) {
		t.Error("cause must be reachable through errors.Is")
	}
	var as *Error
	if !errors.As(error(err), &as) || as.Kind != KindSource {
		t.Error("errors.As must find the *Error")
	}
}

func TestErrorMessage(t *testing.T) {
	tests := []struct {
		err  *Error
		want []string
	}{
		{&Error{Kind: KindOutputLimit}, []string{"output_limit"}},
		{&Error{Kind: KindRatioLimit, Layer: 3, Limit: 1000}, []string{"ratio_limit", "layer 3", "limit 1000"}},
		{&Error{Kind: KindCorrupt, Cause: errors.New("bad block")}, []string{"corrupt", "bad block"}},
	}
	for _, tc := range tests {
		msg := tc.err.Error()
		for _, part := range tc.want {
			if !strings.Contains(msg, part) {
				t.Errorf("message %q lacks %q", msg, part)
			}
		}
		if !strings.HasPrefix(msg, "spillgate: ") {
			t.Errorf("message %q lacks the package prefix", msg)
		}
	}
}

func TestWithLayerStampsOnlyUnstampedSpillgateErrors(t *testing.T) {
	unstamped := &Error{Kind: KindCorrupt}
	got := withLayer(unstamped, 4)
	var e *Error
	if !errors.As(got, &e) || e.Layer != 4 {
		t.Fatalf("layer not stamped: %v", got)
	}
	if unstamped.Layer != 0 {
		t.Fatal("withLayer modified its argument")
	}

	stamped := &Error{Kind: KindCorrupt, Layer: 2}
	if withLayer(stamped, 4) != error(stamped) {
		t.Fatal("an already stamped error must be returned unchanged")
	}
	plain := errors.New("plain")
	if withLayer(plain, 4) != plain {
		t.Fatal("a foreign error must be returned unchanged")
	}
}
