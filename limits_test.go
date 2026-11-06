package spillgate

import (
	"errors"
	"math"
	"strings"
	"testing"
)

// Covers: SG-R-LIM-01 SG-R-LIM-02 SG-R-LIM-03 SG-R-LIM-04 SG-R-LIM-05 SG-R-LIM-07 SG-R-LIM-08
func TestLimitsValidation(t *testing.T) {
	tests := []struct {
		name      string
		limits    Limits
		wantField string // empty means the limits must be valid
	}{
		{"zero value has no MaxOutput", Limits{}, "MaxOutput"},
		{"negative MaxOutput", Limits{MaxOutput: -1}, "MaxOutput"},
		{"MinInt64 MaxOutput", Limits{MaxOutput: math.MinInt64}, "MaxOutput"},
		{"smallest MaxOutput", Limits{MaxOutput: 1}, ""},
		{"largest MaxOutput", Limits{MaxOutput: math.MaxInt64}, ""},

		{"MaxLayers zero means default", Limits{MaxOutput: 1, MaxLayers: 0}, ""},
		{"MaxLayers negative", Limits{MaxOutput: 1, MaxLayers: -1}, "MaxLayers"},
		{"MaxLayers at hard max", Limits{MaxOutput: 1, MaxLayers: HardMaxLayers}, ""},
		{"MaxLayers above hard max", Limits{MaxOutput: 1, MaxLayers: HardMaxLayers + 1}, "MaxLayers"},
		{"MaxLayers way above hard max", Limits{MaxOutput: 1, MaxLayers: math.MaxInt32}, "MaxLayers"},

		{"MaxRatio negative", Limits{MaxOutput: 1, MaxRatio: -1}, "MaxRatio"},
		{"MaxRatio one", Limits{MaxOutput: 1, MaxRatio: 1}, ""},
		{"MaxRatio at hard max", Limits{MaxOutput: 1, MaxRatio: HardMaxRatio}, ""},
		{"MaxRatio above hard max", Limits{MaxOutput: 1, MaxRatio: HardMaxRatio + 1}, "MaxRatio"},
		{"MaxRatio MaxInt64", Limits{MaxOutput: 1, MaxRatio: math.MaxInt64}, "MaxRatio"},

		{"ratio opt-out alone", Limits{MaxOutput: 1, DisableRatioLimit: true}, ""},
		{"ratio opt-out with MaxRatio", Limits{MaxOutput: 1, DisableRatioLimit: true, MaxRatio: 5}, "MaxRatio"},
		{"ratio opt-out with negative MaxRatio", Limits{MaxOutput: 1, DisableRatioLimit: true, MaxRatio: -1}, "MaxRatio"},

		{"RatioGrace negative", Limits{MaxOutput: 1, RatioGrace: -1}, "RatioGrace"},
		{"RatioGrace positive", Limits{MaxOutput: 1, RatioGrace: 1}, ""},
		{"RatioGrace MaxInt64", Limits{MaxOutput: 1, RatioGrace: math.MaxInt64}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.limits.Validate()
			if tc.wantField == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidLimits) {
				t.Fatalf("Validate() = %v, want ErrInvalidLimits", err)
			}
			if !strings.Contains(err.Error(), tc.wantField) {
				t.Fatalf("error %q does not name field %s", err, tc.wantField)
			}
		})
	}
}

// Covers: SG-R-LIM-03 SG-R-LIM-04 SG-R-LIM-05
func TestLimitsDefaults(t *testing.T) {
	got := mustResolve(t, Limits{MaxOutput: 42})
	want := effectiveLimits{
		maxOutput:  42,
		maxLayers:  DefaultMaxLayers,
		maxRatio:   DefaultMaxRatio,
		ratioGrace: DefaultRatioGrace,
	}
	if got != want {
		t.Fatalf("defaults = %+v, want %+v", got, want)
	}
}

// Covers: SG-R-LIM-04 SG-R-LIM-07
func TestRatioOptOutIsExplicit(t *testing.T) {
	off := mustResolve(t, Limits{MaxOutput: 1, DisableRatioLimit: true})
	if off.maxRatio != 0 {
		t.Fatalf("opt-out should resolve to maxRatio 0, got %d", off.maxRatio)
	}
	// No numeric MaxRatio may end up as "disabled".
	for _, ratio := range []int64{1, 2, 1000, HardMaxRatio} {
		if got := mustResolve(t, Limits{MaxOutput: 1, MaxRatio: ratio}); got.maxRatio != ratio {
			t.Fatalf("MaxRatio %d resolved to %d", ratio, got.maxRatio)
		}
	}
}

// Covers: SG-R-LIM-09
func TestResolvedLimitsAreIndependentOfTheCallersStruct(t *testing.T) {
	l := Limits{MaxOutput: 10}
	resolved := mustResolve(t, l)
	l.MaxOutput = 1 << 40
	if resolved.maxOutput != 10 {
		t.Fatalf("resolved limits changed with the caller's struct: %d", resolved.maxOutput)
	}
}

// Covers: SG-R-RAT-01
func TestRatioExceeded(t *testing.T) {
	limits := effectiveLimits{maxOutput: math.MaxInt64, maxRatio: 10, ratioGrace: 100}
	tests := []struct {
		name               string
		produced, consumed int64
		want               bool
	}{
		{"below grace is never checked", 100, 0, false},
		{"one past grace, ratio far exceeded", 101, 1, true},
		{"exactly at ratio is allowed", 1000, 100, false},
		{"one byte over the ratio", 1001, 100, true},
		{"zero consumed counts as one", 11, 0, false}, // below grace anyway
		{"zero consumed, past grace", 101, 0, true},
		{"large and fine", math.MaxInt64 - 1, math.MaxInt64 / 2, false},
		{"MaxInt64 produced from one byte", math.MaxInt64, 1, true},
		{"MaxInt64 produced from MaxInt64 bytes", math.MaxInt64, math.MaxInt64, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := limits.ratioExceeded(tc.produced, tc.consumed); got != tc.want {
				t.Fatalf("ratioExceeded(%d, %d) = %v, want %v", tc.produced, tc.consumed, got, tc.want)
			}
		})
	}
}

// Covers: SG-R-RAT-04
func TestRatioExceededIsOffWhenDisabled(t *testing.T) {
	off := effectiveLimits{maxOutput: math.MaxInt64, maxRatio: 0, ratioGrace: 1}
	if off.ratioExceeded(math.MaxInt64, 1) {
		t.Fatal("disabled ratio limit still fired")
	}
}

// Covers: SG-R-RAT-01
func TestRatioGraceBoundary(t *testing.T) {
	limits := effectiveLimits{maxOutput: math.MaxInt64, maxRatio: 1, ratioGrace: 1000}
	if limits.ratioExceeded(1000, 1) {
		t.Fatal("output equal to the grace must not be checked")
	}
	if !limits.ratioExceeded(1001, 1) {
		t.Fatal("output one past the grace must be checked")
	}
}
