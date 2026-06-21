package web

import (
	"testing"

	"scrutineer/internal/config"
)

// TestEffortsMatchConfig guards against drift between web.Efforts (the source
// of truth, coupled to display labels) and config.Efforts (the independent
// list config.Load validates against at startup). Add a level to one and this
// fails until the other catches up.
func TestEffortsMatchConfig(t *testing.T) {
	if len(Efforts) != len(config.Efforts) {
		t.Fatalf("len(web.Efforts)=%d, len(config.Efforts)=%d", len(Efforts), len(config.Efforts))
	}
	for i, e := range Efforts {
		if e.Value != config.Efforts[i] {
			t.Errorf("Efforts[%d]=%q, config.Efforts[%d]=%q", i, e.Value, i, config.Efforts[i])
		}
		if err := config.ValidateEffort(e.Value); err != nil {
			t.Errorf("config.ValidateEffort(%q) = %v, want nil", e.Value, err)
		}
	}
}

func TestValidEffort(t *testing.T) {
	for _, e := range []string{"low", "medium", "high", "xhigh", "max"} {
		if !ValidEffort(e) {
			t.Errorf("ValidEffort(%q) = false, want true", e)
		}
	}
	for _, e := range []string{"", "High", "extreme", "garbage"} {
		if ValidEffort(e) {
			t.Errorf("ValidEffort(%q) = true, want false", e)
		}
	}
}

func TestDefaultEffort(t *testing.T) {
	defer restoreEffort(defaultEffortOverride)

	defaultEffortOverride = ""
	if got := DefaultEffort(); got != builtinDefaultEffort {
		t.Errorf("DefaultEffort() with no override = %q, want %q", got, builtinDefaultEffort)
	}
	defaultEffortOverride = "max"
	if got := DefaultEffort(); got != "max" {
		t.Errorf("DefaultEffort() with override = %q, want max", got)
	}
}

func TestSetDefaultEffort(t *testing.T) {
	defer restoreEffort(defaultEffortOverride)

	defaultEffortOverride = "high"
	SetDefaultEffort("xhigh")
	if defaultEffortOverride != "xhigh" {
		t.Errorf("SetDefaultEffort(xhigh) = %q, want xhigh", defaultEffortOverride)
	}
	// An empty or unknown value must not clobber the current setting.
	SetDefaultEffort("")
	SetDefaultEffort("garbage")
	if defaultEffortOverride != "xhigh" {
		t.Errorf("invalid SetDefaultEffort changed it to %q, want xhigh", defaultEffortOverride)
	}
}

func restoreEffort(v string) { defaultEffortOverride = v }
