package worker

import (
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/queue"
)

// TestParseFindingsOutput_autoEnqueuesReproduce verifies that a freshly
// created finding triggers a finding-scoped `reproduce` scan when the
// reproduce skill is loaded and active. Re-observed findings (already in
// the DB by fingerprint) must not enqueue a duplicate.
func TestParseFindingsOutput_autoEnqueuesReproduce(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	sqldb, _ := gdb.DB()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	q, err := queue.New(sqldb, log, 0)
	if err != nil {
		t.Fatal(err)
	}

	repo := db.Repository{URL: "https://x/r", Name: "r"}
	gdb.Create(&repo)
	repro := db.Skill{Name: reproduceSkillName, Description: "repro", Body: "b",
		OutputFile: "report.json", OutputKind: "freeform", Version: 1, Active: true, Source: "ui"}
	gdb.Create(&repro)

	w := &Worker{DB: gdb, Log: log, Queue: q}
	emit := func(Event) {}

	mkScan := func(commit string) *db.Scan {
		s := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "security-deep-dive",
			Model: "claude-opus-4-7", Status: db.ScanDone, Commit: commit}
		gdb.Create(s)
		return s
	}

	report := `{"findings":[
		{"id":"F1","title":"SQLi","severity":"High","cwe":"CWE-89","location":"a.go:1"},
		{"id":"F2","title":"XSS","severity":"Medium","cwe":"CWE-79","location":"b.go:1"}
	]}`
	s1 := mkScan("abc")
	if err := w.parseFindingsOutput(s1, report, emit); err != nil {
		t.Fatal(err)
	}

	// Two new findings → two reproduce scans queued, scoped to those
	// findings, with the parent's model carried forward.
	var queued []db.Scan
	gdb.Where("kind = ? AND status = ? AND skill_id = ?", JobSkill, db.ScanQueued, repro.ID).
		Order("id").Find(&queued)
	if len(queued) != 2 {
		t.Fatalf("want 2 reproduce scans queued, got %d", len(queued))
	}
	for _, sc := range queued {
		if sc.FindingID == nil {
			t.Errorf("reproduce scan %d has nil finding_id", sc.ID)
		}
		if sc.RepositoryID != repo.ID {
			t.Errorf("reproduce scan repo = %d, want %d", sc.RepositoryID, repo.ID)
		}
		if sc.Model != "claude-opus-4-7" {
			t.Errorf("reproduce scan model = %q, want parent's model", sc.Model)
		}
		if sc.APIToken == "" {
			t.Errorf("reproduce scan %d missing API token", sc.ID)
		}
	}

	// Re-running the same report on a new parent scan must NOT enqueue
	// another reproduce — the findings are re-observed, not new.
	s2 := mkScan("def")
	if err := w.parseFindingsOutput(s2, report, emit); err != nil {
		t.Fatal(err)
	}
	var stillQueued int64
	gdb.Model(&db.Scan{}).Where("kind = ? AND skill_id = ?", JobSkill, repro.ID).Count(&stillQueued)
	if stillQueued != 2 {
		t.Errorf("re-observed findings must not requeue reproduce; got %d total scans", stillQueued)
	}
}

// TestParseFindingsOutput_skipsAutoReproduceWhenSkillInactive confirms
// that disabling the skill in the DB silently turns off the auto-trigger
// — the operator's escape hatch.
func TestParseFindingsOutput_skipsAutoReproduceWhenSkillInactive(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	sqldb, _ := gdb.DB()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	q, err := queue.New(sqldb, log, 0)
	if err != nil {
		t.Fatal(err)
	}

	repo := db.Repository{URL: "https://x/r", Name: "r"}
	gdb.Create(&repo)
	// gorm's `default:true` tag silently overrides a zero-value bool on
	// Create, so flip Active off in a follow-up Update — this is also how
	// the operator disables a skill from the UI.
	repro := db.Skill{Name: reproduceSkillName, Description: "repro", Body: "b",
		OutputFile: "report.json", OutputKind: "freeform", Version: 1, Active: true, Source: "ui"}
	gdb.Create(&repro)
	gdb.Model(&repro).Update("active", false)

	w := &Worker{DB: gdb, Log: log, Queue: q}
	scan := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "semgrep",
		Model: "claude-opus-4-7", Status: db.ScanDone, Commit: "abc"}
	gdb.Create(scan)

	if err := w.parseFindingsOutput(scan,
		`{"findings":[{"id":"F1","title":"x","severity":"High","cwe":"CWE-89","location":"a.go:1"}]}`,
		func(Event) {}); err != nil {
		t.Fatal(err)
	}

	var n int64
	gdb.Model(&db.Scan{}).Where("skill_id = ?", repro.ID).Count(&n)
	if n != 0 {
		t.Errorf("inactive reproduce skill must not be auto-enqueued; got %d", n)
	}
}
