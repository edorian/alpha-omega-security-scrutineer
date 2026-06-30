package worker

import (
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"scrutineer/internal/db"
)

func newStreamWorker(t *testing.T) (*Worker, db.Repository) {
	t.Helper()
	gdb, err := db.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://x/r", Name: "r"}
	gdb.Create(&repo)
	return &Worker{DB: gdb, DataDir: t.TempDir(), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}, repo
}

func TestPersistStreamedFinding_createsRowFromBody(t *testing.T) {
	w, repo := newStreamWorker(t)
	scan := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "sd", Status: db.ScanRunning, Commit: "aaa", ScanGroup: "grp-1"}
	w.DB.Create(scan)

	body := []byte(`{"id":"F1","title":"t","severity":"High","location":"main.go:10",
		"dup_check":"compared against F0; distinct sink"}`)
	f, err := w.PersistStreamedFinding(scan, body)
	if err != nil {
		t.Fatal(err)
	}
	if f.ID == 0 {
		t.Fatal("streamed finding was not persisted")
	}
	if f.ScanID != scan.ID || f.RepositoryID != repo.ID || f.Commit != "aaa" {
		t.Errorf("scan identity not stamped from the scan: %+v", f)
	}
	if f.DupCheck != "compared against F0; distinct sink" {
		t.Errorf("dup_check = %q, want the emitted sentence", f.DupCheck)
	}
	if f.Fingerprint == "" {
		t.Error("streamed finding has no fingerprint, final report cannot reconcile against it")
	}
}

// A finding streamed mid-scan and then re-ingested from the final report.json
// of the SAME scan must reconcile to one row without inflating seen_count or
// writing a spurious observed-again history row.
func TestPersistStreamedFinding_reconcilesWithFinalReport(t *testing.T) {
	w, repo := newStreamWorker(t)
	scan := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "sd", Status: db.ScanRunning, Commit: "aaa", ScanGroup: "grp-1"}
	w.DB.Create(scan)

	if _, err := w.PersistStreamedFinding(scan, []byte(`{"id":"F1","title":"t","severity":"High","location":"main.go:10"}`)); err != nil {
		t.Fatal(err)
	}

	report := `{"findings":[{"id":"F1","title":"t","severity":"High","location":"main.go:10"}]}`
	if err := w.parseFindingsOutput(&db.Skill{}, scan, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}

	var rows []db.Finding
	w.DB.Find(&rows)
	if len(rows) != 1 {
		t.Fatalf("streamed-then-final reconciled to %d rows, want 1", len(rows))
	}
	if rows[0].SeenCount != 1 {
		t.Errorf("seen_count = %d, want 1 (the same scan must not count a finding twice)", rows[0].SeenCount)
	}
	var observed int64
	w.DB.Model(&db.FindingHistory{}).Where("finding_id = ? AND field = ?", rows[0].ID, "observed").Count(&observed)
	if observed != 0 {
		t.Errorf("observed-again history rows = %d, want 0 for a same-scan reconcile", observed)
	}
}

func TestPersistStreamedFinding_rejectsInvalid(t *testing.T) {
	w, repo := newStreamWorker(t)
	scan := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "sd", Status: db.ScanRunning, Commit: "aaa"}
	w.DB.Create(scan)

	for name, body := range map[string]string{
		"malformed JSON":   `{not json`,
		"missing title":    `{"severity":"High","location":"a.go:1"}`,
		"missing severity": `{"title":"t","location":"a.go:1"}`,
		"missing location": `{"title":"t","severity":"High"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := w.PersistStreamedFinding(scan, []byte(body)); !errors.Is(err, ErrInvalidFinding) {
				t.Errorf("err = %v, want ErrInvalidFinding", err)
			}
		})
	}

	var n int64
	w.DB.Model(&db.Finding{}).Count(&n)
	if n != 0 {
		t.Errorf("invalid findings created %d rows, want 0", n)
	}
}
