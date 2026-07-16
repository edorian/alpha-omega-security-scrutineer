package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

func seedExposureFinding(t *testing.T, s *Server) (db.Finding, db.Skill) {
	t.Helper()
	repo := db.Repository{URL: "https://github.com/example/lib.git", Name: "lib", FullName: "example/lib"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanDone, SkillName: "security-deep-dive"}
	s.DB.Create(&scan)
	f := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "ReDoS", Severity: "High", Status: db.FindingTriaged}
	s.DB.Create(&f)
	skill := db.Skill{Name: "exposure", Body: "x", Active: true, OutputFile: "report.json", OutputKind: "exposure"}
	s.DB.Create(&skill)
	return f, skill
}

func TestFindingExposureRun_enqueuesScanPerDependent(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	f, skill := seedExposureFinding(t, s)
	for _, name := range []string{"a", "b", "c"} {
		s.DB.Create(&db.Dependent{RepositoryID: f.RepositoryID, Name: name, Ecosystem: "npm",
			RepositoryURL: "https://github.com/example/" + name, DependentRepos: 100})
	}
	skipped := db.Dependent{RepositoryID: f.RepositoryID, Name: "no-url", Ecosystem: "npm", DependentRepos: 50}
	s.DB.Create(&skipped)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("POST", fmt.Sprintf("/findings/%d/exposure", f.ID)))
	if w.Code != 200 && w.Code != 303 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}

	var scans []db.Scan
	s.DB.Where("kind = ? AND skill_id = ?", worker.JobExposure, skill.ID).Find(&scans)
	if len(scans) != 3 {
		t.Fatalf("expected 3 exposure scans, got %d", len(scans))
	}
	for _, sc := range scans {
		if sc.FindingID == nil || sc.DependentID == nil {
			t.Errorf("scan %d missing finding_id or dependent_id", sc.ID)
		}
	}

	var rows []db.FindingDependent
	s.DB.Where("finding_id = ?", f.ID).Find(&rows)
	if len(rows) != 1 || rows[0].DependentID != skipped.ID || rows[0].Status != db.ExposureUnderInvestigation {
		t.Fatalf("expected one under_investigation row for the URL-less dependent, got %+v", rows)
	}
}

func TestRecordSkippedExposure_preservesExistingRow(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	f, _ := seedExposureFinding(t, s)
	dep := db.Dependent{RepositoryID: f.RepositoryID, Name: "no-url", Ecosystem: "npm"}
	if err := s.DB.Create(&dep).Error; err != nil {
		t.Fatalf("seed dependent: %v", err)
	}
	if err := s.DB.Create(&db.FindingDependent{
		FindingID:     f.ID,
		DependentID:   dep.ID,
		Status:        db.ExposureKnownAffected,
		Justification: "old justification",
		Rationale:     "old rationale",
		ScanID:        &f.ScanID,
		ScanCommit:    "old-commit",
	}).Error; err != nil {
		t.Fatalf("seed finding dependent: %v", err)
	}

	if err := s.recordSkippedExposure(f.ID, dep.ID); err != nil {
		t.Fatalf("record skipped exposure: %v", err)
	}

	var rows []db.FindingDependent
	if err := s.DB.Where("finding_id = ? AND dependent_id = ?", f.ID, dep.ID).Find(&rows).Error; err != nil {
		t.Fatalf("load finding dependent: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("finding dependent rows = %d, want 1", len(rows))
	}
	row := rows[0]
	if row.Status != db.ExposureKnownAffected || row.Justification != "old justification" || row.Rationale != "old rationale" {
		t.Errorf("verdict fields = %+v", row)
	}
	if row.ScanID == nil || *row.ScanID != f.ScanID || row.ScanCommit != "old-commit" {
		t.Errorf("scan fields = %+v", row)
	}
}

func TestFindingExposureRun_noDependents422(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f, _ := seedExposureFinding(t, s)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("POST", fmt.Sprintf("/findings/%d/exposure", f.ID)))
	if w.Code != 422 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
}

func TestFindingExposureRun_rejectsZizmorFindings(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://github.com/example/lib.git", Name: "lib"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanDone, SkillName: zizmorSkillName}
	s.DB.Create(&scan)
	f := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "workflow issue", Severity: "High"}
	s.DB.Create(&f)
	s.DB.Create(&db.Skill{Name: exposureSkillName, Body: "x", Active: true, OutputFile: "report.json", OutputKind: "exposure"})
	s.DB.Create(&db.Dependent{RepositoryID: repo.ID, Name: "a",
		RepositoryURL: "https://github.com/example/a", DependentRepos: 1})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("POST", fmt.Sprintf("/findings/%d/exposure", f.ID)))
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), "not supported") {
		t.Errorf("body = %q", w.Body.String())
	}
}

func TestFindingExposureRun_skillMissing412(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://github.com/x/y", Name: "y"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanDone}
	s.DB.Create(&scan)
	f := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "x"}
	s.DB.Create(&f)
	s.DB.Create(&db.Dependent{RepositoryID: repo.ID, Name: "a",
		RepositoryURL: "https://github.com/example/a", DependentRepos: 1})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("POST", fmt.Sprintf("/findings/%d/exposure", f.ID)))
	if w.Code != 412 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), "exposure skill is not installed") {
		t.Errorf("body = %q", w.Body.String())
	}
}
