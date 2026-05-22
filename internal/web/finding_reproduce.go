package web

import (
	"encoding/json"
	"fmt"

	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

const reproduceSkillName = "reproduce"

// reproduceFixture mirrors one entry in reproduce/schema.json#/properties/fixtures.
type reproduceFixture struct {
	Path     string `json:"path"`
	Encoding string `json:"encoding"`
	Content  string `json:"content"`
}

// reproduceReport is the subset of the reproduce skill's report.json the UI
// renders. Mirrors skills/reproduce/schema.json.
type reproduceReport struct {
	Outcome     string             `json:"outcome"`
	Language    string             `json:"language"`
	Command     string             `json:"command"`
	PoC         string             `json:"poc"`
	Fixtures    []reproduceFixture `json:"fixtures"`
	Transcript  string             `json:"transcript"`
	ExitCode    *int               `json:"exit_code,omitempty"`
	Assumptions string             `json:"assumptions"`
	Cleanup     string             `json:"cleanup"`
	Notes       string             `json:"notes"`
	Error       string             `json:"error"`
}

// latestReproduceScan returns the most recent done reproduce-skill scan for a
// finding along with its parsed report. The three nil return is the
// "nothing to show" path (no scan, empty report, or parse error) — the UI
// renders an explicit "no reproduction" notice in that case.
func (s *Server) latestReproduceScan(findingID uint) (*db.Scan, *reproduceReport) {
	var scan db.Scan
	err := s.DB.
		Where("finding_id = ? AND kind = ? AND skill_name = ? AND status = ?",
			findingID, worker.JobSkill, reproduceSkillName, db.ScanDone).
		Order("finished_at desc").
		First(&scan).Error
	if err != nil {
		return nil, nil
	}
	if scan.Report == "" {
		return &scan, nil
	}
	var rep reproduceReport
	if err := json.Unmarshal([]byte(scan.Report), &rep); err != nil {
		return &scan, &reproduceReport{Error: fmt.Sprintf("parse error: %v", err)}
	}
	return &scan, &rep
}
