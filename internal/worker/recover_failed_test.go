//go:build recovery

// One-off recovery harness for failed security-deep-dive scans whose
// model output landed on disk but never made it into the DB because the
// strict parser rejected a shape mismatch. Reads the scan id list from
// the SCRUTINEER_RECOVER env var (comma-separated) and re-parses each
// using the now-tolerant code path.
//
//	SCRUTINEER_RECOVER=42,57 go test ./internal/worker \
//	    -tags recovery -run TestRecoverFailedScans -v
//
// Build-tagged so it does not run in CI.
package worker

import (
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

const (
	recoverDBPath   = "/Users/edo/fenster/scrutineer/data/scrutineer.db"
	recoverWorkRoot = "/Users/edo/fenster/scrutineer/data/work"
)

func TestRecoverFailedScans(t *testing.T) {
	ids := os.Getenv("SCRUTINEER_RECOVER")
	if ids == "" {
		t.Skip("set SCRUTINEER_RECOVER=<id>[,<id>…] to run recovery")
	}

	gdb, err := db.Open(recoverDBPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(os.Stderr, nil))}

	for _, raw := range strings.Split(ids, ",") {
		idStr := strings.TrimSpace(raw)
		if idStr == "" {
			continue
		}
		n, err := strconv.ParseUint(idStr, 10, 64)
		if err != nil {
			t.Errorf("bad scan id %q: %v", idStr, err)
			continue
		}
		recoverOne(t, gdb, w, uint(n))
	}
}

func recoverOne(t *testing.T, gdb *gorm.DB, w *Worker, scanID uint) {
	t.Helper()
	reportPath := filepath.Join(recoverWorkRoot, "scan-"+strconv.Itoa(int(scanID)), "report.json")

	var scan db.Scan
	if err := gdb.First(&scan, scanID).Error; err != nil {
		t.Errorf("[scan #%d] load: %v", scanID, err)
		return
	}
	t.Logf("[scan #%d] before: status=%s findings_count=%d report_len=%d",
		scan.ID, scan.Status, scan.FindingsCount, len(scan.Report))
	if scan.Status == db.ScanDone {
		t.Logf("[scan #%d] already Done — skipping", scanID)
		return
	}

	body, err := os.ReadFile(reportPath)
	if err != nil {
		t.Errorf("[scan #%d] read %s: %v", scanID, reportPath, err)
		return
	}

	if err := gdb.Model(&db.Scan{}).Where("id = ?", scanID).
		Update("report", string(body)).Error; err != nil {
		t.Errorf("[scan #%d] save report: %v", scanID, err)
		return
	}
	scan.Report = string(body)

	emit := func(e Event) { t.Logf("[scan #%d] %s", scanID, e.Text) }
	if err := w.parseFindingsOutput(&scan, scan.Report, emit); err != nil {
		t.Errorf("[scan #%d] re-parse: %v", scanID, err)
		return
	}

	if err := gdb.Model(&db.Scan{}).Where("id = ?", scanID).Updates(map[string]any{
		"status":         db.ScanDone,
		"error":          "",
		"findings_count": scan.FindingsCount,
	}).Error; err != nil {
		t.Errorf("[scan #%d] flip status: %v", scanID, err)
		return
	}

	var fresh db.Scan
	gdb.First(&fresh, scanID)
	var n int64
	gdb.Model(&db.Finding{}).Where("scan_id = ?", scanID).Count(&n)
	t.Logf("[scan #%d] after:  status=%s findings_count=%d findings_in_db=%d",
		fresh.ID, fresh.Status, fresh.FindingsCount, n)
}
