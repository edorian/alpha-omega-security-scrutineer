package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

// findingReport renders a single finding as a clean markdown document
// suitable for sharing with an upstream maintainer or affected user.
// Excludes triage-internal data (sinks, CWE codes, model identifiers,
// scan IDs, analyst notes, communications, history) — only the fields
// that carry value to an external reader.
func (s *Server) findingReport(w http.ResponseWriter, r *http.Request) {
	var f db.Finding
	if err := s.DB.Preload("Labels").First(&f, r.PathValue("id")).Error; err != nil {
		http.NotFound(w, r)
		return
	}
	var repo db.Repository
	s.DB.First(&repo, f.RepositoryID)

	body := renderFindingReport(s.DB, &f, &repo)

	filename := findingReportFilename(&f, &repo)
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	_, _ = w.Write([]byte(body))
}

// findingReportFilename builds a descriptive filename like
// "easyadminbundle-flag-countrycode-traversal-xss.md" from the repository
// name and a slugified, length-capped finding title. Falls back to the
// finding ID when no title is available.
func findingReportFilename(f *db.Finding, repo *db.Repository) string {
	const titleMax = 60
	repoSlug := slugify(firstNonEmpty(repo.Name, repo.FullName))
	titleSlug := truncateSlug(slugify(f.Title), titleMax)
	if titleSlug == "" {
		return exportFilename(repoSlug, fmt.Sprintf("finding-%d", f.ID))
	}
	return exportFilename(repoSlug, titleSlug)
}

// exportFilename joins one or more slug components into an "<a>-<b>.md"
// filename, dropping empty pieces. Returns "export.md" if every piece is
// empty so the browser still gets a usable filename hint.
func exportFilename(parts ...string) string {
	kept := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			kept = append(kept, p)
		}
	}
	if len(kept) == 0 {
		return "export.md"
	}
	return strings.Join(kept, "-") + ".md"
}

// slugify lowercases s and collapses any run of non-alphanumeric runes to
// a single "-", trimming leading/trailing dashes.
func slugify(s string) string {
	var b strings.Builder
	prevDash := true
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

// truncateSlug shortens a "-"-separated slug to at most max characters,
// cutting at the last dash within the limit so words aren't bisected.
func truncateSlug(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := strings.LastIndexByte(s[:max], '-')
	if cut <= 0 {
		cut = max
	}
	return strings.Trim(s[:cut], "-")
}

func renderFindingReport(gdb *gorm.DB, f *db.Finding, repo *db.Repository) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", f.Title)

	rows := [][2]string{
		{"Repository", firstNonEmpty(repo.FullName, repo.Name)},
	}
	if repo.URL != "" {
		rows = append(rows, [2]string{"URL", "<" + repo.URL + ">"})
	}
	rows = append(rows,
		[2]string{"Severity", f.Severity},
		[2]string{"Status", string(f.Status)},
		[2]string{"Location", "`" + f.Location + "`"},
		[2]string{"Affected", f.Affected},
		[2]string{"Fix version", f.FixVersion},
		[2]string{"Fix commit", f.FixCommit},
		[2]string{"CVE", f.CVEID},
	)
	if f.CVSSVector != "" {
		cvss := f.CVSSVector
		if f.CVSSScore > 0 {
			cvss = fmt.Sprintf("%s (%.1f)", f.CVSSVector, f.CVSSScore)
		}
		rows = append(rows, [2]string{"CVSS", cvss})
	}
	rows = append(rows, [2]string{"Resolution", string(f.Resolution)})

	fmt.Fprintf(&b, "| Field | Value |\n|---|---|\n")
	for _, r := range rows {
		if r[1] == "" {
			continue
		}
		fmt.Fprintf(&b, "| %s | %s |\n", r[0], r[1])
	}
	b.WriteString("\n")

	if len(f.Labels) > 0 {
		names := make([]string, 0, len(f.Labels))
		for _, l := range f.Labels {
			names = append(names, l.Name)
		}
		fmt.Fprintf(&b, "**Labels:** %s\n\n", strings.Join(names, ", "))
	}

	writeProse(&b, "## Trace", f.Trace)
	writeProse(&b, "## Trust boundary", f.Boundary)
	writeProse(&b, "## Validation", f.Validation)

	if f.DisclosureDraft != "" {
		fmt.Fprintf(&b, "## Disclosure draft\n\n%s\n\n", strings.TrimSpace(f.DisclosureDraft))
	}

	writeFindingReportReproduce(&b, gdb, f.ID)
	writeFindingReferences(&b, gdb, f.ID)

	return b.String()
}

func writeFindingReportReproduce(b *strings.Builder, gdb *gorm.DB, findingID uint) {
	var scan db.Scan
	err := gdb.Where("finding_id = ? AND skill_name = ? AND status = ?",
		findingID, reproduceSkillName, db.ScanDone).
		Order("finished_at desc").First(&scan).Error
	if err != nil || scan.Report == "" {
		return
	}
	var rep reproduceReport
	if err := json.Unmarshal([]byte(scan.Report), &rep); err != nil {
		return
	}

	fmt.Fprintf(b, "## Reproduction\n\n")
	if rep.Outcome != "" {
		fmt.Fprintf(b, "**Outcome:** %s\n\n", rep.Outcome)
	}
	if rep.Language != "" {
		fmt.Fprintf(b, "**Language:** %s\n\n", rep.Language)
	}
	if rep.Command != "" {
		fmt.Fprintf(b, "### Command\n\n```\n%s\n```\n\n", strings.TrimRight(rep.Command, "\n"))
	}
	if rep.PoC != "" {
		fence := "```"
		if rep.Language != "" {
			fence = "```" + rep.Language
		}
		fmt.Fprintf(b, "### Proof of concept\n\n%s\n%s\n```\n\n", fence, strings.TrimRight(rep.PoC, "\n"))
	}
	for _, fx := range rep.Fixtures {
		fmt.Fprintf(b, "### Fixture: `%s`\n\n```\n%s\n```\n\n",
			fx.Path, strings.TrimRight(fx.Content, "\n"))
	}
	if rep.Assumptions != "" {
		fmt.Fprintf(b, "### Assumptions\n\n%s\n\n", strings.TrimSpace(rep.Assumptions))
	}
	if rep.Cleanup != "" {
		fmt.Fprintf(b, "### Cleanup\n\n```\n%s\n```\n\n", strings.TrimRight(rep.Cleanup, "\n"))
	}
}
