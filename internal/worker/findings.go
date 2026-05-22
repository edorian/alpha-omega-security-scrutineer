package worker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"scrutineer/internal/db"
)

// scanReport mirrors the security-deep-dive skill's report schema. Only
// `Findings` is consumed downstream — the worker uses scan.RepositoryID,
// scan.Commit, and scan.SubPath from the DB row, not the report. Every
// other top-level field is held as `json.RawMessage` so a model that
// emits the wrong shape (`repository` as a github object, `artefact` as
// an object describing the release, `commit` as `{sha, ref}` instead of
// a hex string, …) cannot derail the parse and lose all findings.
//
// scan #42 was lost to this exact failure mode: a single mis-shaped
// `repository` field nuked an otherwise-valid security-deep-dive
// report. Treating these as opaque blobs is the fix.
type scanReport struct {
	Repository    json.RawMessage `json:"repository"`
	Commit        json.RawMessage `json:"commit"`
	Artefact      json.RawMessage `json:"artefact"`
	SpecVersion   json.RawMessage `json:"spec_version"`
	Model         json.RawMessage `json:"model"`
	Date          json.RawMessage `json:"date"`
	FilesReviewed json.RawMessage `json:"files_reviewed"`
	Languages     json.RawMessage `json:"languages"`
	Findings      []scanFinding   `json:"findings"`
	RuledOut      json.RawMessage `json:"ruled_out"`
	Inventory     json.RawMessage `json:"inventory"`
	Boundaries    json.RawMessage `json:"boundaries"`

	// Legacy fields from the old minimal schema (for backward compat).
	Notes json.RawMessage `json:"notes"`
}

type scanFinding struct {
	ID           string    `json:"id"`
	Sinks        flexSinks `json:"sinks"`
	Title        string    `json:"title"`
	Severity     string    `json:"severity"`
	CWE          string    `json:"cwe"`
	Location     string    `json:"location"`
	Affected     string    `json:"affected"`
	ReachChecked int       `json:"reach_checked"`
	ReachExposed int       `json:"reach_exposed"`

	// Per-step markdown (security-deep-dive schema). Models occasionally
	// emit structured objects ({reproduced, script, output} for validation,
	// {severity, justification} for rating, etc.) — flexProse accepts
	// either a string or any other JSON value, rendering the latter as a
	// fenced JSON block so the analyst still gets the content.
	Trace      flexProse `json:"trace"`
	Boundary   flexProse `json:"boundary"`
	Validation flexProse `json:"validation"`
	PriorArt   flexProse `json:"prior_art"`
	Reach      flexProse `json:"reach"`
	Rating     flexProse `json:"rating"`

	// Aliases observed in the wild. The model sometimes uses
	// `boundary_analysis` for the prose and `trust_boundary` for the
	// boundary id. We fall back through these in toFindings().
	BoundaryAnalysis flexProse `json:"boundary_analysis"`
	TrustBoundary    flexProse `json:"trust_boundary"`

	// Legacy fields (old schema)
	Confidence string `json:"confidence"`
	Summary    string `json:"summary"`
	Details    string `json:"details"`
}

// flexSinks is a list of sink references. The schema says these are
// sink ids ("S1", "S2"), but the model often emits richer objects:
// `[{"file": "x.c", "line": 66, "sink_class": "..."}]`. We accept either
// shape and produce a flat list of strings — sink ids stay verbatim,
// objects collapse to "file:line (class)" so the prose surface still
// reads naturally and the first entry can backfill an empty location.
type flexSinks []string

func (s *flexSinks) UnmarshalJSON(b []byte) error {
	trim := bytes.TrimSpace(b)
	if len(trim) == 0 || bytes.Equal(trim, []byte("null")) {
		*s = nil
		return nil
	}
	if trim[0] != '[' {
		// Non-array — render as a single fenced JSON entry rather than
		// fail. Unusual; preserves the data.
		*s = flexSinks{string(trim)}
		return nil
	}
	var raw []json.RawMessage
	if err := json.Unmarshal(trim, &raw); err != nil {
		return err
	}
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		rt := bytes.TrimSpace(r)
		if len(rt) == 0 {
			continue
		}
		if rt[0] == '"' {
			var str string
			if err := json.Unmarshal(rt, &str); err == nil {
				out = append(out, str)
				continue
			}
		}
		// Object/array/number — try to format known shapes.
		out = append(out, formatSinkRef(rt))
	}
	*s = out
	return nil
}

// formatSinkRef collapses a structured sink reference (file/line/class
// object, or anything else) into the analyst-readable "file:line
// (class)" form. Falls back to compact JSON if the keys aren't there.
func formatSinkRef(raw json.RawMessage) string {
	var ref struct {
		ID        string      `json:"id"`
		File      string      `json:"file"`
		Path      string      `json:"path"`
		Location  string      `json:"location"`
		Line      json.Number `json:"line"`
		LineEnd   json.Number `json:"line_end"`
		Lineno    json.Number `json:"lineno"`
		Class     string      `json:"class"`
		SinkClass string      `json:"sink_class"`
		Kind      string      `json:"kind"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&ref); err != nil {
		// Not an object we can introspect — keep compact JSON.
		var compact bytes.Buffer
		if cerr := json.Compact(&compact, raw); cerr == nil {
			return compact.String()
		}
		return string(raw)
	}
	loc := firstNonEmpty(ref.Location, ref.File, ref.Path)
	line := firstNonEmpty(string(ref.Line), string(ref.Lineno))
	if loc != "" && line != "" {
		loc = loc + ":" + line
	} else if loc == "" {
		loc = ref.ID
	}
	class := firstNonEmpty(ref.SinkClass, ref.Class, ref.Kind)
	switch {
	case loc != "" && class != "":
		return fmt.Sprintf("%s (%s)", loc, class)
	case loc != "":
		return loc
	case class != "":
		return class
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err == nil {
		return compact.String()
	}
	return string(raw)
}

func firstNonEmpty(parts ...string) string {
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			return p
		}
	}
	return ""
}

// sinkLocationHint pulls the "file:line" prefix out of a formatted sink
// reference like `ext/phar/util.c:66 (resource_consumption)`. Returns
// the empty string for sink ids ("S1") or anything that doesn't look
// like a path.
func sinkLocationHint(s string) string {
	if i := strings.Index(s, " ("); i > 0 {
		s = s[:i]
	}
	if !strings.Contains(s, ":") && !strings.Contains(s, "/") && !strings.Contains(s, ".") {
		return ""
	}
	return s
}

// flexProse holds a markdown string. UnmarshalJSON accepts either a JSON
// string (the schema-correct form) or any other JSON value (object,
// array, number, bool), rendering non-strings as a fenced JSON code block
// so the prose surface still gets the content. This protects against
// model output that emits structured objects where the schema asks for
// markdown — losing the data over a tag mismatch is the worst outcome.
type flexProse string

func (f *flexProse) UnmarshalJSON(b []byte) error {
	trim := bytes.TrimSpace(b)
	if len(trim) == 0 || bytes.Equal(trim, []byte("null")) {
		*f = ""
		return nil
	}
	if trim[0] == '"' {
		var s string
		if err := json.Unmarshal(trim, &s); err != nil {
			return err
		}
		*f = flexProse(s)
		return nil
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, trim, "", "  "); err != nil {
		*f = flexProse(string(trim))
	} else {
		*f = flexProse("```json\n" + pretty.String() + "\n```")
	}
	return nil
}

// pickProse returns the first non-empty alternative. Fields with aliases
// (Boundary / BoundaryAnalysis / TrustBoundary) feed through this so the
// canonical key wins when present, but a model that only emitted an alias
// still surfaces the content.
func pickProse(parts ...flexProse) string {
	for _, p := range parts {
		if strings.TrimSpace(string(p)) != "" {
			return string(p)
		}
	}
	return ""
}

// normalizeSeverity title-cases the severity label so the rest of the
// app's case-sensitive enum matching keeps working when the model emits
// "medium" or "MEDIUM" instead of "Medium".
func normalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium", "moderate":
		return "Medium"
	case "low":
		return "Low"
	}
	return s
}

// severityFromProse pulls a severity label out of structured prose
// (typically the rating block when the model nested it as a JSON object
// instead of leaving it at the top level). Cheap regex match: the
// rating prose flexProse has produced is a fenced JSON block, so
// `"severity": "medium"` is reliably present when the data was there.
var severityRe = regexp.MustCompile(`"severity"\s*:\s*"(critical|high|medium|moderate|low)"`)

func severityFromProse(parts ...string) string {
	for _, p := range parts {
		if m := severityRe.FindStringSubmatch(strings.ToLower(p)); m != nil {
			return m[1]
		}
	}
	return ""
}

func parseReport(raw []byte) (scanReport, error) {
	var r scanReport
	if err := json.Unmarshal(raw, &r); err != nil {
		return r, fmt.Errorf("report.json: %w", err)
	}
	return r, nil
}

func (r scanReport) toFindings(scanID, repoID uint, commit, subPath string) []db.Finding {
	out := make([]db.Finding, 0, len(r.Findings))
	for _, f := range r.Findings {
		// Severity is the most-frequently-misplaced field — the model
		// often nests it inside `rating` instead of leaving it at the top
		// level. Fall back through the rating/legacy summary prose so the
		// UI still gets a sortable label.
		sev := normalizeSeverity(f.Severity)
		if sev == "" {
			sev = normalizeSeverity(severityFromProse(string(f.Rating), f.Summary, f.Details))
		}
		// Location is similarly fragile — the model sometimes leaves it
		// null and stuffs the file:line into the first sink reference.
		// Prefer the explicit field; fall back to the first sink's
		// "file:line" prefix when present.
		loc := f.Location
		if loc == "" && len(f.Sinks) > 0 {
			loc = sinkLocationHint(f.Sinks[0])
		}
		out = append(out, db.Finding{
			ScanID:       scanID,
			RepositoryID: repoID,
			Commit:       commit,
			SubPath:      subPath,
			FindingID:    f.ID,
			Sinks:        strings.Join(f.Sinks, ", "),
			Title:        f.Title,
			Severity:     sev,
			CWE:          f.CWE,
			Location:     loc,
			Affected:     f.Affected,
			Trace:        string(f.Trace),
			Boundary:     pickProse(f.Boundary, f.BoundaryAnalysis, f.TrustBoundary),
			Validation:   string(f.Validation),
			PriorArt:     string(f.PriorArt),
			Reach:        string(f.Reach),
			Rating:       string(f.Rating),
		})
	}
	return out
}

// validEmail is a pragmatic filter. Anything without an @ or containing
// "noreply" gets dropped.
func validEmail(s string) bool {
	if !strings.Contains(s, "@") {
		return false
	}
	if strings.Contains(s, "noreply") {
		return false
	}
	return true
}
