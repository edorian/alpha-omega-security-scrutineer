package worker

import (
	"strings"
	"testing"

	"scrutineer/internal/db"
)

// TestParseReport_repositoryAsObject covers the regression that nuked
// security-deep-dive scan #42: the model emitted `repository` as a
// github-shaped object instead of the schema's URI string. The parser
// must accept either form (the field is informational only — the worker
// uses scan.RepositoryID from the DB, not this).
func TestParseReport_repositoryAsObject(t *testing.T) {
	raw := []byte(`{
		"spec_version": 10,
		"date": "2026-05-07",
		"repository": {
			"url": "https://github.com/spatie/laravel-medialibrary.git",
			"name": "laravel-medialibrary",
			"full_name": "spatie/laravel-medialibrary"
		},
		"commit": "abc1234",
		"languages": ["php"],
		"findings": [
			{"id": "F1", "title": "x", "severity": "Medium", "cwe": "CWE-79", "location": "a.php:1"}
		],
		"inventory": [],
		"ruled_out": [],
		"boundaries": []
	}`)
	rep, err := parseReport(raw)
	if err != nil {
		t.Fatalf("repository-as-object must not fail parse: %v", err)
	}
	if len(rep.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(rep.Findings))
	}
	if rep.Findings[0].Title != "x" {
		t.Errorf("finding title: %q", rep.Findings[0].Title)
	}
}

// TestParseReport_proseFieldsAsObjects covers the next failure modes
// hit on scan #42 once `repository` was tolerant: validation, rating,
// prior_art, reach all came as structured objects instead of markdown
// strings. flexProse renders any non-string JSON as a fenced block so
// the prose surface still carries the data.
func TestParseReport_proseFieldsAsObjects(t *testing.T) {
	raw := []byte(`{
		"spec_version": 10,
		"date": "2026-05-07",
		"repository": "https://example.com",
		"commit": "abc",
		"languages": ["php"],
		"findings": [{
			"id": "F1",
			"title": "Stored XSS",
			"severity": "medium",
			"cwe": "CWE-79",
			"location": "src/x.php:42",
			"trace": [
				{"step": 1, "description": "user uploads filename"},
				{"step": 2, "description": "filename hits sink"}
			],
			"validation": {
				"reproduced": true,
				"script": "php -r 'echo 1;'",
				"output": "<img title=\"x\" onmouseover=\"alert(1)\">",
				"explanation": "double-quote breaks attribute"
			},
			"boundary_analysis": "user → sanitiser → blade",
			"prior_art": {"advisories": [], "searched": ["packagist"]},
			"reach": {"package_downloads": 35515732, "dependent_repos": 4164},
			"rating": {"severity": "medium", "confidence": "high", "justification": "..."}
		}],
		"inventory": [], "ruled_out": [], "boundaries": []
	}`)
	rep, err := parseReport(raw)
	if err != nil {
		t.Fatalf("structured prose fields must not fail parse: %v", err)
	}
	f := rep.Findings[0]

	// Each non-string prose field should round-trip as a fenced JSON block.
	for name, got := range map[string]string{
		"validation": string(f.Validation),
		"prior_art":  string(f.PriorArt),
		"reach":      string(f.Reach),
		"rating":     string(f.Rating),
		"trace":      string(f.Trace),
	} {
		if !strings.Contains(got, "```json") {
			t.Errorf("%s: expected fenced JSON, got %q", name, got)
		}
	}

	// String form (boundary_analysis above) survives as-is and feeds
	// Boundary via the alias fallback.
	got := []db.Finding(nil)
	got = rep.toFindings(1, 1, "abc", "")
	if len(got) != 1 {
		t.Fatalf("toFindings returned %d", len(got))
	}
	if got[0].Boundary != "user → sanitiser → blade" {
		t.Errorf("boundary alias fallback failed: %q", got[0].Boundary)
	}

	// Severity normalised.
	if got[0].Severity != "Medium" {
		t.Errorf("severity not normalised: %q", got[0].Severity)
	}
}

// TestParseReport_sinksAsObjects covers scan #57 (php-src): findings
// arrived with `sinks` as an array of `{file, line, sink_class}` objects
// instead of an array of sink-id strings. flexSinks must collapse each
// object to "file:line (class)" and the empty top-level `location` must
// backfill from the first sink's path.
func TestParseReport_sinksAsObjects(t *testing.T) {
	raw := []byte(`{
		"spec_version": 10,
		"findings": [{
			"id": null,
			"title": "Phar circular symlink stack overflow",
			"severity": "medium",
			"location": null,
			"sinks": [
				{"file": "ext/phar/util.c", "line": 66, "sink_class": "resource_consumption"},
				{"file": "ext/phar/util.c", "line": 84, "sink_class": "resource_consumption"}
			]
		}, {
			"id": "F2",
			"title": "string-id sinks still work",
			"severity": "Low",
			"location": "x.c:1",
			"sinks": ["S1", "S2"]
		}]
	}`)
	rep, err := parseReport(raw)
	if err != nil {
		t.Fatalf("object-shaped sinks must not fail parse: %v", err)
	}
	got := rep.toFindings(1, 1, "abc", "")
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2", len(got))
	}
	wantSinks := "ext/phar/util.c:66 (resource_consumption), ext/phar/util.c:84 (resource_consumption)"
	if got[0].Sinks != wantSinks {
		t.Errorf("sinks[0] = %q, want %q", got[0].Sinks, wantSinks)
	}
	if got[0].Location != "ext/phar/util.c:66" {
		t.Errorf("location backfill: %q, want %q", got[0].Location, "ext/phar/util.c:66")
	}
	if got[1].Sinks != "S1, S2" {
		t.Errorf("string-id sinks lost shape: %q", got[1].Sinks)
	}
	if got[1].Location != "x.c:1" {
		t.Errorf("explicit location must not be overwritten: %q", got[1].Location)
	}
}

// TestFlexProse_acceptsAnyShape locks down the unmarshal contract: a
// string passes through, null/empty becomes "", anything else gets
// fenced. The point is no input shape can cause an error.
func TestFlexProse_acceptsAnyShape(t *testing.T) {
	cases := map[string]string{
		`"hello"`:           "hello",
		`null`:              "",
		`""`:                "",
		`{"a":1}`:            "```json\n{\n  \"a\": 1\n}\n```",
		`[1,2,3]`:            "```json\n[\n  1,\n  2,\n  3\n]\n```",
		`42`:                 "```json\n42\n```",
		`true`:               "```json\ntrue\n```",
	}
	for in, want := range cases {
		var f flexProse
		if err := f.UnmarshalJSON([]byte(in)); err != nil {
			t.Errorf("input %s: unmarshal err: %v", in, err)
			continue
		}
		if string(f) != want {
			t.Errorf("input %s: got %q, want %q", in, string(f), want)
		}
	}
}
