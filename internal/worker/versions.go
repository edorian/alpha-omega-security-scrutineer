package worker

import (
	"context"
	"os/exec"
	"regexp"
	"strings"
)

// RunnerImageName returns the docker image the given runner uses for scans,
// or "" when the runner is not the docker runner (e.g. LocalClaude under
// --no-docker), where there is no fixed image to interrogate.
func RunnerImageName(r SkillRunner) string {
	if d, ok := r.(DockerRunner); ok {
		return d.image()
	}
	return ""
}

// DockerServerVersion returns the docker daemon's server version, or "" if
// docker is unavailable or the command fails. Mirrors DockerAvailable's
// shell-out style; the caller supplies a context so the settings page can
// bound how long it waits.
func DockerServerVersion(ctx context.Context) string {
	out, err := exec.CommandContext(ctx, "docker", "version", "--format", "{{.Server.Version}}").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// RunnerToolVersions holds the versions of the analysis tools baked into the
// runner image. Any field is "" when its tool could not be queried.
type RunnerToolVersions struct {
	Zizmor  string
	Semgrep string
	Claude  string
}

// queryToolsScript prints each tool's version as a key=value line so the
// output parses unambiguously regardless of each tool's own format. stderr
// is dropped so update notices and warnings don't pollute the value.
const queryToolsScript = `echo "zizmor=$(zizmor --version 2>/dev/null)"; ` +
	`echo "semgrep=$(semgrep --version 2>/dev/null)"; ` +
	`echo "claude=$(claude --version 2>/dev/null)"`

// QueryRunnerToolVersions starts one short-lived container off the runner
// image and reads back the versions of the scanner tools it ships. The
// deployed image is the source of truth (it can drift from the Dockerfile's
// pinned ARGs), so we interrogate the image rather than parse the Dockerfile.
//
// --pull never means a missing image fails fast instead of triggering a slow
// registry pull, so the settings page never blocks on a download. The caller
// must pass a context with a timeout to bound a hung daemon. Returns a zero
// value (all fields "") for an empty image name or any failure.
func QueryRunnerToolVersions(ctx context.Context, image string) RunnerToolVersions {
	if image == "" {
		return RunnerToolVersions{}
	}
	out, err := exec.CommandContext(ctx, "docker", "run", "--rm",
		"--pull", "never", "--entrypoint", "sh", "--", image, "-c", queryToolsScript).Output()
	if err != nil {
		return RunnerToolVersions{}
	}
	return parseToolVersions(string(out))
}

// versionRe matches the first dotted-numeric version token in a string, so
// "zizmor 1.26.1" and "2.1.123 (Claude Code)" both reduce to the bare number.
var versionRe = regexp.MustCompile(`\d+\.\d+[\w.\-+]*`)

func parseToolVersions(out string) RunnerToolVersions {
	var v RunnerToolVersions
	for line := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		val = versionRe.FindString(val)
		switch key {
		case "zizmor":
			v.Zizmor = val
		case "semgrep":
			v.Semgrep = val
		case "claude":
			v.Claude = val
		}
	}
	return v
}
