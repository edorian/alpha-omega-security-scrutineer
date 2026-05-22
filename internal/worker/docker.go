// Package worker provides a DockerRunner that executes claude in an ephemeral
// container. Used when docker is available on the host; falls back to
// LocalClaude otherwise. The scrutineer process runs on the host (not
// containerised) and calls docker directly -- no socket mounting needed (T12).
package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// LocalRunnerImage is the docker tag scrutineer uses for the runner
// image it builds from the local Dockerfile.runner. The tag does NOT
// exist on any public registry; scrutineer refuses to pull runner
// images over the network — every container is built from the source
// tree the binary ships with so the analyst can audit what's running.
const LocalRunnerImage = "scrutineer-runner:local"

// DefaultRunnerDockerfile is the path scrutineer looks for when it
// needs to build the runner image. Resolved relative to the working
// directory (typically the scrutineer source tree).
const DefaultRunnerDockerfile = "Dockerfile.runner"

// DockerRunner launches claude inside an ephemeral container with the scan
// workspace (clone + staged skill + output file) mounted at /work. It
// implements SkillRunner.
type DockerRunner struct {
	Image     string
	Effort    string
	ProxyURL  string // http://user:token@host.docker.internal:port; "" disables egress
	FullClone bool
	MaxTurns  int
}

func (d DockerRunner) image() string {
	if d.Image != "" {
		return d.Image
	}
	return LocalRunnerImage
}

// EnsureLocalRunnerImage builds the runner image from dockerfile when
// the local tag is missing or out of date relative to the Dockerfile's
// content. Returns the tag actually present on the host. The tag is
// suffixed with the Dockerfile's sha256[:12] so a Dockerfile change
// rolls forward to a new image without the operator remembering to
// rebuild — `docker build` is a no-op when the layers are cached.
//
// Never reaches the network for runner content: the build context is
// the scrutineer source tree and the FROM lines pin every base image
// by digest (see Dockerfile.runner). Operators who want a different
// runner pass --runner-image and bypass this entirely.
func EnsureLocalRunnerImage(ctx context.Context, dockerfile string, log *slog.Logger) (string, error) {
	if _, err := os.Stat(dockerfile); err != nil {
		return "", fmt.Errorf("runner dockerfile %q: %w (cd to the scrutineer source tree, "+
			"or pass --runner-image <pre-built-tag> to skip the local build)", dockerfile, err)
	}
	body, err := os.ReadFile(dockerfile)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", dockerfile, err)
	}
	sum := sha256.Sum256(body)
	tag := "scrutineer-runner:local-" + hex.EncodeToString(sum[:])[:12]

	// Already built? `docker images -q <tag>` prints the image id; empty
	// output means missing.
	if out, err := exec.CommandContext(ctx, "docker", "images", "-q", tag).Output(); err == nil &&
		strings.TrimSpace(string(out)) != "" {
		log.Info("runner image up to date", "tag", tag)
		return tag, nil
	}

	contextDir := filepath.Dir(dockerfile)
	log.Info("building runner image (this can take ~10 min on first run)",
		"tag", tag, "dockerfile", dockerfile, "context", contextDir)
	cmd := exec.CommandContext(ctx, "docker", "build",
		"--tag", tag,
		"--tag", LocalRunnerImage,
		"--file", dockerfile,
		contextDir,
	)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("docker build %s: %w", dockerfile, err)
	}
	log.Info("runner image built", "tag", tag)
	return tag, nil
}

// RunSkill runs a skill inside an ephemeral container. The whole workspace
// (clone + staged .claude/skills + context.json + output) is mounted at
// /work read-write so claude can read the skill files and write its output.
// Egress is routed through scrutineer's allowlisting proxy on the host;
// see EgressProxy. tmpfs/cap-drop rules mirror the local runner's intent.
func (d DockerRunner) RunSkill(ctx context.Context, sj SkillJob, emit func(Event)) (SkillResult, error) {
	src, err := ensureClone(ctx, sj.Repo, sj.WorkRoot, d.FullClone, emit)
	if err != nil {
		return SkillResult{}, err
	}
	commit := gitHead(src)
	work := sj.WorkRoot
	absWork, _ := filepath.Abs(work)

	var outPath string
	if sj.OutputFile != "" {
		outPath = filepath.Join(work, sj.OutputFile)
		_ = os.Remove(outPath)
	}

	claudeArgs := []string{
		"claude", "-p",
		"--output-format", "stream-json",
		"--verbose",
		"--permission-mode", "bypassPermissions",
		"--model", sj.Model,
	}
	if d.Effort != "" {
		claudeArgs = append(claudeArgs, "--effort", d.Effort)
	}
	if d.MaxTurns > 0 {
		claudeArgs = append(claudeArgs, "--max-turns", strconv.Itoa(d.MaxTurns))
	}
	claudeArgs = append(claudeArgs, buildSkillPrompt(sj.Name, sj.OutputFile))

	dockerArgs := []string{
		"run", "--rm",
		"--cap-drop", "ALL",
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=256m",
		"-v", absWork + ":/work",
		"-w", "/work",
		"--add-host", HostGatewayAlias + ":host-gateway",
	}
	if d.ProxyURL != "" {
		dockerArgs = append(dockerArgs,
			"-e", "HTTPS_PROXY="+d.ProxyURL,
			"-e", "HTTP_PROXY="+d.ProxyURL,
			"-e", "ALL_PROXY="+d.ProxyURL,
			"-e", "NO_PROXY=",
		)
	} else {
		dockerArgs = append(dockerArgs, "--network", "none")
	}
	// Silence Claude Code's outbound telemetry/metrics/error reporting.
	// Without these the CLI tries to ship logs to
	// http-intake.logs.us5.datadoghq.com (OTel-via-Datadog), Statsig,
	// and Sentry on every scan — all denied by the egress proxy and
	// noisy in the scrutineer log. Disabling at the source removes the
	// connect attempts entirely.
	dockerArgs = append(dockerArgs,
		"-e", "OTEL_SDK_DISABLED=true",
		"-e", "DISABLE_TELEMETRY=1",
		"-e", "DISABLE_ERROR_REPORTING=1",
		"-e", "DISABLE_BUG_COMMAND=1",
		"-e", "DISABLE_AUTOUPDATER=1",
		"-e", "DISABLE_NON_ESSENTIAL_MODEL_CALLS=1",
	)
	if os.Getenv("ANTHROPIC_API_KEY") != "" {
		dockerArgs = append(dockerArgs, "-e", "ANTHROPIC_API_KEY")
	}
	if os.Getenv("CLAUDE_CODE_OAUTH_TOKEN") != "" {
		dockerArgs = append(dockerArgs, "-e", "CLAUDE_CODE_OAUTH_TOKEN")
	}
	dockerArgs = append(dockerArgs, d.image())
	dockerArgs = append(dockerArgs, claudeArgs...)

	cmd := exec.CommandContext(ctx, "docker", dockerArgs...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Env = os.Environ()

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return SkillResult{}, err
	}
	cmd.Stderr = cmd.Stdout

	emit(Event{Kind: KindText, Text: "$ docker run --rm " + d.image() + " <skill:" + sj.Name + ">"})
	if err := cmd.Start(); err != nil {
		return SkillResult{}, fmt.Errorf("start docker: %w", err)
	}

	ParseStream(stdout, emit)
	waitErr := cmd.Wait()
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}

	res := SkillResult{Commit: commit}
	if outPath != "" {
		res.Report = readCappedReport(outPath, emit)
	}
	if waitErr != nil {
		return res, fmt.Errorf("docker exited: %w", waitErr)
	}
	return res, nil
}

// DockerAvailable checks if docker is in PATH and the daemon is reachable.
func DockerAvailable() bool {
	out, err := exec.Command("docker", "info", "--format", "{{.ServerVersion}}").Output()
	return err == nil && len(out) > 0
}
