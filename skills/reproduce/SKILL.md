---
name: reproduce
description: Take an existing finding and turn it into a clean, self-contained, runnable proof-of-concept. Runs the PoC, captures the dangerous behaviour, and writes both the script and a transcript back so an analyst (or downstream `disclose`/`patch`) inherits a known-good reproduction instead of prose. Marks findings that genuinely cannot be reproduced so they stop blocking triage.
license: MIT
compatibility: Needs network access to the scrutineer API. Finding-scoped. The runner image ships Python 3, Node 22, Go, Bash, and PHP 8.3 with composer plus most bundled extensions; rely on those rather than installing tooling.
metadata:
  scrutineer.output_file: report.json
  scrutineer.output_kind: freeform
---

# reproduce

Sister skill to `verify`. `verify` answers "does the original reproduction still trigger?". `reproduce` answers "what is the smallest script that triggers this, and does it actually work?". Run it on a finding whose Validation field is prose, ambiguous, or a sketch; the output is a PoC the analyst can hand to a maintainer or a CVE form without rewriting.

## Workspace

- `./src` — the repository at HEAD
- `./context.json` — has `scrutineer.api_base`, `scrutineer.token`, `scrutineer.repository_id`, and `scrutineer.finding_id` (required; this skill only makes sense finding-scoped)
- `./report.json` — write the PoC + transcript here
- `./schema.json` — output shape

## Available languages and tools in the runner

The runner image is intentionally polyglot. Pick the smallest one that triggers the bug:

- **Python 3.13** — for findings in Python code, or for fetch/eval driver scripts.
- **Node 22** — for JS/TS findings; can `npm install --offline` if `node_modules/` exists.
- **Go** — for Go findings; `go run ./...` works against `./src`.
- **PHP 8.3** (`php` and `php83`) — bundled extensions: bcmath, bz2, ctype, curl, dom, exif, fileinfo, gd, gettext, gmp, iconv, imap, intl, ldap, mbstring, mysqli, opcache, openssl, pcntl, pdo + pdo_mysql/pgsql/sqlite, pgsql, phar, posix, session, simplexml, snmp, soap, sockets, sodium, sqlite3, tidy, tokenizer, xml/xmlreader/xmlwriter, xsl, zip, plus pecl apcu, imagick, redis. `composer` is on PATH. `phpize` and `php-config` are linked from `php83-dev` so PHP C extensions can be built in place. For PHP findings: `php -r '...'`, a `/tmp/poc.php` script, or `cd src && composer install --no-interaction` if a `composer.lock` is committed.
- **C / C++** — `gcc 15` and `clang 21` are both on PATH, plus `lld`, `llvm`, `gdb`, `strace`, `ltrace`, `cmake`, `meson`, `ninja`, autotools, `bison`/`flex`/`re2c`, `linux-headers`, `musl-dev`. AddressSanitizer and UndefinedBehaviorSanitizer runtimes ship via `compiler-rt` and only work with **clang** — Alpine's gcc has no `libasan`/`libubsan` (musl gap). Curl (`/usr/bin/curl`) is on PATH for fetching upstream tarballs.
- **Bash + coreutils + git** — for shell-injection findings, archive extraction, race conditions.

If the bug needs something not in the image (a database server, a package registry, an interactive debugger, an alternative libc such as glibc), say so in the report — that is a reason for `inconclusive`, not for inventing a fake reproduction.

### C / C++ PoC template

```bash
# Build the target with sanitizers; clang is required (gcc on Alpine
# cannot link asan/ubsan). lld is the supported linker for sanitizer
# builds.
export CC=clang CXX=clang++
export CFLAGS="-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined"
export CXXFLAGS="$CFLAGS"
export LDFLAGS="-fsanitize=address,undefined -fuse-ld=lld"
export ASAN_OPTIONS="abort_on_error=1:detect_leaks=1:symbolize=1"
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"

# autotools:
./configure && make -j
# OR cmake:
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DCMAKE_C_COMPILER=clang -DCMAKE_C_FLAGS="$CFLAGS" \
      -DCMAKE_EXE_LINKER_FLAGS="$LDFLAGS"
cmake --build build -j

# Drive the sink with the input you traced. Asan abort + stack frame is
# the proof. PoC succeeds if the asan/ubsan diagnostic fires; PoC OK gets
# echoed once you have grepped for the expected message.
./target < poc-input 2>&1 | tee /tmp/poc.log
grep -q 'AddressSanitizer:' /tmp/poc.log && echo 'PoC OK: asan caught it' && exit 0
echo 'PoC FAIL: no sanitizer diagnostic' && exit 1
```

### PHP C extension PoC template

```bash
# Audit a PHP extension (config.m4 + PHP_FUNCTION macros) against the
# runner's PHP. For sanitizer use, build PHP from source first — see the
# security-deep-dive language hints for the full recipe; the short
# version is below for the common "load and call" PoC.
cd src/ext/myext
phpize
./configure --enable-myext
make -j
php -d extension="$(pwd)/modules/myext.so" \
    -d display_errors=1 -d error_reporting=E_ALL \
    /tmp/poc.php
```

`USE_ZEND_ALLOC=0` plus a sanitizer-built PHP is required when the bug lives in the `zval` boundary; without it, asan sees Zend's pool as one giant arena and reports nothing.

## What to do

1. Read `./context.json`. If `scrutineer.finding_id` is missing, write `{"error": "no finding_id in context.json; reproduce is finding-scoped"}` to `report.json` and exit 0.

2. Fetch the finding: `GET {api_base}/findings/{finding_id}` with `Authorization: Bearer {token}`. You get `title`, `severity`, `cwe`, `location`, `affected`, plus the six-step prose (`trace`, `boundary`, `validation`, `prior_art`, `reach`, `rating`). The `trace` and `validation` fields are your starting points; everything else is context.

3. Read the code at `location` in `./src`. Confirm the sink the trace describes still exists at that file:line (or follow renames if it moved). If the sink is gone, write a `not_reproducible` report citing the commit that removed it and exit 0 — there is nothing to reproduce.

4. Build a self-contained PoC. Constraints:

   - **Single file when possible.** A single `poc.py`, `poc.php`, `poc.sh`, `poc.js`, or `poc.go`. Multi-file is allowed when the bug genuinely needs a fixture (a malformed archive, a crafted YAML, a phar payload); ship the fixture content as part of the PoC, generated on the fly when feasible (`echo "..." | base64 -d > evil.zip`).
   - **No external network at runtime.** The PoC must run with the runner's offline workspace. If the bug needs a remote service, mock it with a localhost listener or skip the PoC and mark `inconclusive`.
   - **Deterministic.** No timing-dependent races without a loop bound. No "run this 1000 times and one will leak". Findings about races are still in scope; structure the loop so the PoC asserts the leak after a bounded number of iterations and exits non-zero if it never happens.
   - **Self-checking.** End the PoC with a clear assertion of the dangerous outcome. Print `PoC OK: <what was achieved>` on success or exit non-zero. The point is the analyst can re-run the PoC and see immediately whether it still works.
   - **Minimal.** No retry logic, no progress bars, no colour codes, no pip/npm/composer installs unless the manifest in `./src` already pins them. The PoC reads top-to-bottom.
   - **Targets the published artefact when the finding does.** If the validation cited a release tarball, fetch the same release into a tmpdir; do not silently switch to git HEAD.

5. Run the PoC inside the runner. Capture stdout, stderr, and exit code. Paste the full transcript (truncated to 4000 chars per stream) into `transcript`.

6. Decide the outcome:

   - **reproduced** — the PoC ran end-to-end and the dangerous behaviour fired (file written, command executed, secret leaked, parser crashed, …). The transcript shows it.
   - **not_reproducible** — the sink is gone, the input cannot reach it on this code, or the precondition the trace assumed is not present. Cite the commit, the guard, or the missing surface in `notes`. Distinct from `inconclusive`: this means you understood the code and the bug is no longer there.
   - **inconclusive** — you could not run the PoC for an environmental reason (missing service, missing extension, the bug needs an interactive UI, the trace is too vague to make runnable). Explain in `notes` what you would need.

7. Write the PoC and transcript back to the finding so downstream skills inherit them:

   **POST a finding note** — `POST {api_base}/findings/{finding_id}/notes` with:

   ```json
   {
     "body": "Reproduction in scan #{scan_id} (`reproduce` skill).\n\nOutcome: reproduced | not_reproducible | inconclusive.\n\nPoC and transcript live on the scan report.",
     "by": "reproduce"
   }
   ```

   **PATCH the finding's `validation` field** — only if `outcome == "reproduced"` and the existing validation prose is thin (less than 200 chars, or missing a runnable script). Replace it with a markdown block containing the PoC fenced and the transcript excerpt:

   ```json
   {
     "fields": {
       "validation": "PoC (rebuilt by `reproduce` skill, scan #{scan_id}):\n\n```{lang}\n<poc body>\n```\n\nTranscript:\n\n```\n<truncated transcript>\n```"
     },
     "by": "reproduce"
   }
   ```

   Do not overwrite a non-thin validation field. Do not touch any other field — `severity`, `cwe`, `location`, `cvss_vector`, `affected`, `fix_*`, `status` belong to the analyst.

   If `outcome` is `not_reproducible`, also POST a note recommending the analyst flip the lifecycle to `wontfix` or `fixed` (whichever applies); do not flip it yourself.

8. Write `./report.json` (see schema). Required fields: `outcome`, `language`, `poc`, `transcript`, `command`, `notes`. Optional: `fixtures` (an array of extra files the PoC needed, base64-encoded), `assumptions` (preconditions the PoC requires), `cleanup` (commands to undo side effects).

## Output shape

```json
{
  "outcome": "reproduced",
  "language": "php",
  "command": "php /tmp/poc.php",
  "poc": "<?php\n// triggers CVE-... in vendor/foo/bar.\n...\nif (file_exists('/tmp/pwned')) { echo \"PoC OK\\n\"; exit(0); }\nexit(1);\n",
  "fixtures": [
    { "path": "evil.tar", "encoding": "base64", "content": "..." }
  ],
  "transcript": "$ php /tmp/poc.php\nPoC OK: wrote /tmp/pwned via tar slip\n",
  "exit_code": 0,
  "assumptions": "PHP 8.3 with phar enabled (image default).",
  "cleanup": "rm -f /tmp/pwned",
  "notes": "Validation field on the finding was prose-only; replaced with this PoC."
}
```

## Constraints

- **Don't weaponise.** A PoC demonstrates the unsafe behaviour with the smallest possible payload — write a marker file, print a string, return a known cookie. Do not reverse-shell, do not exfiltrate, do not chain to a real exploit. The audience is a maintainer reading a security advisory.
- **Don't lifecycle.** No `status` PATCH, no `cve_id` invention, no `fix_commit` setting. Reproducing the bug is upstream of all of those.
- **Don't pollute the workspace.** Build the PoC under `/tmp` or a scratch dir, not inside `./src`. If you must edit `./src` to make the PoC run (e.g. add a regression test), revert before exit; `git -C src diff` should be empty when this skill finishes.
- **Don't run the PoC with elevated capabilities the bug doesn't already need.** No `sudo`, no `--privileged` tricks. The runner is non-root (`runner` user) by design — if the bug only fires as root, that is information for the rating, not a workaround.
- **Don't fabricate.** A PoC that "would work if X" is not a reproduction. `outcome: inconclusive` is always honest. A fabricated reproduced outcome is the worst possible failure mode of this skill.
