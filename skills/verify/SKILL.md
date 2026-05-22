---
name: verify
description: Independently verify a specific finding by re-running its reproduction against the current repository state. Records whether the finding still reproduces, was fixed upstream, or could not be reproduced. Use on a finding before investing analyst time in disclosure.
license: MIT
compatibility: Needs network access to the scrutineer API (http://host:port/api). Expects the finding's reproduction instructions to be runnable against ./src with commonly available tooling.
metadata:
  scrutineer.output_file: report.json
  scrutineer.output_kind: verify
---

# verify

Take an existing finding produced by a prior audit skill and check whether it still holds against the current code. A verify run answers one question: does the reproduction in the finding's validation step still trigger the dangerous behaviour?

If the finding's existing validation field is prose-only or too vague to execute, prefer the `reproduce` skill instead — it builds a clean PoC from scratch. `verify` is for re-running an already-runnable reproduction; `reproduce` is for authoring one.

## Workspace

- `./src` — the repository at its current HEAD
- `./context.json` — has `scrutineer.api_base`, `scrutineer.token`, `scrutineer.repository_id`, and `scrutineer.finding_id` (required; this skill only makes sense finding-scoped)
- `./report.json` — write the verify report here
- `./schema.json` — output shape

## What to do

1. Read `./context.json`. If `scrutineer.finding_id` is missing, write `{"status": "inconclusive", "notes": "no finding_id in context.json; verify is finding-scoped"}` and exit.

2. Fetch the finding: `GET {api_base}/findings/{finding_id}` with `Authorization: Bearer {token}`. You get back title, severity, location, cwe, affected, and the six-step prose (trace, boundary, validation, prior_art, reach, rating).

3. Read the `validation` field. This is the original reproduction instructions: how to run it, what it looked like when it worked, what dangerous behaviour was observed.

4. Re-run the reproduction against `./src`. Be conservative:
   - Only run what the validation field describes. Do not improvise a new attack vector.
   - If the validation is prose-only (no concrete script), try to execute what it describes literally. If you cannot turn the prose into a runnable check, that is `inconclusive` — say why.
   - Prefer running the reproduction against the published artefact (as the original did) over git HEAD, if the validation mentions one.
   - Capture stdout, stderr, exit code. Paste relevant excerpts into `evidence`.
   - The runner has Python 3, Node 22, Go, Bash, PHP 8.3 (`php`, plus `composer` and the bundled extensions: curl, dom, mbstring, intl, pdo_*, gd, sodium, zip, phar, opcache, apcu, redis, imagick, …), and a full C/C++ toolchain (`gcc`, `clang`, `compiler-rt`, `lld`, `gdb`, `cmake`, `meson`, `ninja`, autotools, `bison`, `flex`, `re2c`). For PHP findings, run the validation as `php -r '...'`, a one-off `.php` script under `/tmp`, or a vendored test (`composer install --no-interaction --no-progress` works offline if `vendor/` exists; if not, the runner has no registry network — treat as `inconclusive` and explain). Prefer running against `./src` directly with `php -d open_basedir=...` only if the original validation specified flags; otherwise plain `php`. For C/C++ findings, build with `clang -fsanitize=address,undefined -g -O1 -fno-omit-frame-pointer -fuse-ld=lld` and reproduce — gcc on Alpine has no `libasan`/`libubsan`, so reach for clang when the validation needs sanitizer evidence. For PHP C extensions, `phpize && ./configure && make` and load the resulting `.so` with `php -d extension=...`; see security-deep-dive for the sanitizer-aware variant.
   - When the original validation produced an artefact (extracted file, written marker, exfiltrated value), re-run it cleanly: cd to a fresh tmpdir, run, check for the artefact. Quote the path you checked.

5. Decide the status:
   - **confirmed** — the reproduction produces the same dangerous behaviour as the original. The finding is still live.
   - **fixed** — the reproduction does not reproduce, AND you can identify what stopped it (a guard, a sanitiser, a refactor that removed the sink). Cite the commit or file:line that fixed it in `notes`.
   - **inconclusive** — one of:
     - the reproduction couldn't run (missing tool, platform mismatch, network dependency)
     - the code has drifted enough that the original trace no longer maps cleanly onto the current tree
     - the reproduction ran but produced a different outcome you cannot classify

   Do not mark `fixed` just because the reproduction failed; "I ran it and nothing happened" is `inconclusive` unless you can point at why.

## Output

Write `./report.json`:

```json
{
  "status": "confirmed" | "fixed" | "inconclusive",
  "evidence": "...",
  "notes": "..."
}
```

Scrutineer updates the finding's lifecycle status based on your answer:
- `confirmed` moves a `new` finding to `enriched`
- `fixed` moves any finding to `fixed`
- `inconclusive` leaves the status alone

Evidence and notes are appended to the finding's Notes field with a timestamp header so the analyst can read your trail later.
