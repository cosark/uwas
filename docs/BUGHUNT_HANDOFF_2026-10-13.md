# Maintainer Handoff — Standing Leads from the 25-Round Bug Hunt (2026-10-13)

Nine defects were found, proven, fixed, and committed during the 2026-10-13
proof-driven bug-hunt series (25 rounds; commits `b27dd07f`, `50063363`,
`752043c6`, `8a000d7f`, `2908742a`, `9cc5a582` on `main`). This document
records what that series deliberately did **not** fix: leads that are real but
require a product or design decision, and one unreproduced test transient.
Everything below was verified against the tree as of `9cc5a582`.

---

## 1. cPanel `import_db` is accepted but never acted on (design gap)

**Status**: standing — needs a product decision before code.

The admin API accepts an operator's intent to import databases from a cPanel
backup, threads it through the whole call chain, and then nothing reads it.

- `internal/migrate/cpanel.go:46` — `ImportCPanelBackup(backupPath, targetDir
  string, importDB bool)`: the parameter is never referenced in the function
  body. Its own doc comment (immediately above line 46) still promises
  "optionally imports databases".
- Phase 5 of the import (inside `ImportCPanelBackup`) only **discovers**
  databases; `CPanelDatabase.Imported` (`internal/migrate/cpanel.go:41`) is
  never set to `true` anywhere in the tree.
- The intent enters here: `internal/admin/handlers_migrate.go:334`
  (`importDB := r.FormValue("import_db") == "true"`) and is passed through at
  `:337` (`migrate.ImportCPanelBackup(tmpPath, webRoot, importDB)`).
- The API response (`internal/admin/handlers_migrate.go:354`) lists the
  discovered databases with `Imported: false`, so the response is honest — but
  an operator who checks the box gets files and domains with no databases, and
  the panel gives no hint why.

**Why it was not fixed in the series**: unlike a regression, "fixing" this
means building the import pipeline (creating the database and user, sourcing
credentials — the cPanel dump carries no password, so a decision is needed:
reuse the site's wp-config credentials, generate new ones, or refuse without
explicit credentials — plus conflict policy for existing schemas). That is
feature work with design decisions, out of scope for a bug round.

**Options for a maintainer**: (a) implement the import using the detected
site's wp-config credentials with generated-password fallback; (b) remove the
`import_db` form field, the parameter, and the doc-comment promise (small API
change); or (c) document the current behavior on the panel. Any of the three
closes the gap; (b) is the smallest.

---

## 2. htaccess `Options ±Indexes` has no effect on directory listing (low impact)

**Status**: standing — low impact, requires an Apache-compat decision.

The htaccess layer has no handling for the `Options` directive's `Indexes`
form: a repo-wide search for `Indexes` across `internal/htaccess/*.go` and
`internal/server/server_htaccess.go` returns no non-test matches, and the
directory-listing decision is taken solely from UWAS configuration:

- Decision point: `internal/server/server_dispatch.go:1001`
  (`func dirListingAllowed(root, rawPath, urlPath string) bool`), reached from
  the dispatch path; the config-driven guard it consults is documented at
  `:657` (`directory_listing: false`, F3601).

Consequence: a tenant `.htaccess` containing `Options +Indexes` never enables
listing, and `Options -Indexes` never disables it. Migrated sites that relied
on either see no error — listing availability simply does not change.

**Adjacent note (verified resolved — no action needed)**: an earlier audit
round recorded `DirectoryIndex` as a parsed-but-unconsumed htaccess setting.
That is no longer true: `internal/server/server_htaccess.go:226-227` feeds
`ctx.IndexFiles = eff.DirectoryIndex`, declared at
`internal/router/context.go:46` and consumed by the static handler's index
precedence (`internal/handler/static/handler.go:441-445`). Only the
`±Indexes` half of the `Options` directive remains unimplemented.

**Why it was not fixed in the series**: implementing `Options` handling means
choosing semantics — does a tenant's `-Indexes` override the operator's
`directory_listing: true`, and does `+Indexes` override `false`? That is a
security-relevant precedence decision (a tenant re-enabling listing the
operator disabled), which belongs to the maintainers.

---

## 3. Unreproduced `internal/server` test transient (1 red / 5 green)

**Status**: standing — unreproduced; treat any recurrence as a real flake to
chase with full logs (never with retry-tolerance).

During round 20's verification (after the ESI `FetchFragment` fix, commit
`9cc5a582`), one `go test -race -count=1 ./internal/admin/
./internal/server/` run (disk-backed `TMPDIR=/home/ersinkoc/uwas-tmp`)
reported `FAIL github.com/uwaserver/uwas/internal/server 158.407s`. The
failing test's name was lost — that run's output was piped through `tail`,
and the shell status later reported (`RETRY_EXIT=0`) was the pipe's exit
code, not `go test`'s. Five subsequent full `-race` runs of the same suites
passed with zero failures, including one under the exact original condition
(two-package invocation, same TMPDIR):

| Sample | Command shape | Result |
|---|---|---|
| 1 | `./internal/server/` alone, default TMPDIR | ok 151.874s |
| 2 | `./internal/admin/ ./internal/server/`, disk TMPDIR | **FAIL 158.407s** (name lost) |
| 3 | `./internal/server/` alone, disk TMPDIR | ok (exit 0) |
| 4 | `./internal/server/` alone, disk TMPDIR | ok (exit 0, 0 FAIL lines) |
| 5 (round 21) | `./internal/server/` alone, disk TMPDIR | ok (exit 0) |
| 6 (round 21) | `./internal/admin/ ./internal/server/`, disk TMPDIR | ok (exit 0) |

Surviving (all-passing) logs: `/tmp/srv_retry_r20.log`,
`/tmp/srv_retry3_r20.log`, `/tmp/r21_try1.log`, `/tmp/r21_try2.log` — the
failing run's log was not captured. `/tmp` is ephemeral; these paths may not
survive a reboot.

**Assessment**: the only in-flight code change was the `FetchFragment` error
path (`internal/server/server.go:1612-1619`, commit `9cc5a582`) — an error
return on a previously panicking path, with no new goroutines or shared
state, making it an unlikely cause. The failure is equally consistent with a
pre-existing flaky test in the 200+-test server suite surfacing under
two-package parallel race load. The cause was not found; per the testing
discipline it was not papered over with retries.

**If it recurs**: capture full output to a file (never pipe through
`tail`), note the exact `--- FAIL` test name, and run that test alone and
shuffled (`-count=5`) before touching code.

---

## Environment note (affects full-suite verification)

The full `go test -race` gate over all 75 packages exhausts the /tmp tmpfs
per-user quota partway through the sequential run, producing link-phase
failures ("disk quota exceeded") and /tmp-writing test failures unrelated to
code. Standalone reruns with `TMPDIR` pointed at disk (e.g.
`/home/ersinkoc/uwas-tmp`) classify them cleanly. Any CI or local full-gate
run should set a disk-backed `TMPDIR` first.
