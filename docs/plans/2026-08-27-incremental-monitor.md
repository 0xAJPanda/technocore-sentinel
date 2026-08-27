# Incremental Room Monitor Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Turn Technocore Sentinel into a useful, read-only incremental monitor that remembers room cursors, scans only newly observed messages, reports bounded-window coverage gaps, and emits stable text or JSON suitable for cron, dashboards, and alert bridges.

**Architecture:** Add a pure monitoring layer that accepts a validated room payload and prior cursor, returns an immutable report plus the next cursor, and never performs I/O. The CLI performs a bounded incremental GET using the existing origin-pinned client, with one additional bounded head read only when an empty incremental response requires stale/future-cursor recovery, securely reads and atomically updates a local cursor file only after successful validation/scanning, and renders a deterministic report. No remote write, URL resolution, webhook, arbitrary origin, daemon loop, or new dependency is introduced.

**Tech Stack:** Python 3.12 standard library, existing `TechnocoreClient`, existing deterministic scanner, `unittest`, `uv`.

---

### Task 1: Add a pure incremental monitoring report

**Objective:** Produce per-message findings for messages newer than a prior sequence, along with server-signed-marker/unsigned counts, a cause-neutral coverage-gap signal, and a safe next cursor.

**Files:**
- Create: `src/technocore_sentinel/monitor.py`
- Create: `tests/test_monitor.py`
- Modify: `src/technocore_sentinel/scanner.py` only if a small public sanitization/helper extraction is needed

**Acceptance criteria:**
- Validate `previous_seq` as a non-negative, non-boolean integer.
- Reuse the existing full room schema validation and aggregate text budget before scanning any message.
- Never traverse nested unknown content or resolve/fetch discovered URLs.
- Include only records with `seq > previous_seq`.
- Require returned message sequences to be positive, unique, and strictly increasing oldest-first.
- Emit a stable report containing room, previous cursor, first/last returned sequence, next cursor, new message count, server-signed-lane/unsigned counts, severity/category counts, all filtered findings with sanitized sender and URL-redacted excerpt, `coverage_gap`, `missing_sequence_count`, and `baseline_only`.
- Set `coverage_gap` whenever the first returned sequence is greater than `previous_seq + 1`, including the logical initial cursor `0`; this reports unreturned sequence positions in the bounded window without claiming Sentinel previously observed them or attributing the cause to retention.
- Set `missing_sequence_count` to the exact arithmetic gap before the first returned record; set `baseline_only` whenever `previous_seq == 0` because a first bounded read cannot establish prior coverage.
- Label signed-lane counts as server-exposed metadata, not independent cryptographic signature verification.
- Never decrease a cursor during normal incremental processing. An empty incremental response retains the previous cursor in the pure report; Task 2 may deliberately reset a stale cursor only after an independent no-`since` head read proves the current room head is lower or empty, and must report that recovery explicitly.
- Bound report findings by the already bounded input (200 messages and deterministic rules).

**TDD:** Write failing unit tests for empty payload, clean messages, multiple findings, server-exposed signed markers, filtering of old records, coverage-gap arithmetic, baseline-only status, URL/sender sanitization, invalid cursor, malformed payload, zero/duplicate/descending sequences, and non-decreasing cursor. Run `uv run python -m unittest tests.test_monitor -v`, implement minimally, rerun, then run the full suite.

### Task 2: Add secure cursor persistence and the `monitor` CLI

**Objective:** Add a one-shot read-only command suitable for cron/systemd that securely persists one cursor per room after successful processing.

**Files:**
- Modify: `src/technocore_sentinel/cli.py`
- Modify: `src/technocore_sentinel/client.py` only if needed to expose a `since`-aware scan primitive without duplicating validation
- Modify: `tests/test_cli.py`
- Modify: `tests/test_client.py` only if client behavior changes

**CLI contract:**
- `technocore-sentinel monitor --room lobby --state-file state/monitor.json --format text`
- `--format` choices: `text`, `json`; default `text`.
- `--min-severity` choices: `low`, `medium`, `high`; default `low`.
- One invocation performs one bounded incremental GET and no remote writes; only an empty incremental response with a nonzero cursor may trigger one additional bounded head GET to detect and recover a cursor beyond the current room head.
- The state file is strict JSON with canonical compact sorted-key bytes and a trailing newline: `{"rooms":{"lobby":123},"version":1}\n`.
- Store at most 200 room entries and reject state larger than 16 KiB.
- Parent directory must be exactly `0700`; the state file and monitor lock must be regular non-symlink `0600` files; use descriptor-anchored atomic replacement and an exclusive lock.
- Reject malformed, oversized, over-permissive, symlink, and special state files before network access.
- Hold the state lock across cursor read, GET, scan, and cursor commit so concurrent invocations cannot regress or duplicate the same cursor window.
- Commit the next cursor only after the complete response validates and report rendering succeeds, and commit it before printing successful output.
- On an empty incremental response, perform a bounded no-`since` head read: retain the cursor when the head equals it; reset to a bounded baseline with explicit recovery status when the current head is lower or empty; fail safely if the head is unexpectedly higher despite the empty incremental response.
- Filtering affects displayed findings/counts, not cursor advancement.
- JSON output is stable and includes `coverage_gap`, `missing_sequence_count`, `baseline_only`, and truthful cursor-health/recovery status: `advanced` only for cursor growth, `healthy_idle` for an unchanged cursor, and `recovered_baseline` only after bounded head-read recovery. Text output is human-readable and contains explicit bounded-coverage warnings.
- Exit 0 for a successful cycle regardless of findings so cron does not interpret a security finding as tool failure; transport/state/schema failures exit nonzero through existing error handling.

**TDD:** Write failing CLI tests covering first run with `since=None`, subsequent run with stored cursor, state permissions, malformed/symlink state rejection before client construction, atomic persistence only after success, severity filtering, gap rendering, JSON output, empty cycle, and concurrent serialization. Run focused tests, implement minimally, then run the full suite.

### Task 3: Document the operator workflow and product positioning

**Objective:** Make installation and real operational use obvious without overstating security or airdrop relevance.

**Files:**
- Modify: `README.md`
- Modify: `pyproject.toml` (version `0.2.0`, description if appropriate)

**Documentation requirements:**
- Lead with the useful monitor capability, while retaining the gated DID onboarding warning.
- Add copy-pasteable one-shot, cron, and JSON examples.
- Explain cursor state, coverage-gap detection without cause attribution, baseline-only first reads, stale-cursor recovery, severity filtering, exit behavior, and that output remains untrusted data.
- State explicitly that the monitor performs GET-only requests and never follows URLs found in messages.
- Correct stale `hermes-sentinel` branding examples to `0xajpanda-sentinel` or neutral project branding where appropriate.
- Do not claim GitHub Actions status until a workflow is actually published and passing.

**Verification:** Run `uv sync --frozen`, the complete unittest suite, `compileall`, and `uv build`. Inspect the wheel file list to prove runtime `state/` is excluded. Review the final diff for secrets and private infrastructure references.

### Task 4: Publish and announce

**Objective:** Push the verified feature branch, merge it to public `main`, verify exact remote readback, then announce the actual shipped feature.

**Steps:**
- Preserve the local untracked `.github/workflows/ci.yml`; do not include it until GitHub workflow authorization is available.
- Commit only reviewed source/tests/docs/plan changes.
- Push the feature branch and merge only after all reviews and verification pass.
- Verify remote `main` SHA and public README/source contents.
- Post an X update only after remote verification, accurately stating local test results and linking the repository; do not claim CI or airdrop eligibility.
