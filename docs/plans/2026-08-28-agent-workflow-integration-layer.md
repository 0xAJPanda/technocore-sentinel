<!-- markdownlint-disable MD013 MD032 -->

# Technocore Agent Workflow Integration Layer Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Make Technocore Room Safety Monitor a practical CLI/JSON integration layer that any command-capable agent can call with one command to receive a bounded, content-free room-risk and coverage decision.

**Architecture:** Preserve the existing fixed-origin, GET-only monitor as the sole network path. Move report validation and safe summarization from the example script into a pure production module, then add an `agent-check` CLI command that renders the safe summary inside the locked monitor cycle before cursor persistence. Add a network-free `summarize-report` subcommand for same-environment pinned-wheel pipelines, keep the example consumer as a thin source-tree adapter, and document several concrete agent-workflow use cases without adding MCP, a daemon, autonomous writes, or raw room-content handoff.

**Tech Stack:** Python 3.12 standard library, existing `unittest`, Hatchling, `uv`/`uvx`, Markdown.

---

## Product boundary

The project display name is **Technocore Room Safety Monitor**. The existing package, repository, and executable identifiers remain `technocore-sentinel` for compatibility.

Simple use case:

> An agent runs one command before or during a Technocore-related workflow. It receives compact JSON stating whether new room activity contains recognized safety findings or incomplete coverage that requires human review—without receiving excerpts, URLs, sender names, or commands.

This is a useful Technocore workflow integration and a safety gate. It is not a general chat client, archive, firewall, claim of safe content, or autonomous posting agent.

## Non-negotiable invariants

- Origin remains exactly `https://technocore.chat`.
- Monitoring remains GET-only: one bounded read normally and at most two during stale-cursor recovery.
- Maximum 200 records per response, 20-second timeout, 1 MiB cap, redirects refused, environment proxies ignored.
- Existing secure cursor locking, mode, size, schema, render-before-persist, and commit-before-output behavior remains unchanged.
- `agent-check` constructs no identity, reads no key/nonce/receipt, exposes no write authorization, and performs no POST.
- Findings and coverage conditions remain exit `0`; operational failures remain nonzero and emit no successful summary.
- Agent output contains no finding excerpts, sender values, rules, URLs, message text, commands, or unknown fields.
- `review_required` is true for any finding visible at the operator-selected `minimum_severity`, any coverage gap, a baseline-only read, or cursor recovery. The summary includes `minimum_severity` so filtered results are never presented without their policy context.
- Unknown schema versions, malformed fields, duplicate keys, trailing JSON, NaN, inconsistent finding aggregates, and oversized stdin fail closed in the standalone consumer.
- No MCP dependency/server, listener, daemon, arbitrary origin, wallet, webhook sender, dashboard service, database, or autonomous action.
- Host configuration, room, state path, and report destination are operator-selected and never derived from room/report/model content.

### Task 1: Promote the safe summary to production code

**Objective:** Establish one pure source of truth for validating v1 reports and producing the bounded agent decision summary.

**Files:**
- Create: `src/technocore_sentinel/workflow.py`
- Modify: `examples/agent-workflows/summarize_report.py`
- Create: `tests/test_workflow.py`
- Modify: `tests/test_agent_workflow_example.py`

**Steps:**

1. Add failing tests for pure report validation and summarization, including exact output keys, review triggers for low/medium/high visible findings, count/finding consistency, bool-as-int rejection, nullable fields, additive unknown-field non-leak, and fresh return values.
2. Run the targeted tests and record RED.
3. Implement a pure stdlib module with no I/O/network imports. Export the 1 MiB input bound, strict bytes parser, report summarizer, and compact renderer.
4. Refactor the example stdin script into a thin wrapper using the production module while retaining bounded `MAX+1` reads and stable `error: invalid report` behavior. Add a production stdin entry function for the CLI `summarize-report` subcommand.
5. Run workflow/example tests normally and under `python -O`.

**Required report cross-field invariants:**

- `server_signed_count + unsigned_count == new_message_count`.
- Finding aggregates exactly equal `severity_counts` and `category_counts`.
- `coverage_gap` is exactly equivalent to a positive `missing_sequence_count`, and the count equals the leading sequence gap.
- Empty/new-message and sequence fields agree: no new messages means null `first_seq`/`last_seq` and `next_seq == previous_seq`; new messages require `previous_seq < first_seq <= last_seq == next_seq`.
- `baseline_only` is exactly equivalent to `previous_seq == 0`.
- `baseline` requires `previous_seq == 0`, `baseline_only == true`, `cursor_recovered == false`, and null `recovered_from_seq`.
- `advanced` requires `previous_seq > 0`, `next_seq > previous_seq`, at least one new message, `baseline_only == false`, `cursor_recovered == false`, and null `recovered_from_seq`.
- `healthy_idle` requires `previous_seq > 0`, `next_seq == previous_seq`, no new messages, `baseline_only == false`, `cursor_recovered == false`, and null `recovered_from_seq`.
- `recovered_baseline` requires `previous_seq == 0`, `baseline_only == true`, `cursor_recovered == true`, and non-null `recovered_from_seq > next_seq`.
- Every emitted summary validates directly against the closed `summary_schema`.

### Task 2: Add the one-command `agent-check` integration

**Objective:** Let an agent obtain the safe summary directly without manually composing monitor and consumer commands.

**Files:**
- Modify: `src/technocore_sentinel/cli.py`
- Modify: `src/technocore_sentinel/contract.py`
- Modify: `tests/test_cli.py`
- Modify: `tests/test_contract.py`

**Command:**

```sh
technocore-sentinel agent-check \
  --room lobby \
  --state-file /ABSOLUTE/PRIVATE/PATH/monitor.json \
  --min-severity low
```

**Steps:**

1. Add RED tests proving `agent-check` reuses the existing locked monitor cycle, emits one compact sorted summary line, omits every untrusted finding value, preserves report conditions at exit `0`, and makes operational failures nonzero with no success output.
2. Test that it never creates/loads identity state and uses the existing monitor state/security path.
3. Refactor monitor output selection so the ordinary report renderer or safe-summary renderer completes under the exclusive lock before `_write_json_at()`. A summary validation/rendering failure must leave prior state bytes unchanged and stdout empty. Do not parse/summarize only after `_monitor_cycle()` has committed state.
4. Implement `agent-check` by selecting that pre-commit safe-summary renderer. Do not introduce another Technocore client or scanner.
5. Add the network- and state-free `summarize-report` subcommand. It reads bounded stdin and uses the same strict parser/summary renderer as the example adapter.
6. Extend `agent_contract()` additively with display name, integration purpose, both command names, and a closed `summary_schema`; preserve existing report metadata and schema.
7. Run contract/CLI/monitor tests normally and optimized.

### Task 3: Explain the use case and varied workflows simply

**Objective:** Make the README answer what the integration does in plain language and show distinct, honest workflows.

**Files:**
- Modify: `README.md`
- Modify: `SECURITY.md`
- Modify: `examples/agent-workflows/README.md`
- Modify: `examples/agent-workflows/hermes.md`
- Modify: `examples/agent-workflows/claude-code.md`
- Modify: `examples/agent-workflows/codex.md`
- Modify: `examples/agent-workflows/openclaw.md`
- Modify: `pyproject.toml` description only if needed for display clarity

**Required messaging:**

- Heading/display name: **Technocore Room Safety Monitor**.
- Tagline: “A read-only CLI/JSON safety and coverage gate for Technocore agent workflows.”
- Simple use case: the agent receives a content-free decision about recognized room risks and coverage health; it does not receive or execute hostile room text.
- Honest scope: the tool integrates a Technocore room safety signal into workflows; it is not yet a general read/reply/chat bridge.
- State that this directly supports the goal of integrating Technocore into various agentic workflows, but do not claim official endorsement, adoption, or reward eligibility.

**Concrete workflows:**

1. Interactive agent intake gate: Hermes/Claude/Codex run `agent-check` before deciding whether an operator should inspect new room activity.
2. Scheduled triage: OpenClaw/cron runs one check and queues human review when `review_required` is true.
3. Dashboard/alert ingestion: a local collector consumes compact summary JSON without receiving room excerpts.

All host docs should prefer `agent-check`, retain pinned `RELEASE` placeholders, preserve absolute private paths, fail closed on unknown schema, and retain the advanced two-stage pipeline only through the same pinned environment's `technocore-sentinel summarize-report` command. Remove arbitrary external-Python invocation of the packaged example adapter.

### Task 4: Reviews and verification

**Objective:** Prove exact requirements, code quality, package integrity, and truthful documentation before updating the PR.

**Steps:**

1. Run focused spec review of production workflow module, `agent-check`, contract, examples, and docs.
2. Fix every concrete spec gap with a failing regression.
3. Run independent quality/security review; preserve commit-before-output and existing monitor invariants.
4. Run:

```sh
uv sync --frozen
uv run python -m unittest discover -s tests -v
uv run python -O -m unittest discover -s tests -v
uv run python -m compileall -q src tests examples
npx --yes markdownlint-cli2 README.md SECURITY.md docs/plans/*.md examples/agent-workflows/*.md
git diff --check
uv build --out-dir /NEW/UNIQUE/TEMP/DIRECTORY
```

1. Audit wheel/sdist for `workflow.py`, `contract.py`, and the seven workflow assets; reject `.github`, state, plans, caches, private runtime files, and identities.
2. Run exact-wheel `contract` and `summarize-report` smoke tests against the fixture. Exercise `agent-check` through the installed wheel with an injected/mock client path so no live Technocore call is needed.
3. Commit only reviewed files, explicitly exclude `.github/`, push `feat/incremental-monitor`, update PR #1, and verify remote SHA/content/file list.

## Release/claim restrictions

Do not merge, tag, upload to PyPI, publish a GitHub release, post to X, perform a live Technocore write, or claim official FLOP/Technocore endorsement or reward eligibility without separate explicit authorization and public readback.
