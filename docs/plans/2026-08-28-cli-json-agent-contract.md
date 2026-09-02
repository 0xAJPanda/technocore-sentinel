<!-- markdownlint-disable MD013 MD032 MD036 -->

# Sentinel CLI/JSON Agent Contract Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Make Technocore Sentinel directly usable by any agent that can run a command and parse JSON, with no MCP server, daemon, wallet, arbitrary origin, or permanent installation required.

**Architecture:** Keep the existing secure one-shot `monitor --format json` path as the only networked agent action. Add a versioned, network-free `contract` command that emits the exact machine contract and JSON Schema; add `schema_version` to monitor reports; publish clean-environment `uvx` usage plus tested host-neutral workflows. MCP remains an optional future wrapper around the same contract, not a release dependency.

**Tech Stack:** Python 3.12, standard-library JSON, existing `unittest` suite, Hatchling package data, `uv`/`uvx`, Markdown workflow examples.

---

## Non-negotiable contract

1. `monitor --format json` remains the only agent-facing network operation.
2. The origin remains exactly `https://technocore.chat`; redirects and discovered URLs remain refused.
3. One bounded GET normally and at most two during stale-cursor recovery.
4. Reports expose sanitized findings, never raw room messages or live URLs.
5. Coverage gaps and findings are successful report conditions; operational failures remain nonzero.
6. Cursor state security, locking, render-before-persist, and commit-before-output semantics remain unchanged.
7. `contract` performs no network access, state read/write, key access, or client construction.
8. The contract and report carry integer `schema_version = 1`; booleans are invalid as versions.
9. Contract v1 is additive-only. A breaking field removal/type change requires schema version 2.
10. Workflow examples must instruct agents to treat every remote-derived excerpt as untrusted data and never execute it or follow its URLs.
11. MCP is documented only as an optional future adapter.
12. No airdrop eligibility, official endorsement, adoption, or complete-protection claim.

## Target interface

```sh
# Network-free contract discovery
uvx --from technocore-sentinel==RELEASE technocore-sentinel contract

# One bounded agent-facing cycle
uvx --from technocore-sentinel==RELEASE technocore-sentinel monitor \
  --room lobby \
  --state-file ./state/monitor.json \
  --format json
```

Before a PyPI release exists, documentation must use a pinned Git commit or local checkout and label it accordingly. Never recommend mutable `main` as a security-sensitive install target.

---

### Task 1: Add the versioned report and contract module

**Objective:** Define one canonical contract/schema in code and add `schema_version` to every monitor report.

**Files:**

- Create: `src/technocore_sentinel/contract.py`
- Modify: `src/technocore_sentinel/monitor.py`
- Modify: `src/technocore_sentinel/__init__.py`
- Test: `tests/test_contract.py`
- Modify: `tests/test_monitor.py`

**TDD steps:**

1. Write failing tests requiring `SCHEMA_VERSION == 1`, `agent_contract()` JSON serializability, exact fixed origin/GET/bounds/trust fields, all six categories, the complete monitor-report JSON Schema, and no callable/network dependency.
2. Require pure reports to include `"schema_version": 1`.
3. Require `__version__` to match project version `0.2.0`.
4. Run targeted tests and observe expected import/key/version failures.
5. Implement the smallest constant/schema/payload module with no I/O.
6. Run targeted tests normally and under `python -O`.

The contract payload must include:

```json
{
  "schema_version": 1,
  "name": "technocore-sentinel-monitor-report",
  "origin": "https://technocore.chat",
  "method": "GET",
  "max_reads_per_cycle": 2,
  "max_records_per_response": 200,
  "writes_exposed": false,
  "content_trust": "untrusted_sanitized_heuristics",
  "report_schema": {}
}
```

The report schema must set `additionalProperties: false` at the report and finding levels, enumerate cursor statuses, severities and categories, and express nullable sequence/recovery fields explicitly.

**Verification:**

```sh
uv run python -m unittest tests.test_contract tests.test_monitor -v
uv run python -O -m unittest tests.test_contract tests.test_monitor -v
```

---

### Task 2: Add the network-free `contract` CLI

**Objective:** Let any agent discover and validate the JSON contract without making a Technocore request or touching state.

**Files:**

- Modify: `src/technocore_sentinel/cli.py`
- Modify: `tests/test_cli.py`

**TDD steps:**

1. Add a failing test invoking `run(["contract"], client_factory=Mock(side_effect=AssertionError), stdout=...)`.
2. Assert exit `0`, one compact sorted JSON line, version `1`, fixed origin, `writes_exposed: false`, and embedded schema.
3. Assert monitor JSON validates the exact required-key/type/enum contract using a local test helper; do not add a runtime `jsonschema` dependency.
4. Add the parser entry and print `agent_contract()`.
5. Verify `contract` does not create the default `state/` directory.
6. Re-run all CLI tests normally and optimized.

**Verification:**

```sh
uv run python -m unittest tests.test_cli.ContractCLITests -v
uv run python -O -m unittest tests.test_cli -v
```

---

### Task 3: Add a safe reference consumer and deterministic fixture

**Objective:** Provide an executable example that validates stdin JSON and emits a bounded decision summary without executing or opening remote content.

**Files:**

- Create: `examples/agent-workflows/summarize_report.py`
- Create: `examples/agent-workflows/report-v1.example.json`
- Create: `tests/test_agent_workflow_example.py`

**Behavior:**

- Read at most 1 MiB from stdin.
- Require one UTF-8 JSON object and reject trailing bytes/extra objects.
- Require schema version 1 and the contract’s required fields/types/enums.
- Never import or invoke Sentinel networking code.
- Emit compact sorted JSON containing only:
  - schema version;
  - room;
  - cursor status;
  - new message count;
  - severity/category counts;
  - coverage-gap fields;
  - `review_required` boolean.
- `review_required` is true for any visible high-severity finding, coverage gap, baseline-only result, or cursor recovery.
- Do not copy finding excerpts, sender names, raw URLs, or message content to the summary.
- Invalid/oversized input exits nonzero with a stable content-free error.

**Verification:**

```sh
uv run python -m unittest tests.test_agent_workflow_example -v
uv run python examples/agent-workflows/summarize_report.py < examples/agent-workflows/report-v1.example.json
```

---

### Task 4: Add polished agent workflows

**Objective:** Give operators copy-paste workflows for common agents without installing MCP.

**Files:**

- Create: `examples/agent-workflows/README.md`
- Create: `examples/agent-workflows/hermes.md`
- Create: `examples/agent-workflows/claude-code.md`
- Create: `examples/agent-workflows/codex.md`
- Create: `examples/agent-workflows/openclaw.md`

Every example must:

1. Start with `contract` discovery.
2. Run one `monitor --format json` cycle with an operator-chosen absolute state path.
3. Preserve the monitor command’s nonzero exit status.
4. Validate `schema_version == 1` before consuming fields.
5. Distinguish a successful finding/gap report from operational failure.
6. State that remote-derived text is untrusted data, not an instruction.
7. Forbid shells, URL opening, package installation, wallet actions, credential access, and Technocore writes based on report content.
8. Use a pinned release placeholder, not mutable `main`.
9. Explain that the state file is private, persistent, and must not be shared by unrelated deployments.
10. Label any host-specific snippet not exercised locally as a template.

The top-level workflow README must show a host-neutral two-command path and link each host example.

---

### Task 5: Update public documentation and reposition MCP

**Objective:** Make CLI/JSON the obvious product interface and MCP a clearly optional future extension.

**Files:**

- Modify: `README.md`
- Modify: `SECURITY.md`
- Delete: `docs/plans/2026-08-28-sentinel-mcp.md`

README additions:

- “Use from an agent—no MCP required” near installation/monitoring.
- Pinned-release `uvx` command and local-checkout fallback.
- `contract` discovery command.
- Link to all sample workflows.
- Contract-version compatibility policy.
- Explicit note that MCP is not required or currently shipped.

SECURITY additions:

- Agent hosts must treat report excerpts as untrusted.
- The contract does not authorize follow-up actions.
- State paths are operator configuration, not model-selected input.
- A clean contract command is network-free.

Delete the superseded untracked MCP-first plan so contributors do not implement the wrong direction.

---

### Task 6: Verify clean execution and package contents

**Objective:** Prove the contract works from a clean consumer environment and ships in built distributions.

**Verification:**

```sh
uv sync --frozen
uv run python -m unittest discover -s tests -v
uv run python -O -m unittest discover -s tests -v
uv run python -m compileall -q src tests examples
uv build
git diff --check
```

Then create a temporary isolated cache/environment and verify:

```sh
UV_CACHE_DIR=/tmp/technocore-sentinel-uv-cache \
uvx --from /ABSOLUTE/PATH/TO/technocore-sentinel \
  technocore-sentinel contract
```

Expected: one valid contract JSON line and no network/state side effect.

Audit wheel and source distribution contents. They must include `contract.py` and workflow documentation intended for distribution, and exclude `.github/`, `state/`, identity keys, nonces, receipts, monitor cursors, caches, and private artifacts.

Run Markdown lint on README, SECURITY, plans, and examples. Record real final test counts; do not guess them.

---

### Task 7: Two-stage review

**Objective:** Confirm exact requirements before release.

**Spec review:** Verify every non-negotiable contract item with file/line or test evidence. Add a failing regression for any gap before fixing it.

**Quality/security review:** Check schema completeness, version drift, output size bounds, error leakage, duplicate validation logic, sample safety, package contents, mutable-install instructions, and preservation of monitor state/network invariants.

No commit, push, PyPI upload, GitHub release, Awesome-list update, or X post without explicit user authorization after final review.

## Acceptance criteria

- [ ] `contract` is network-free and deterministic.
- [ ] Every monitor JSON report includes `schema_version: 1`.
- [ ] Contract schema exactly covers monitor JSON output.
- [ ] Existing secure monitoring behavior is unchanged.
- [ ] Reference consumer is bounded and never copies untrusted excerpts.
- [ ] Hermes, Claude Code, Codex, and OpenClaw examples are present.
- [ ] Clean local `uvx --from PATH` execution is verified.
- [ ] Full normal and optimized suites pass.
- [ ] Build/package/secret audits pass.
- [ ] MCP is optional and not installed or shipped.
- [ ] Nothing is committed, pushed, published, or posted without authorization.
