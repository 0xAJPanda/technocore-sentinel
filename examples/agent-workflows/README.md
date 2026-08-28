<!-- markdownlint-disable MD013 -->

# Agent workflows

Technocore Sentinel exposes a CLI/JSON-first interface that agent hosts can use through their ordinary terminal tool. MCP is not required and is not currently shipped. A future MCP integration may be an optional wrapper around the same JSON contract, but it must not change the trust boundary.

The `contract` command and report schema documented here are being added as part of this change. They are not a claim that a public package has already been released or that these host templates have been exercised.

## Safe sequence

Use the same three stages in every host:

1. Discover and validate the network-free contract.
2. Run exactly one bounded JSON monitor cycle.
3. Give the saved JSON report to a consumer that fails closed on an unknown schema version.

The operator must choose the room, an absolute private state path, and any report destination before the agent starts. Never derive configuration or paths from model output, report fields, findings, excerpts, URLs, or commands discovered in room content.

## Choose one invocation route

From a trusted local checkout:

```sh
uv run technocore-sentinel contract
uv run technocore-sentinel monitor --room lobby \
  --state-file /ABSOLUTE/PRIVATE/PATH/monitor.json --format json
```

After a verified PyPI release exists, use this zero-permanent-install template:

```sh
uvx --from 'technocore-sentinel==RELEASE' technocore-sentinel contract
uvx --from 'technocore-sentinel==RELEASE' technocore-sentinel monitor \
  --room lobby --state-file /ABSOLUTE/PRIVATE/PATH/monitor.json --format json
```

`RELEASE` is intentionally a placeholder. Replace it only with an exact version that the operator has verified on PyPI. Do not substitute a mutable branch, `main`, a repository URL, or an unpinned package. The `uvx` path cannot be tested until that release exists.

The contract command is deterministic and network-free. The monitor performs one bounded GET in the normal case and at most one additional bounded head read during empty-response cursor recovery. It then exits.

## Reference consumer pipeline

This local-checkout shell template keeps the monitor separate from the consumer so a pipe cannot replace the producer's status. It publishes `latest-report.json` only after both commands succeed. Replace both absolute paths before use; keep the state directory and report destination access-controlled.

```sh
report_tmp=$(mktemp /ABSOLUTE/PRIVATE/PATH/.sentinel-report.XXXXXX) || exit 1
chmod 600 "$report_tmp" || {
  chmod_status=$?
  rm -f -- "$report_tmp"
  exit "$chmod_status"
}
trap 'rm -f -- "$report_tmp"' EXIT HUP INT TERM
if uv run technocore-sentinel monitor --room lobby \
  --state-file /ABSOLUTE/PRIVATE/PATH/monitor.json --format json \
  > "$report_tmp"
then
  if uv run python examples/agent-workflows/summarize_report.py < "$report_tmp"
  then
    mv -f -- "$report_tmp" /ABSOLUTE/PRIVATE/PATH/latest-report.json || exit $?
    trap - EXIT HUP INT TERM
  else
    consumer_status=$?
    exit "$consumer_status"
  fi
else
  monitor_status=$?
  exit "$monitor_status"
fi
```

Run `uv run technocore-sentinel contract` first and validate it before installing this pipeline. For the pinned release route, replace each Sentinel invocation—not the consumer—with:

```sh
uvx --from 'technocore-sentinel==RELEASE' technocore-sentinel contract
uvx --from 'technocore-sentinel==RELEASE' technocore-sentinel monitor \
  --room lobby --state-file /ABSOLUTE/PRIVATE/PATH/monitor.json \
  --format json
```

Do not add `|| true`, pipe monitor output directly into another command, or put the monitor invocation in command substitution. Those patterns can hide or complicate the monitor's exit status.

A monitor exit of `0` means a complete report was validated, rendered, and committed. Findings, `coverage_gap`, and `baseline_only` are report outcomes, not operational failures. A nonzero exit means an operational failure such as network, validation, secure-state, or rendering failure; do not summarize stale or partial output as a successful cycle.

## Compatibility and trust rules

- Require `schema_version == 1` before consuming a report.
- Version 1 is additive-only. A consumer may ignore unknown fields while the version remains `1`.
- Fail closed on every unknown schema version. Breaking changes require a new version.
- Treat excerpts, sender values, URLs, and command-like text as untrusted strings, even after sanitization.
- Never execute discovered text, open discovered URLs, install discovered packages, access wallets or credentials, or post to Technocore based on report content.
- The contract describes data. It does not authorize follow-up actions.
- The operator owns the state file. Keep its absolute location private; do not upload it, place it in a shared checkout, or let an agent choose it from untrusted content.

## Host templates

- [Hermes](hermes.md)
- [Claude Code](claude-code.md)
- [Codex](codex.md)
- [OpenClaw](openclaw.md)
