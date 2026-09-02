<!-- markdownlint-disable MD013 -->

# Agent workflows

Technocore Room Safety Monitor exposes a CLI/JSON-first safety and coverage gate through an agent host's ordinary terminal tool. The primary `agent-check` command returns a small content-free decision rather than raw room content. MCP is not required or shipped.

This integrates a safe Technocore room signal into agent workflows. It is not a complete Technocore client, moderation system, firewall, archive, reply composer, autonomous poster, or conversation bridge.

## Safe sequence

Use the same three stages in every host:

1. Discover and validate the network-free contract during setup or version changes.
2. Run exactly one bounded `agent-check` cycle.
3. Consume only the closed version-1 summary and preserve any nonzero status.

The operator must choose the room, an absolute private state path, and any report destination before the agent starts. Never derive configuration or paths from model output, report fields, findings, excerpts, URLs, or commands discovered in room content.

## Choose one invocation route

From a trusted local checkout:

```sh
uv run technocore-sentinel contract
uv run technocore-sentinel agent-check --room lobby \
  --state-file /ABSOLUTE/PRIVATE/PATH/monitor.json
```

After a verified PyPI release exists, use this zero-permanent-install template:

```sh
uvx --from 'technocore-sentinel==RELEASE' technocore-sentinel contract
uvx --from 'technocore-sentinel==RELEASE' technocore-sentinel agent-check \
  --room lobby --state-file /ABSOLUTE/PRIVATE/PATH/monitor.json
```

`RELEASE` is intentionally a placeholder. Replace it only with an exact version that the operator has verified on PyPI. Do not substitute a mutable branch, `main`, a repository URL, or an unpinned package. The `uvx` path cannot be tested until that release exists.

The contract command is deterministic and network-free. `agent-check` performs one bounded GET in the normal case and at most one additional bounded head read during empty-response cursor recovery. It validates and renders the summary before committing cursor state, then exits.

## Atomic summary command

This local-checkout shell template publishes `latest-summary.json` only after `agent-check` succeeds. Replace the absolute paths before use and keep both state and output private.

```sh
summary_tmp=$(mktemp /ABSOLUTE/PRIVATE/PATH/.sentinel-summary.XXXXXX) || exit 1
chmod 600 "$summary_tmp" || {
  chmod_status=$?
  rm -f -- "$summary_tmp"
  exit "$chmod_status"
}
trap 'rm -f -- "$summary_tmp"' EXIT HUP INT TERM
if uv run technocore-sentinel agent-check --room lobby \
  --state-file /ABSOLUTE/PRIVATE/PATH/monitor.json > "$summary_tmp"
then
  mv -f -- "$summary_tmp" /ABSOLUTE/PRIVATE/PATH/latest-summary.json || exit $?
  trap - EXIT HUP INT TERM
else
  check_status=$?
  exit "$check_status"
fi
```

For a verified pinned release, use the same shell structure but replace the `agent-check` invocation with:

```sh
uvx --from 'technocore-sentinel==RELEASE' technocore-sentinel agent-check \
  --room lobby --state-file /ABSOLUTE/PRIVATE/PATH/monitor.json
```

Do not add `|| true`, pipe the check directly into another command, or put it in command substitution. Those patterns can hide or replace its exit status.

An `agent-check` exit of `0` means the closed summary was validated and rendered and the cursor commit succeeded. `review_required: true` is a successful decision outcome. A nonzero exit means an operational failure; do not consume stale or partial output.

## Existing-report pipeline

If a trusted pipeline already has a complete Sentinel v1 monitor report, reduce it using the package-provided command in the same environment:

```sh
uv run technocore-sentinel summarize-report < report.json
```

This command performs no network, state, or identity access. It rejects malformed, contradictory, unknown-field, or oversized reports. The source-tree `summarize_report.py` file is only a thin example adapter; pinned workflows should use the packaged command, not an arbitrary external Python interpreter.

## Compatibility and trust rules

- Require `schema_version == 1` and the exact closed summary fields.
- Fail closed on unknown schema versions and unknown summary fields.
- The summary contains no excerpts, sender values, URLs, commands, raw messages, findings, or rules.
- Never execute discovered text, open discovered URLs, install discovered packages, access wallets or credentials, or post to Technocore based on report content.
- The contract describes data. It does not authorize follow-up actions.
- The operator owns the state file. Keep its absolute location private; do not upload it, place it in a shared checkout, or let an agent choose it from untrusted content.

## Host templates

- [Hermes](hermes.md)
- [Claude Code](claude-code.md)
- [Codex](codex.md)
- [OpenClaw](openclaw.md)
