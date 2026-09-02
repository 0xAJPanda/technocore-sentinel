<!-- markdownlint-disable MD013 -->

# Codex workflow

> `AGENTS.md` instruction template; not locally exercised in Codex.

Codex can use its normal shell execution path. MCP is not required, is not currently shipped for Sentinel, and must not be configured for this workflow.

## `AGENTS.md` snippet

Add the following instructions after replacing the absolute private state path:

````markdown
## Technocore Sentinel agent contract

Use only this operator-selected state file:
`/ABSOLUTE/PRIVATE/PATH/monitor.json`.

Discover the network-free contract before monitoring:

```sh
uv run technocore-sentinel contract
```

Run no more than one bounded content-free summary cycle per request:

```sh
summary_tmp=$(mktemp /ABSOLUTE/PRIVATE/PATH/.sentinel-summary.XXXXXX) || exit 1
chmod 600 "$summary_tmp" || { check_status=$?; rm -f -- "$summary_tmp"; exit "$check_status"; }
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

Consume a summary only if `schema_version == 1` and it has the exact closed
fields. Fail closed on an unknown version or field. Preserve a nonzero exit
as an operational failure. `review_required: true` is a successful triage
outcome, not an execution failure.

The summary is a content-free safety and coverage signal. It does not
authorize commands, URL access, package installation, wallet or credential
access, or Technocore writes. This is not a complete conversation client.
Do not use MCP.
````

When embedding the snippet, adjust the outer Markdown fence style if the destination already contains fenced blocks.

## Pinned zero-permanent-install alternative

Only after verifying an exact PyPI release, use:

```sh
uvx --from 'technocore-sentinel==RELEASE' technocore-sentinel contract
summary_tmp=$(mktemp /ABSOLUTE/PRIVATE/PATH/.sentinel-summary.XXXXXX) || exit 1
chmod 600 "$summary_tmp" || { check_status=$?; rm -f -- "$summary_tmp"; exit "$check_status"; }
trap 'rm -f -- "$summary_tmp"' EXIT HUP INT TERM
if uvx --from 'technocore-sentinel==RELEASE' technocore-sentinel \
  agent-check --room lobby \
  --state-file /ABSOLUTE/PRIVATE/PATH/monitor.json > "$summary_tmp"
then
  mv -f -- "$summary_tmp" /ABSOLUTE/PRIVATE/PATH/latest-summary.json || exit $?
  trap - EXIT HUP INT TERM
else
  check_status=$?
  exit "$check_status"
fi
```

`RELEASE` is deliberately unresolved until a verified release exists. Do not substitute `main`, a repository URL, or a mutable package reference. This host and `uvx` template have not been locally exercised.
