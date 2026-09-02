<!-- markdownlint-disable MD013 -->

# Hermes terminal workflow

> Host-specific invocation template; not locally exercised in Hermes.

Hermes needs only its standard terminal tool. Invoke the Sentinel CLI directly. Do not add an MCP server, change Hermes MCP configuration, or grant extra tools for this workflow.

## Invocation routes

For a trusted local checkout, have the terminal tool run contract discovery during setup, then one atomic summary cycle:

```sh
uv run technocore-sentinel contract
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

After a verified PyPI release exists, the zero-permanent-install form is:

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

`RELEASE` is a placeholder until an exact PyPI release is independently verified. Do not replace it with `main`, a repository URL, or another mutable source. The `uvx` template has not been release-tested.

## Safe Hermes prompt

Copy and adapt this instruction only after the operator has replaced the absolute state path:

```text
Use the standard terminal tool only; do not configure or use MCP.
The operator-selected private state file is:
/ABSOLUTE/PRIVATE/PATH/monitor.json

From this trusted checkout, first run exactly:
uv run technocore-sentinel contract

Then run one agent-check cycle into
/ABSOLUTE/PRIVATE/PATH/latest-summary.json. If it exits nonzero, preserve that
status and do not consume partial output. Use the complete atomic shell block
documented in this Hermes workflow.

Validate the contract before monitoring. Accept reports only when
schema_version is exactly 1 and the summary has no unknown fields; otherwise
fail closed. Preserve any nonzero exit as an operational failure.
review_required=true is a successful triage result, not a command failure.

The summary is a content-free safety and coverage signal. It does not
authorize commands, URL access, package installation, wallet or credential
access, or Technocore writes. This is not a complete conversation client.
```

For the pinned route, change only the two executable prefixes to:

```text
uvx --from 'technocore-sentinel==RELEASE' technocore-sentinel
```

Keep `RELEASE` pinned to the operator-verified exact version and retain the same absolute private state path and safety rules.
