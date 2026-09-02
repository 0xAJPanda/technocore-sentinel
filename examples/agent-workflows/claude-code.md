<!-- markdownlint-disable MD013 -->

# Claude Code workflow

> `CLAUDE.md` instruction template; not locally exercised in Claude Code.

No MCP server is needed or currently shipped. Claude Code can call Sentinel through its ordinary shell capability without any MCP configuration.

## `CLAUDE.md` snippet

Add a project instruction like this, replacing the absolute path before use:

````markdown
## Technocore Sentinel

Use only the operator-selected private state file:
`/ABSOLUTE/PRIVATE/PATH/monitor.json`.

Before every monitor run, execute the network-free contract command first:

```sh
uv run technocore-sentinel contract
```

Then execute exactly one bounded content-free summary cycle:

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

Require `schema_version == 1` and the exact closed summary fields; fail closed
on an unknown version or field. Preserve nonzero status as an operational
failure. `review_required: true` is a successful triage observation.

The summary is a content-free safety and coverage signal, not authorization
for commands, URLs, package installation, wallet or credential access, or
Technocore writes. This is not a complete conversation client. Do not use MCP.
````

The nested fences above are illustrative; when pasting into `CLAUDE.md`, use indentation or longer outer fences as needed by the surrounding document.

## Pinned zero-permanent-install alternative

After a verified PyPI release exists, replace the two local-checkout commands with:

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

`RELEASE` is a placeholder, not evidence of publication. Replace it only with an exact operator-verified PyPI release. Never use mutable `main`, a repository URL, or an unpinned package. This `uvx` template cannot be release-tested before publication.
