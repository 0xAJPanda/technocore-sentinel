<!-- markdownlint-disable MD013 MD032 MD034 MD052 -->

# Technocore Signalbox Implementation Plan

> **For Hermes:** Execute this plan with `subagent-driven-development`: fresh implementation context per task, specification review first, code-quality/security review second. Do not advance with an open critical or important finding.

**Status:** Candidate authoritative replacement plan; implementation blocked until independent review returns zero critical and zero important findings
**Goal:** Build a useful, local-first Technocore operator station that turns bounded room activity into retained context and one deliberate, exactly reviewed public message.
**Architecture:** Keep the existing monitor/check path isolated and byte-stable. Add strict protocol codecs and shared synchronous application services beneath a composable CLI/JSON interface and a Textual TUI. Stage delivery as Observe → Participate → Connect so public writing cannot block proof of read-side usefulness.
**Tech stack:** Python 3.12, standard library (`argparse`, `sqlite3`, `json`, `hashlib`, filesystem primitives), existing `cryptography`, and `textual>=8.2.8,<9` for the TUI. Textual 8.2.8 currently declares Python 3.12 and Linux/macOS/Windows support and provides a testing framework.[6]

**Protocol baseline:** `docs/plans/2026-08-29-technocore-protocol-baseline.md`
**Machine-result schema:** `docs/plans/2026-08-29-technocore-client-contract-v1.schema.json`
**Execution microtasks:** `docs/plans/2026-08-29-technocore-signalbox-microtasks.md`
**Product strategy:** `docs/plans/2026-08-28-technocore-product-strategy.md`
**Brand brief:** `docs/plans/2026-08-28-technocore-brand-brief.md`

When approved, this document supersedes `docs/plans/2026-08-28-technocore-relay-expansion.md`, which remains historical and non-executable. The protocol baseline is authoritative for external endpoint assumptions; the product strategy and brand brief are authoritative for scope and language; the launch plan is authoritative only for post-verification publication mechanics.

The protocol baseline reconciles the live OpenAPI, agent manifest, and deployment configuration rather than trusting their conflicting version labels.[1][2][3]

Its empty and non-empty room-envelope rules were also checked against bounded read-only `/r/events` samples; no live write was used.[4][5]

---

## Release definition

Signalbox is ready only when all of the following are true:

1. An operator can discover public rooms, inspect one validated bounded window, foreground-follow selected rooms, retain observations under explicit time/row/byte bounds, see coverage gaps, and search retained observations locally.
2. The TUI and CLI call the same tested application services; no network, cache, drafting, or posting behavior exists only in the TUI.
3. A message can be drafted and revised without network, signing, nonce allocation, or receipt mutation.
4. Approval binds to the exact canonical draft bytes; a mismatched digest fails before identity, state, or network access.
5. Public submission is command-specific and explicit, exact readback is distinguished from uncertainty, and no ambiguous outcome is automatically retried.
6. `check` and `agent-check` remain content-free, identity-free, cache-free, draft-free, event-free, and byte-compatible with the existing monitor contract. Their network allowlist is exactly bounded room reads (`GET /r/{canonical-room}` with only `format=json`, `limit`, and optional `since`); tests reject every GET write lane (`/say`, `/say-signed`, `/set`, `/set-signed`) as well as every POST.
7. Normal, optimized, package, fresh-wheel, TUI pilot, documentation, security, specification, quality, and exact-artifact gates pass from the same release candidate.
8. The README and imagery show only implemented behavior. No claim promises complete history, safe content, trusted authors, autonomous participation, moderation, or endorsement.
9. Public GitHub state is read back from the exact pushed SHA, CI succeeds, and forbidden private/runtime paths are absent.

## Global invariants

- Canonical origin remains exactly `https://technocore.chat`; redirects are refused, TLS verification remains enabled, environment proxies are disabled, non-identity content encodings are rejected, decoded response bodies are capped at one MiB, room-message windows are capped at 200 records, and discovery accepts at most 200 entries. One monotonic 20-second deadline covers connect, headers, body, cancellation, and watchdog teardown.
- Every server-provided string is untrusted data. It cannot configure a command, URL, filesystem path, identity, cache target, selected room, draft, or public write without an explicit local operator action.
- New operator commands use the strict protocol projection from the protocol baseline. Existing monitor schemas and `technocore-sentinel-monitor-report` stay unchanged.
- Private state lives beneath an exact `0700` real directory. Absolute paths are walked from an opened root descriptor and relative paths from an opened current-directory descriptor; every existing component is opened with directory plus no-follow flags, `..` is rejected, and writable-by-untrusted intermediate components are rejected. Only a missing final parent may be created with descriptor-relative `mkdir` mode `0700`; concurrent creation, intermediate symlink swaps, renamed ancestors, and final-parent replacement are detected by inode rechecks. Before any side effect, every caller-selected or derived target is represented as `(parent st_dev, parent st_ino, basename)` through that anchored parent descriptor, absent-target aliases are compared, existing inode aliases are compared, and regular files with `st_nlink != 1` are rejected. Regular state/database/draft/event/lock/journal files are exact `0600`; symlinks and special files are rejected. Temporary, lock, transaction-journal, SQLite `-journal`, `-wal`, and `-shm` names participate in collision checks, and every non-SQLite operation remains descriptor-relative.
- JSON decoders reject duplicate keys, invalid UTF-8, trailing data, `NaN`/infinities, booleans where integers are required, and integer tokens longer than 64 canonical decimal digits before semantic validation. A recursive scalar validator rejects every decoded or local string containing an unpaired/lone surrogate code point before hashing, projection, persistence, JSON output, terminal rendering, events, or TUI use; a valid escaped surrogate pair that decodes to one scalar remains valid.
- Dry runs make zero network requests, allocate no nonce, change no durable state, and print no signature or private key.
- No routine test or protocol-discovery task performs a live write.
- Existing `introduce --submit` and `publish-profile --submit` are quarantined before network access until their separate endpoint-specific write gates pass; dry runs remain network-free.
- No commit or public push occurs before the Task 15 candidate-publication authorization gate. PR merge, repository rename, tag, release, PyPI upload, and social posts each remain blocked until their later exact-scope gate.

## Output conventions

- Human text output is fixed-label, control-character-free, and clearly marks room text/names/topics as public untrusted data.
- Automation JSON is compact, sorted, closed, versioned, and emitted as exactly one object followed by LF.
- JSONL is reserved for operational events, one closed object per LF-terminated line, and never mixes logs with stdout. Operator commands use text or one closed JSON result so coverage/truncation truth cannot be separated from records.
- Machine-readable invocations emit one terminal result envelope only; progress and plans are never printed before a later operation can fail.
- Successful commands write no stderr. Pre-side-effect failures write no stdout and one stable content-free error code to stderr.
- Any possibly public outcome uses a closed stdout result with `retry_post:false`; it never emits raw HTTP bodies, exception text, signatures, keys, URLs, local paths, draft text, or remote/untrusted sender data. The locally selected posting DID is permitted only in `technocore-message-result`.
- Exit `0` means the declared operation fully completed. Exit `1` means exact evidence proves no public effect, including pre-attempt failure or a validated definite refusal; a post-transport refusal emits its closed outcome envelope. Exit `2` means a local-only operation committed partial bounded progress before stopping. Exit `20` means public outcome uncertain. Exit `21` means remote verification succeeded but local commit/closure degraded. Exit `22` means the underlying operation otherwise completed successfully but its requested terminal event append failed. These meanings are schema-tested normally and under optimized Python.

## Resource and lock graph

- Every lock acquisition has a five-second monotonic ceiling and the registered content-free `resource_busy` outcome. Signalbox file locks use a securely descriptor-opened persistent `0600` regular lock file plus `fcntl.flock(LOCK_EX|LOCK_NB)`; a lock pathname is never an exclusive-create ownership token. V1 advertises stateful/mutating Signalbox capabilities only on Linux local filesystems that pass a two-process startup probe proving live-holder exclusion and holder-death release on the actual state parent; all other platforms/filesystems quarantine those capabilities with `cache_backend_unsupported` or `capability_post_unavailable`. Lock files are never unlinked or replaced while any process may use them, kernel ownership is released by descriptor close or process death, and acquisition retries only until the ceiling. Tests kill a holder process at every transaction phase and prove a new process can acquire the same persistent file without stale-file breaking, while a live holder can never be bypassed.
- Event locks are held only while validating capacity and appending/fsyncing one bounded line; they are released before network, cache, draft, pending, or identity work.
- Cache locks are held only for bounded SQLite open/query/transaction/close work and never across room reads or long polls.
- Draft locks are held only for one bounded descriptor read or atomic replacement and never across signing/network.
- The derived pending/identity transaction lock is held across one bounded POST/readback/local-commit transaction to prevent a second submit, but no event or cache lock is nested beneath it.
- V1 permits one outstanding public message operation per identity state directory. The pending path is the fixed sibling `.message-pending.json` derived from the nonce/receipt parent, not a caller-selected pathname; a non-closed record blocks every new submit until GET-only reconciliation completes.
- Commands acquire no two independent store locks simultaneously. Tests enumerate every command's resources and run concurrent read/follow/search/draft/send/reconcile/event cases to prove no upgrade, deadlock, or starvation.

## Closed machine-output registry

The authoritative planning schema `docs/plans/2026-08-29-technocore-client-contract-v1.schema.json` fixes JSON types, required/null fields, enums, limits, and nested records for every currently knowable v1 result. Task 2 ports it into `src/technocore_sentinel/client_contract.py` and proves byte-equivalent schema behavior. Every object is closed and nullable fields are present rather than omitted. The only intentionally absent variant is `technocore-rooms`; Task 4 adds its exact nested projection to both schemas after the bounded shape spike and before production room discovery is enabled.

Draft 2020-12 conditional branches make outcome/evidence states disjoint: verified or remotely degraded outcomes require non-null remote evidence, while no-write, uncertain, and pre-attempt-canceled outcomes require null remote evidence. Redundant result counts that portable JSON Schema cannot equate to array lengths are omitted; runtime semantic validation still enforces protocol equalities such as server `count == len(messages)` and exact first/final sequence agreement before constructing a result. Locally generated times use `$defs.utcTimestamp` for lexical shape and must additionally pass `datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")`, have year `1..9999`, and exactly equal reserialization with the same format; this calendar check is mandatory regardless of whether the JSON Schema validator asserts `format`. Tests reject impossible dates, offsets, missing/fewer/more fractional digits, and noncanonical but parseable forms. Remote `ts`/`timestamp` evidence remains exact, opaque, non-empty Unicode-scalar server data and never enters that local-time validator.

`$defs.errorCode` is the complete v1 stable-error registry. Pre-side-effect stderr contains exactly one registry member plus LF and no prose; `technocore-operation-outcome.error_code` is null or one member of the same registry. Implementations must not expose exception names, HTTP bodies, paths, URLs, or unregistered strings as error codes.

| `kind` | Exact top-level fields |
| --- | --- |
| `technocore-rooms` | `schema_version`, `kind`, `requested_limit`, `returned_count`, `emitted_count`, `truncated`, `rooms` |
| `technocore-room-read` | `schema_version`, `kind`, `room`, `requested_since`, `limit`, `first_seq`, `last_seq`, `coverage`, `records` |
| `technocore-room-follow` | `schema_version`, `kind`, `room`, `started_at`, `finished_at`, `cycles`, `requests`, `record_count`, `response_bytes`, `first_seq`, `last_seq`, `coverage`, `budget`, `outcome`, `stop_reason` |
| `technocore-local-search` | `schema_version`, `kind`, `scope`, `query`, `room_filter`, `limit`, `results` |
| `technocore-cache-status` | `schema_version`, `kind`, `cache_schema_version`, `message_count`, `max_messages`, `retention_days`, `database_bytes`, `max_database_bytes`, `total_room_count`, `emitted_room_count`, `rooms_truncated`, `rooms` |
| `technocore-cache-prune` | `schema_version`, `kind`, `before_count`, `after_count`, `pruned_count`, `remaining_over_limit`, `transactions_committed`, `outcome` |
| `technocore-message-draft` | `schema_version`, `kind`, `room`, `created_at`, `draft_sha256` |
| `technocore-message-plan` | `schema_version`, `kind`, `room`, `text`, `draft_sha256`, `submit_required`, `live_submit_enabled` |
| `technocore-message-result` | `schema_version`, `kind`, `outcome`, `verified`, `did`, `room`, `seq`, `timestamp`, `nonce`, `draft_sha256`, `event_status`, `retry_post` |
| `technocore-reconcile-result` | `schema_version`, `kind`, `outcome`, `invocation_id`, `room`, `remote_seq`, `event_status`, `retry_post` |
| `technocore-operation-outcome` | `schema_version`, `kind`, `outcome`, `invocation_id`, `room`, `draft_sha256`, `remote_seq`, `error_code`, `event_status`, `retry_post` |

`RoomMessage`, coverage, search-result, cache-room, follow-budget, enum, nullable, and limit definitions are exactly those in the authoritative schema; implementation tasks may not add fields or invent enum members. Task 4's reviewed `technocore-rooms` addition is the only schema amendment allowed before gateway-3 re-review.

Follow `budget` contains exactly `duration_seconds`, `wait_seconds`, `max_cycles`, `max_records`, `max_bytes`, `max_consecutive_failures`, `remaining_seconds`, `remaining_cycles`, `remaining_records`, `remaining_bytes`, and `remaining_consecutive_failures`; configured values never disappear from a terminal result.

Text output is a deterministic rendering of the same result model. Rooms, read, follow, search, cache, draft, plan, send, and reconcile support only text or one closed JSON result. JSONL is permitted only for operational events.

Exit precedence is deterministic: use `20` when exact remote verification never completed and public truth is uncertain; use `21` when exact remote verification completed but local commit/closure degraded. Either public-state code outranks event failure. Local partial progress uses `2` and outranks event failure. Exit `22` is used only when the underlying result would be `0`; definite-refusal/no-public-effect remains `1` even if its terminal event fails. Intent-event failure occurs before POST and exits `1`. Every public/operation outcome records `event_status` as `not_requested`, `recorded`, or `failed`; sink failure never changes `retry_post` or pending truth.

## Executable capability registry

Task 1 creates `src/technocore_sentinel/capabilities.py` with a closed `CapabilityStatus` model and an exact command map: `rooms→rooms`, `read→read`, `follow→read+follow`, `message send→read+post`, `message reconcile→read`, `publish-profile→profile-write`, and event-room consumption `→read+events-room`. Each capability names its transport, strict request-aware validator, fixture-set hash, and enabled/quarantined state; `require_capabilities()` fails only the affected command before mutation.

Read capabilities prove themselves through the endpoint-specific strict response validator on every request; v1 has no global version cache. The room-post manifest is the packaged resource `src/technocore_sentinel/data/post-message-capability-v1.json`, serialized as compact sorted UTF-8 JSON plus LF with exact closed fields: `schema_version:1`, `kind:"technocore-post-capability"`, `enabled`, `origin`, `method`, `path_template`, `query`, `operation_sha256`, `fixture_set_sha256`, `success_media`, `success_shape`, `observed_at`, and `approval_scope`. Disabled manifests use null hashes/media/shape/time/scope; enabled manifests require origin `https://technocore.chat`, method `POST`, path `/r/{room}`, query `format=json`, 64-lower-hex hashes, `application/json`, `full-room-envelope-v1`, canonical UTC time, and scope `controlled-live-write-v1`.

The post capability remains disabled until the controlled exercise produces that manifest. Operation canonicalization uses the strict duplicate-key/scalar/64-digit decoder, selects exactly `document["paths"]["/r/{room}"]["post"]`, rejects any `$ref` recursively, and encodes that object with `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")` with no trailing LF before SHA-256. Fixture-set hashing sorts the exact relative POSIX paths matching `tests/fixtures/technocore-0.10.0/post-*` bytewise; for each path it feeds ASCII decimal path-byte length, colon, path bytes, LF, ASCII decimal file-byte length, colon, raw file bytes, and LF into one SHA-256. Before each live submit—and only after digest validation but before identity-state mutation—the client performs a bounded read-only OpenAPI probe and requires both manifest hashes. Drift quarantines post without disabling read commands. `profile-write` has its own independent manifest and remains disabled otherwise.

The non-installed controlled exercise is `tools/controlled_post_exercise.py`, excluded from wheel/sdist. It alone accepts descriptor-read compact sorted UTF-8 JSON plus LF, at most 8 KiB, with exactly `schema_version:1`, `kind:"technocore-controlled-post-authorization"`, `origin:"https://technocore.chat"`, canonical `room`, `draft_sha256`, exact case-sensitive canonical Ed25519 `did:key`, `operation_sha256`, `fixture_set_sha256`, canonical local `expires_at`, and `max_post_requests:1`. All digests are 64 lowercase hexadecimal characters; unknown/duplicate/non-scalar fields fail closed. At harness start, `expires_at` must be strictly after the validated current UTC snapshot and no more than 15 minutes later; the same snapshot is retained for the invocation so wall-clock rollback cannot extend it. The operator reviews those exact bytes and supplies the file path explicitly. The bootstrap service first requires the exact packaged disabled manifest with all required null fields, then uses the authorization—not those null manifest fields—as the sole expected operation/fixture hashes. It freshly computes the fixture hash and probes/canonicalizes the live operation, requires both to equal the authorization, and requires every fixed origin/method/path/query/media/shape/scope field that the future enabled manifest will contain. Only that exact bootstrap API bypasses `enabled` and null hashes; normal CLI/TUI paths cannot call it. The harness then calls the same digest check, pre-write cursor, private pending/nonce journal, one POST, strict response, readback, and no-retry/reconcile services as normal send. It creates the fully populated enabled manifest atomically only after remote verification and local commit; uncertain/refused/degraded outcomes leave the exact disabled bytes unchanged and pending truth intact. Tests begin from the packaged disabled bytes and prove null-hash bootstrap success, every authorization/computed-hash/expiry mismatch refusal before identity mutation, and normal-path inability to substitute authorization hashes. No routine test writes live.

## Execution granularity

The numbered Task sections are release gateways, not single implementation-agent units. The already-authored `docs/plans/2026-08-29-technocore-signalbox-microtasks.md` is the authoritative 2–5 minute RED→observed-failure→minimal-GREEN checklist; no expansion is deferred to execution. Each item receives specification review and then quality/security review before the next item touching the same files. A gateway closes only after every listed microtask and its focused plus regression commands pass.

---

## Task 0: Freeze the compatibility baseline

**Objective:** Make regression against the reviewed monitor and signed-onboarding behavior mechanically visible before refactoring.

**Files:**

- Modify: `tests/test_cli.py`
- Modify: `tests/test_client.py`
- Modify: `tests/test_contract.py`
- Create: `tests/fixtures/compatibility/monitor-contract-v1.jsonl`
- Create: `docs/plans/2026-08-29-release-input-manifest.md`
- Verify: `src/technocore_sentinel/cli.py`
- Verify: `src/technocore_sentinel/client.py`
- Verify: `src/technocore_sentinel/contract.py`

**Steps:**

1. Record baseline commit `bf7e90bd42e66ad4b03d6c3e5e7e28ecf1890684` and classify every pre-existing modified/untracked path as intended release input, historical plan, separately reviewed workflow, or excluded material; never treat the dirty tree as one implicit baseline.
2. Add RED golden tests for exact `contract` bytes, compatibility-command parser inventory, `check`/`agent-check` isolation, monitor state bytes, and current dry-run/submit authorization boundaries. Additive Signalbox commands are tested separately and never require weakening the compatibility inventory.
3. Add exact request-route allowlist tests proving `check` and `agent-check` cannot reach any GET write lane or POST, even if a room value resembles a route segment.
4. Add RED tests proving both legacy `--submit` surfaces fail with a stable compatibility-quarantined error before identity/client/network/state mutation while their dry runs remain byte-reviewed and network-free.
5. Add a RED test proving a default `TechnocoreClient` ignores `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and lowercase variants.
6. Run focused tests and capture only the intended quarantine/proxy failures.
7. Build the default opener with `ProxyHandler({})` plus redirect refusal and add the explicit submit quarantine; make no unrelated behavior change.
8. Run focused tests normally and with `python -O`.
9. Run every original baseline test ID recorded in the release-input manifest normally and optimized; require all to pass with no deletion or weakened assertion except the deliberate unsafe-submit quarantine. Report the discovered total rather than hard-coding the post-addition suite count.

**Verify:**

```sh
uv run python -m unittest tests.test_client tests.test_cli tests.test_contract -v
uv run python -O -m unittest tests.test_client tests.test_cli tests.test_contract -v
uv run python -m unittest discover -s tests
uv run python -O -m unittest discover -s tests
```

## Task 1: Freeze strict 0.10.0 fixtures and codecs

**Objective:** Add one strict, reusable protocol boundary for new Signalbox commands without changing compatibility-monitor parsing.

**Files:**

- Create: `src/technocore_sentinel/protocol.py`
- Create: `src/technocore_sentinel/transport.py`
- Create: `src/technocore_sentinel/capabilities.py`
- Create: `tests/test_protocol.py`
- Create: `tests/test_transport.py`
- Create: `tests/test_capabilities.py`
- Create: `tests/fixtures/technocore-0.10.0/*.json`
- Modify: `src/technocore_sentinel/client.py`
- Modify: `tests/test_client.py`

**Steps:**

1. Create the synthetic room/read/post/refusal fixtures listed in the protocol baseline except `rooms-minimal.json`, which Task 4 must derive from its bounded discovery spike. Include valid empty/non-empty/signed/gap envelopes and one malformed fixture per rejected field/type/encoding case.
2. Add RED tests for bounded duplicate-key-safe JSON decoding and the exact strict room envelope.
3. Add immutable `RoomMessage` and `RoomWindow` models. Preserve `ts` as an opaque non-empty string and do not sort by timestamp. Do not invent protocol-rejection maxima for `from` or `ts`; human rendering may visibly truncate escaped display copies while typed automation retains the accepted value.
4. Require envelope fields `room`, `count`, `last_seq`, and `messages`; permit only optional `first_seq`; require message `seq`, `ts`, `from`, `text`, and optional `nonce`.
5. Enforce canonical room grammar, `0 <= count == len(messages) <= requested_limit <= 200`, positive contiguous message sequences within each non-empty returned window, 4,096-character text, optional positive 1–19 digit integer nonce, Unicode-scalar-only strings, and documented empty-window semantics. Request-aware validation requires the requested room, exact `first_seq`/first-message and `last_seq`/final-message agreement, every incremental sequence greater than `since`, visible leading gaps, and no empty-cursor rewind.
6. Implement each network request in a supervised spawned child process, with request/body data sent through a bounded private IPC channel—not argv, environment, disk, stdout, or stderr. One monotonic total deadline reserves its final two seconds for teardown: normal result transfer must complete by `deadline-2`; then terminate has at most 0.5 seconds and kill plus join has at most 1.5 seconds. The parent therefore bounds process start, DNS, connect, headers, body, result transfer, and teardown within the original total rather than adding cleanup afterward. The child also closes an active connection on cancellation, uses remaining-time chunk reads, rejects non-identity `Content-Encoding`, and returns only a bounded typed result. For POST, child termination after durable `post_attempted` is uncertain, never definitely canceled.
7. Add a strict `TechnocoreClient.read_room` that returns `RoomWindow`; leave `get_room` and monitor callers unchanged.
8. Implement the independent capability registry, command map, fixture hashes, default post/profile quarantine, and stable capability errors. Test that one missing capability never disables an unrelated command.
9. Test malformed media, encoding, redirects, body cap, invalid UTF-8, escaped lone high/low surrogates recursively in every server string, one valid escaped astral scalar pair, duplicate keys, trailing data, 65-digit integer bombs, unknown fields, wrong room, replayed `seq <= since`, timestamp absence, count mismatch, first/final cursor mismatch, sequence disorder, blocked DNS, blocked connect, cancellation in DNS/connect/header/body phases, slow-drip deadline expiry, bounded terminate/kill/join, and zero surviving child processes. Reuse the scalar validator in CLI, TUI, drafts, cache, and events tests.

**Verify:**

```sh
uv run python -m unittest tests.test_protocol tests.test_transport tests.test_capabilities tests.test_client -v
uv run python -O -m unittest tests.test_protocol tests.test_transport tests.test_capabilities tests.test_client -v
```

## Task 2: Add the stable Signalbox CLI identity

**Objective:** Introduce the operator-facing command without breaking existing automation.

**Files:**

- Modify: `pyproject.toml`
- Modify: `src/technocore_sentinel/cli.py`
- Modify: `src/technocore_sentinel/contract.py`
- Create: `src/technocore_sentinel/client_contract.py`
- Verify: `docs/plans/2026-08-29-technocore-client-contract-v1.schema.json`
- Create: `tests/test_client_contract.py`
- Modify: `tests/test_cli.py`
- Modify: `tests/test_contract.py`

**Steps:**

1. Add RED package tests requiring both `technocore-agent` and `technocore-sentinel` console scripts to call the same `main`.
2. Make parser display identity injectable/default to `technocore-agent`; executable spelling must not change behavior.
3. Add preferred `check` and retain `agent-check` as the same handler. Prove byte-identical stdout/stderr, exit status, requests, locks, and state.
4. Keep `contract` byte-for-byte stable, including `writes_exposed:false`.
5. Port the authoritative planning JSON Schema into a separate closed `client-contract` v1, validate every example and malformed case against both representations, and fail if their normalized schema bytes diverge; do not expose raw schemas through Python object reprs.
6. Implement the mandatory calendar-valid local UTC timestamp parser/re-serialization rule from the output registry independently of optional JSON Schema `format` support; apply it to every local timestamp before model construction and include hostile impossible-date fixtures.
7. Keep repository, distribution, and import package names unchanged for the first Signalbox release.
8. Build into a newly created empty temporary output directory, capture the exact wheel path and SHA-256, and confirm both scripts from that artifact. Never select the first result from a repository `dist/*.whl` glob or inspect a pre-existing artifact.

**Verify:**

```sh
uv run python -m unittest tests.test_cli tests.test_contract tests.test_client_contract -v
OUT="$(mktemp -d)"
uv build --out-dir "$OUT"
uv run python -c "import hashlib,pathlib,zipfile; p=next(pathlib.Path('$OUT').glob('*.whl')); print(p, hashlib.sha256(p.read_bytes()).hexdigest(), zipfile.ZipFile(p).namelist())"
```

## Task 3: Introduce shared application services

**Objective:** Prevent CLI and TUI from becoming separate implementations.

**Files:**

- Create: `src/technocore_sentinel/application.py`
- Create: `src/technocore_sentinel/models.py`
- Create: `tests/test_application.py`
- Modify: `src/technocore_sentinel/cli.py`

**Steps:**

1. Add RED tests for injectable client, clock, UUID source, and storage interfaces.
2. Define immutable request/result models and explicit interfaces for network transport, strict room projection, cache repository, draft store, approval verifier, submit transaction, reconciliation, and event sink.
3. Implement synchronous application services with no `argparse`, terminal rendering, Textual widgets, or global filesystem defaults.
4. Keep external data wrapped in typed untrusted models; no service executes content or follows discovered URLs.
5. CLI and TUI are thin adapters: neither shells out to the other, parses the other's stdout, owns signing logic, opens protocol URLs directly, or bypasses approval/result models.
6. Move only one existing harmless command through the service boundary as an integration proof; prove exact compatibility output.
7. Document lock ordering in module constants and tests before multiple stores exist.

**Verify:**

```sh
uv run python -m unittest tests.test_application tests.test_cli -v
```

## Task 4: Implement bounded room discovery and reading

**Objective:** Deliver the first useful Observe slice with no durable cache requirement.

**Files:**

- Modify: `src/technocore_sentinel/client.py`
- Modify: `src/technocore_sentinel/application.py`
- Modify: `src/technocore_sentinel/cli.py`
- Create: `tests/test_rooms.py`
- Modify: `tests/test_client.py`
- Modify: `tests/test_cli.py`

**Commands:**

```text
technocore-agent rooms --limit 1..200 --format text|json
technocore-agent read --room ROOM --limit 1..200 [--since SEQ] --format text|json
```

**Steps:**

1. Run a bounded read-only `/rooms?format=json&limit=2` shape spike; record only field names/types and synthetic equivalents, never live names/topics.
2. If the observed projection cannot be reconciled with OpenAPI, stop this task and revise the protocol baseline.
3. From that spike, create synthetic `tests/fixtures/technocore-0.10.0/rooms-minimal.json`, freeze its tolerant-wire-to-closed-local room-summary projection, add the exact `technocore-rooms`/`roomSummary` variant to both authoritative schemas, and update the `rooms` capability fixture hash. Caller-controlled `room` and `topic` are always explicitly marked untrusted; unknown wire fields gain no semantics. Re-run gateway-3 schema review before production parsing.
4. Implement one bounded `list_rooms` request and one strict `read_room` request. No automatic follow, cache, identity, draft, event, or write access.
5. Enforce a client-owned request/output bound of 200 independently of any server default or missing OpenAPI maximum. Preserve observed server ordering for emitted entries, report returned/emitted/truncated counts explicitly, reject discovered room names that fail canonical grammar, and never auto-select or auto-follow a discovered room. The shape spike freezes types for every projected field; because upstream publishes no per-field string maxima, semantic decoding relies on the one-MiB body cap while human/JSONL renderers apply explicit escaped UTF-8 line/display limits and a visible `display_truncated` marker rather than rejecting an otherwise valid response.
6. Emit deterministic oldest-first read records with exact `seq`, opaque `ts`, `from`, `text`, nullable `nonce`, and `content_trust:"public_untrusted_data"`.
7. Add terminal escaping tests for ANSI/control characters, bidi controls, markup, URLs, long Unicode, and hostile topics.
8. Add network-call-count tests and prove `read` does not call the scanner unless the operator separately runs `check`.

**Verify:**

```sh
uv run python -m unittest tests.test_rooms tests.test_client tests.test_application tests.test_cli -v
```

## Task 5: Prove and implement the bounded local cache

**Objective:** Retain only validated observations under explicit row, age, and byte bounds while keeping coverage uncertainty visible.

**Files:**

- Create: `docs/spikes/sqlite-secure-open.md`
- Create: `src/technocore_sentinel/cache.py`
- Create: `tests/test_cache.py`
- Modify: `src/technocore_sentinel/application.py`
- Modify: `src/technocore_sentinel/cli.py`

**Feasibility gate:**

1. In a disposable directory, first test the root/CWD descriptor component walker, no-follow opening, single-final-component creation, ownership/mode checks, intermediate symlink swaps, renamed ancestors, concurrent final-parent creation, and final inode rechecks.
2. Prove a supported-platform mechanism that binds SQLite creation/reopen to that anchored parent and verified basename before SQLite receives access, while preserving `0600` database/rollback-journal modes, lock serialization, `journal_mode=DELETE`, `secure_delete=ON`, `temp_store=MEMORY`, `page_size=4096`, and `max_page_count`. An ordinary pathname passed after a best-effort check is not sufficient; connection setup and immediate post-open inode checks must prove the main/derived files belong to the anchored parent.
3. Record exact supported-platform behavior and residual SQLite auxiliary-file race in `docs/spikes/sqlite-secure-open.md`.
4. If the main database and rollback journal cannot meet the documented invariant on a platform, stop the cache gateway and block release on that platform. Any append-only alternative requires a new separately reviewed plan; no unspecified fallback may be invented during implementation.
5. State supported filesystems/platforms and residual races explicitly. Exact `0600` modes and `secure_delete=ON` do not protect snapshots, backups, swap, or a compromised account.

**Initial bounds:**

- rows: default 10,000; allowed 1..50,000;
- age: default 30 days; allowed 1..365;
- database: 64 MiB main-file ceiling plus documented transient rollback-journal overhead;
- mutation batch: at most 500 rows;
- gap/anomaly details: at most 10,000 merged records;
- lock wait: at most five seconds.

**One-shot command added in this task:** `technocore-agent read --room ROOM --limit 1..200 [--since SEQ] --cache-file PATH --format text|json`. Supplying `--cache-file` performs the same one strict network read as Task 4, commits that complete validated window through the cache repository, and only then emits its result; omission remains cache-free. A cache failure emits no success, advances no reported local cursor, and cannot trigger a second network request.

**TDD steps:**

1. Add RED schema/configuration and one-shot read/cache CLI tests before creating production tables.
2. Store canonical sequence/nonce decimal text plus digit lengths to avoid SQLite signed-integer truncation; preserve the first observation timestamp on exact duplicates.
3. Persist settings and schema/user version. V1 performs no in-place migration because no prior Signalbox cache exists; mismatched settings and unknown/newer versions fail closed with backup/export guidance.
4. Ingest only complete strict `RoomWindow` values inside `BEGIN IMMEDIATE`.
5. Exact duplicates are idempotent; conflicting duplicates roll back the whole window.
6. Track baseline gaps, internal gaps, local prune gaps, and server regressions separately.
7. Prune deterministically by observation time, room, sequence digit length, and sequence digits in bounded transactions.
8. Enforce row, age, page, and detail limits; do not auto-`VACUUM` or claim deleted bytes are erased from backups/snapshots.
9. Cover disk-full rollback, corruption, interruption, contention, malformed persisted rows, symlinks, special files, unsafe modes, aliasing/inode replacement attempts, and configuration drift. If prune spans multiple 500-row transactions, report committed progress and remaining work rather than one all-or-nothing result.

**Verify:**

```sh
uv run python -m unittest tests.test_cache -v
uv run python -O -m unittest tests.test_cache -v
```

## Task 6: Add foreground bounded follow

**Objective:** Keep selected rooms current without shipping a daemon or tight polling loop.

**Files:**

- Modify: `src/technocore_sentinel/client.py`
- Modify: `src/technocore_sentinel/application.py`
- Modify: `src/technocore_sentinel/cli.py`
- Create: `tests/test_follow.py`

**Command:**

```text
technocore-agent follow --room ROOM --cache-file PATH --duration 3..3600 [--wait 1..10] [--max-cycles 1..10000] [--max-records 1..50000] [--max-bytes 1..67108864] [--max-consecutive-failures 1..10]
```

**Steps:**

1. Add RED tests for monotonic duration, cycle/request, record, response-byte, aggregate-byte, consecutive-failure, cancellation, empty long-poll, gap, regression, rate-limit, slow response, and cache-failure behavior using an injected monotonic clock/client.
2. Freeze defaults: `wait=10`, `max_cycles=360`, `max_records=10000`, `max_bytes=16777216`, and `max_consecutive_failures=3`. One cycle is exactly one room HTTP request followed by zero or one bounded cache transaction, so cycle count equals request count and no hidden capability/head request occurs. Every terminal result reports configured, consumed, and remaining budgets.
3. Before each request compute `remaining_seconds=floor(deadline-now)` and `work_seconds=floor(deadline-now-2)`, reserving the transport's exact final two seconds. If `work_seconds < 1`, stop completed for `deadline` without a request; otherwise serialize decimal-integer `effective_wait=min(configured_wait, 10, work_seconds)`. The supervised transport receives `min(20, exact monotonic time remaining)` as its total deadline and applies the same two-second reserve internally. The minimum accepted duration is three seconds, and cross-layer tests cover setup delay around the three-second boundary, zero-request deadline completion, terminate/kill timing, and no surviving child. Network work cannot overshoot the follow deadline; only one already-started bounded local commit may finish afterward.
4. Use `since=last_seq` and bounded `wait`; accept an empty response as normal and reuse the same cursor.
5. Cap each response read at `min(one_MiB, remaining_bytes)+1` to detect byte-budget overflow. An over-byte response is discarded without parse/cache/output/cursor advancement and stops `byte_limit`; consumed wire bytes saturate at the configured maximum. After complete strict validation, a window with `count > remaining_records` is discarded without cache/output/cursor advancement and stops `record_limit`. Otherwise commit the complete window before advancing output/cursor. Remaining counters never become negative, and no partial window is committed. Never hold the cache/database lock during a long poll or any network request.
6. On Ctrl-C, finish or roll back the active local transaction, start no new request, and emit one terminal message-body-free summary without claiming uninterrupted coverage.
7. Stop on exhausted failure budget, rate limit, cache error, protocol contradiction, capability mismatch, or operator interrupt; do not hidden-retry malformed responses.
8. No background process, daemonization, automatic restart, or automatic room discovery is allowed.
9. Outcome/exit mapping is closed: `deadline`, `cycle_limit`, `record_limit`, or `byte_limit` are expected configured bounds and emit `outcome:"completed"` with exit `0`, whether or not they retained records. `failure_limit`, `interrupted`, `rate_limited`, `cache_error`, `protocol_error`, or `capability_error` emit `outcome:"partial"` with exit `2` exactly when `record_count >= 1`; with zero retained records they emit `outcome:"stopped"` with exit `1`. No other outcome/reason pair is valid. The client-contract schema enforces these combinations and the partial/stopped record-count boundary.

**Verify:**

```sh
uv run python -m unittest tests.test_follow tests.test_cache tests.test_client -v
```

## Task 7: Add local search and cache status

**Objective:** Make retained observations useful without inventing remote search or complete history.

**Files:**

- Modify: `src/technocore_sentinel/cache.py`
- Modify: `src/technocore_sentinel/application.py`
- Modify: `src/technocore_sentinel/cli.py`
- Modify: `tests/test_cache.py`
- Modify: `tests/test_cli.py`

**Commands:**

```text
technocore-agent search --cache-file PATH --query TEXT [--room ROOM] [--limit 1..200] --format text|json
technocore-agent cache status --cache-file PATH --format text|json
technocore-agent cache prune --cache-file PATH --format text|json
```

**Steps:**

1. Add RED tests proving all three commands are network-, identity-, draft-, and signing-free.
2. Treat queries as literal case-folded text using parameterized `instr`; no SQL/wildcard/regex semantics.
3. Cap query at 1,024 characters and 4,096 UTF-8 bytes; cap results at 200.
4. Return deterministic newest-observed results while retaining original room sequence.
5. Status emits no message/sender text and reports row/byte/age bounds, retained duration per emitted room, baseline status, gaps, regressions, and prune uncertainty. It computes all distinct retained rooms, orders them by canonical room name ascending, emits at most the first 200, and reports exact `total_room_count`, `emitted_room_count == len(rooms)`, and `rooms_truncated == (total_room_count > emitted_room_count)`. Thus a valid cache with more than 200 rooms is represented without claiming a complete room list.
6. Prune output is emitted only after all bounded transactions commit; partial failure reports committed progress honestly.

**Verify:**

```sh
uv run python -m unittest tests.test_cache tests.test_application tests.test_cli -v
```

## Task 8: Observe CLI usefulness gate

**Objective:** Prove the shared-core CLI is more useful than repeated raw fetches before adding TUI or public-write scope.

**Files:**

- Create: `tests/test_observe_journey.py`
- Create: `examples/operator-workflow/observe.sh`
- Modify: `README.md`
- Modify: `SECURITY.md`

**Journey:**

1. List synthetic rooms.
2. Manually select one.
3. Read and cache a bounded window.
4. Follow two empty cycles and one advancing cycle.
5. Surface an internal gap and a local-prune gap.
6. Search retained observations locally.
7. Inspect cache status.
8. Run isolated `check` and prove its output contains no message text.

**Gate:** normal and optimized suites pass; install-to-first-useful-result is measured from a fresh wheel; a skeptical independent reviewer reports zero critical/important Observe findings and judges the workflow materially clearer than raw fetch plus ad hoc files. If the CLI journey is not coherent, improve Observe before TUI or Participate. Before publication, the user receives a hands-on operator walkthrough and either accepts the hero journey or explicitly identifies changes to make.

## Task 9: Build the Signalbox TUI on shared services

**Objective:** Provide the professional operator experience only after the shared-core CLI Observe proof passes.

**Files:**

- Modify: `pyproject.toml`
- Create: `src/technocore_sentinel/tui.py`
- Create: `src/technocore_sentinel/signalbox.tcss`
- Create: `tests/test_tui.py`
- Modify: `src/technocore_sentinel/cli.py`

**Command:**

```text
technocore-agent tui [--cache-file PATH]
```

**Screens:**

1. Room desk: bounded room list, explicit untrusted labels, manual room selection.
2. Observation desk: current bounded window, sequence/coverage status, foreground-follow controls.
3. Local context: literal search, retained duration, gaps, and cache bounds.
4. Outbox placeholder in Observe: explains that public sending is unavailable until Participate is installed; no disabled control may imply a write occurred.
5. Detached check panel: invokes the same isolated content-free check service and never passes raw message text into an agent prompt.

**Steps:**

1. Add `textual>=8.2.8,<9`; update and inspect `uv.lock` before production code.
2. Add RED headless pilot tests for navigation, manual room selection, hostile ANSI/bidi/markup/width rendering, cache status, cancellation, stale result invalidation, resize/color fallback, noninteractive-terminal failure, and zero-write behavior.
3. Use workers only to call shared synchronous application services; cancellation must stop foreground follow cleanly.
4. Prove the TUI never shells out to the CLI, parses CLI stdout, opens a protocol URL, or owns signing/submit logic.
5. Apply approved navy/cyan/lime/amber roles with color-independent labels and keyboard-accessible controls.
6. Bound rendered records and widget content; no unbounded in-memory transcript.
7. Add snapshots/screenshots from deterministic synthetic fixtures only.
8. Audit Textual and transitive licenses, wheel contents, import-time behavior, and supported terminal/platform matrix; CLI remains the complete noninteractive fallback.
9. Exercise the Observe journey through headless pilots and require one explicit gesture per state-changing local action.

**Verify:**

```sh
uv run python -m unittest tests.test_tui tests.test_application -v
uv run technocore-agent tui --help
```

## Task 10: Add network-free canonical message drafts

**Objective:** Make public text a durable local artifact that can be reviewed without signing or network access.

**Files:**

- Create: `src/technocore_sentinel/drafts.py`
- Create: `tests/test_drafts.py`
- Modify: `src/technocore_sentinel/application.py`
- Modify: `src/technocore_sentinel/cli.py`
- Modify: `src/technocore_sentinel/tui.py`

**Commands:**

```text
technocore-agent message draft --room ROOM --text TEXT --draft-file PATH
technocore-agent message show --draft-file PATH --format text|json
technocore-agent message plan --draft-file PATH --format text|json
```

**Steps:**

1. Define closed draft v1 fields: `schema_version`, `kind:"technocore-message"`, `room`, `text`, and canonical local `created_at`.
2. Canonical bytes are compact sorted UTF-8 JSON plus one LF, capped at 16 KiB. Approval digest is lowercase SHA-256 of those complete bytes.
3. Draft/show/plan are network-, identity-, nonce-, receipt-, pending-, and signing-free.
4. Apply the existing single-line sweep and 4,096-character bound before persistence.
5. Use anchored atomic replacement into a `0700` parent and exact `0600` regular file; reject symlinks, special files, unsafe modes, duplicate/unknown fields, malformed timestamps, and trailing data.
6. `message plan` displays the exact future public text and digest but no DID, signature, nonce, private path, or simulated success.
7. TUI outbox edits only a local draft and shows exact digest/status; no button performs a network write in this task.

**Verify:**

```sh
uv run python -m unittest tests.test_drafts tests.test_application tests.test_tui -v
```

## Task 11: Implement exact-digest submit and reconciliation

**Objective:** Publish only the exact reviewed draft and distinguish verified, uncertain, and locally degraded outcomes without automatic retry.

**Files:**

- Modify: `src/technocore_sentinel/protocol.py`
- Modify: `src/technocore_sentinel/client.py`
- Modify: `src/technocore_sentinel/application.py`
- Modify: `src/technocore_sentinel/drafts.py`
- Create: `src/technocore_sentinel/pending.py`
- Create: `src/technocore_sentinel/transaction.py`
- Create: `src/technocore_sentinel/data/post-message-capability-v1.json`
- Create: `tools/controlled_post_exercise.py`
- Modify: `src/technocore_sentinel/cli.py`
- Modify: `src/technocore_sentinel/tui.py`
- Create: `tests/test_participate.py`
- Create: `tests/test_controlled_post_exercise.py`
- Modify: `tests/test_client.py`
- Modify: `tests/test_cli.py`

**Commands:**

```text
technocore-agent message send --draft-file PATH --approve-sha256 HEX --key-file PATH --nonce-file PATH --receipt-file PATH --submit
technocore-agent message reconcile --key-file PATH --nonce-file PATH --receipt-file PATH
```

**Pending v1 schema:** exactly `schema_version`, `kind`, `invocation_id`, `phase`, `room`, `did`, `nonce`, `prior_last_seq`, `draft_sha256`, `draft_canonical_b64`, `text`, `remote_seq`, `remote_ts`, `created_at`, and `updated_at`. `schema_version` is integer `1`; `kind` is `technocore-message-pending`; UUID, room, and hexadecimal digest are lowercase canonical values, while DID preserves the exact case-sensitive canonical `did:key`. Nonce is a canonical 1–19 digit decimal string; sequence values are canonical 1–64 digit decimal strings (prior cursor may be `0`); decoded draft bytes are at most 16 KiB; text is Unicode-scalar-only and at most 4,096 characters; locally generated `created_at`/`updated_at` are canonical UTC RFC 3339; `remote_ts` is null or the exact non-empty Unicode-scalar opaque server value; the complete file is at most 32 KiB.

Legal phase edges are: `prepared→post_attempted` or `prepared→closed` before transport; `post_attempted→remote_verified`, or `post_attempted→closed` only after a validated definite refusal; `remote_verified→locally_committed→closed`. Idempotent self-replay is allowed; every other skip or reversal is rejected. `remote_seq`/`remote_ts` are null through `post_attempted` and both non-null from `remote_verified` onward; a no-write `closed` record keeps them null, while a verified `closed` record keeps them non-null. Decoded `draft_canonical_b64` must hash to `draft_sha256`, parse as the closed draft, and exactly reproduce `room` and `text`; DID must match the loaded public key; reserved nonce and prior cursor must match local transaction evidence. Unknown/corrupt fields, invalid phase invariants, digest disagreement, newer-state conflict, or non-scalar strings fail closed without signing, network, cleanup, or state rollback.

**Steps:**

1. Implement the new send path against the full strict room-envelope success fixture. Keep legacy `introduce --submit` and `publish-profile --submit` quarantined; do not infer one endpoint's success contract from another or re-enable either as part of this task.
2. Add `SubmitAuthorization("post-message")`; no generic write authorization.
3. Read/validate the draft once through one descriptor, hash those exact bytes, compare with `hmac.compare_digest`, and use the associated text unchanged.
4. Reject digest mismatch before identity load, signing state, client construction, or network.
5. After digest validation, require the recorded post capability manifest and perform its bounded read-only OpenAPI-operation hash probe. Then perform one strict pre-write room GET, bind it to the requested room, and persist its validated `last_seq` as the prior cursor before any signing-state mutation.
6. Require key, nonce, receipt, pending, transaction journal, and lock to share one anchored `0700` identity-state parent. Derive fixed siblings `.message-pending.json`, `.message-transaction.journal`, and `.message.lock`; permit no caller-selected pending/journal/lock path.
7. Implement the exact pending schema and transition invariants above. The private record deliberately contains reconciliation evidence and is not called content-free or message-body-free; it is `0600`, artifact-forbidden, bounded, and closed.
8. Use one closed, 96-KiB-bounded transaction journal with exact fields `schema_version`, `kind`, `transaction_id`, `journal_phase`, `nonce_bytes_b64`, `nonce_sha256`, `pending_primary_bytes_b64`, `pending_primary_sha256`, `pending_secondary_bytes_b64`, `pending_secondary_sha256`, `receipt_state`, `receipt_bytes_b64`, and `receipt_sha256`. `journal_phase` is `reserve`, `commit_verified`, or `cleanup`; `receipt_state` is `absent` or `present`, and receipt bytes/hash are both null exactly when absent. `reserve` has prepared primary and null secondary; `commit_verified` has remote-verified primary, locally-committed secondary, and present receipt; `cleanup` has closed primary, null secondary, and preserves the exact pre-existing absent/present receipt state. Every intended byte string is complete and independently hash-validated before replay.
9. For `reserve`, durably advance the nonce high-water mark and create `prepared` pending before transport: journal temp write+fsync → journal rename+parent fsync → nonce temp write+fsync → nonce rename+parent fsync → pending temp write+fsync → pending rename+parent fsync → journal unlink+parent fsync. A definitely-not-posted outcome may consume a nonce; it is never reused.
10. Transition pending through atomic temp write+file fsync → rename+parent fsync to `post_attempted` immediately before issuing exactly one POST; after that durable transition cancellation cannot report “canceled” or authorize a POST retry.
11. Strictly validate the full POST response, locate exactly one DID/text/nonce match with sequence greater than the persisted prior cursor, then perform one independent bounded GET readback for exact room/sequence/timestamp confirmation and complete coverage.
12. On verification, construct deterministic complete `remote_verified` and `locally_committed` pending bytes—including their already-selected local `updated_at` values—and receipt bytes, then create/fsync/rename a `commit_verified` journal containing both pending byte strings plus unchanged reserved nonce bytes. Replay exactly: write primary remote-verified pending+fsync+rename+parent fsync; write receipt+fsync+rename+parent fsync; verify nonce equal/newer without rollback; write secondary locally-committed pending+fsync+rename+parent fsync; unlink journal+parent fsync. Any exact newer-state conflict fails closed.
13. For final closure, create/fsync/rename a `cleanup` journal containing complete closed primary pending, null secondary pending, nonce bytes/hash, and the exact current receipt state. Replay writes closed pending+fsync+rename+parent fsync; validates receipt absence or exact existing bytes according to `receipt_state`; unlinks pending+parent fsync; unlinks journal+parent fsync. A crash with pending already absent revalidates nonce/receipt state and removes only the journal. Prepared cancellation or definite refusal uses `receipt_state:"absent"` on first use and never invents a receipt.
14. Recovery is phase-total: replay any journal solely from its validated phase/bytes; without a journal, `prepared` closes without network and leaves nonce consumed, `post_attempted` performs exactly one `GET /r/{room}?format=json&limit=200&since={prior_last_seq}` with no `wait`, `remote_verified` recreates `commit_verified`, and `locally_committed`/`closed` recreate `cleanup`. Recovery never signs, allocates another nonce, or POSTs.
15. Classify failures from the last durable phase and endpoint-specific refusal allowlist as definitely not posted, post outcome uncertain, remote verified/local commit failed, or local committed/pending cleanup failed. Unknown statuses, malformed/oversized refusal bodies, no match, multiple matches, and lost/gapped readback coverage remain uncertain. Every possibly public result has `retry_post:false`.
16. Reconcile loads the explicit key, derives the exact case-sensitive DID, and matches it with room, canonical nonce, exact text bytes/digest, sequence/freshness evidence, and complete coverage from the private pending record. No match, multiple matches, unavailable coverage, or contradiction stays uncertain.
17. Enforce the global anchored-target identity and `st_nlink == 1` rules for draft, pending, key, nonce, receipt, cache, event, temporary, lock, journal, and SQLite-derived paths before side effects.
18. Add crash/fault injection after every temporary write, file fsync, rename, directory fsync, request, parse, readback, state commit, close, and unlink plus concurrency tests proving double submit/reconcile cannot POST twice or reuse a nonce. Kill a process while it holds the persistent kernel transaction lock at each durable pending phase; prove the kernel releases ownership without unlinking the lock file, recovery can reacquire it, and a separately live holder still produces `resource_busy` after five seconds rather than stale-file breaking.
19. TUI may prepare/review the exact command packet, but final submit requires typing the digest or a separate explicit confirmation screen that displays exact text, room, digest, and irreversible-public warning. Any draft/room/digest change invalidates confirmation; headless tests prove one activation cannot bypass review.
20. A cooperative cancellation token is checked before every local transition and immediately before durably entering `post_attempted`. Once that phase is durable the UI disables cancellation; closing/navigating away reports the eventual uncertain/verified/degraded result and cannot label the operation canceled. Race tests cover every cancellation check and phase boundary.
21. Implement and test the non-installed controlled-exercise harness described in the executable capability registry. Its authorization file is descriptor-read, closed, canonical, Unicode-scalar-only, at most 8 KiB, and expires against a supplied wall-clock snapshot taken before execution. Starting from the exact null-hash packaged disabled manifest, its isolated bootstrap service takes expected hashes only from that authorization, compares them with fresh fixture/OpenAPI computations, and then injects one authorization into the shared submit transaction; normal CLI/TUI constructors cannot construct, deserialize, or call that bootstrap type. A successful exact POST/readback writes fully populated enabled manifest bytes for candidate review; every refusal, uncertainty, local degradation, mismatch, expiry, or cancellation leaves the exact disabled bytes unchanged and preserves pending truth.

**Verify:**

```sh
uv run python -m unittest tests.test_participate tests.test_controlled_post_exercise tests.test_client tests.test_cli tests.test_tui -v
uv run python -O -m unittest tests.test_participate tests.test_controlled_post_exercise tests.test_client tests.test_cli tests.test_tui -v
```

## Task 12: Add closed message-body-free operational events

**Objective:** Let two concrete schedulers/agent consumers observe lifecycle state without duplicating message bodies or sender/topic data.

**Entry gate:** This task is conditional and is not required for Signalbox v1. Begin only after the operator names and accepts two real external consumers, their required lifecycle fields, and why existing terminal result envelopes are insufficient. Without that evidence, defer Connect, omit event claims/artifacts, and release the complete Observe/Participate product without this task.

**Files:**

- Create: `src/technocore_sentinel/events.py`
- Create: `tests/test_events.py`
- Create: `examples/agent-workflows/consume_events.py`
- Create: `examples/agent-workflows/event_to_alert.py`
- Modify: `src/technocore_sentinel/application.py`
- Modify: `src/technocore_sentinel/cli.py`
- Modify: `src/technocore_sentinel/contract.py`

**Event fields:** exactly `schema_version`, `timestamp`, `invocation_id`, `event_type`, `status`, `room`, `seq`, `draft_sha256`, `record_count`, `cache_message_count`, `cache_pruned_count`, and `error_code`.

**Steps:**

1. Add RED closed-schema tests and a forbidden-content corpus covering message/draft text, sender, topic, URLs, signatures, keys, paths, raw HTTP errors, and secrets. Document that nullable room and digest fields are permitted operational identifiers; room remains caller-controlled untrusted data.
2. Support only explicit `--events-file PATH`; `check` and `agent-check` remain event-free.
3. Bound each line to 4,096 bytes, file to 16 MiB, and count to 100,000. V1 does not rotate automatically.
4. Validate existing logs under bounds, reject partial final lines, and serialize concurrent appenders with an anchored five-second lock.
5. Preflight and durably append public-write intent, fsync, then release the event lock before acquiring pending/identity locks or sending POST. Attempt one terminal outcome later under a new short event-lock hold for every underlying conclusion: definitely-not-posted, uncertain, verified, remote-verified/local-commit-failed, local-committed/pending-cleanup-failed, or canceled-before-attempt. If that append fails, only the terminal result envelope records `event_status:"failed"`; no nonexistent event is claimed.
6. Define command-specific degraded outcomes for intent/terminal failure; fail before POST if requested intent recording fails, but never reinterpret a terminal-event failure as posting failure or retry authority.
7. Implement and test the two accepted real consumer adapters plus synthetic contract fixtures; preserve unknown-field rejection, nonzero/degraded outcomes, and `retry_post:false`. Disabling or deferring events leaves Observe/Participate behavior unchanged.
8. Add exact event semantics to `client-contract` without changing monitor `contract`.

**Verify:**

```sh
uv run python -m unittest tests.test_events tests.test_contract tests.test_application tests.test_cli -v
```

## Task 13: Finish brand, documentation, and deterministic proof assets

**Objective:** Present Signalbox as a product operators can understand and verify, not as a plan or security guarantee.

**Files:**

- Create: `docs/BRAND.md`
- Create: `docs/assets/signalbox-mark.svg`
- Create: `docs/assets/signalbox-operator-loop.svg`
- Create: `docs/assets/signalbox-shared-core.svg`
- Create: `docs/assets/signalbox-tui.png`
- Create: `docs/assets/signalbox-demo.cast`
- Create: `docs/assets/signalbox-demo.gif`
- Modify: `README.md`
- Modify: `SECURITY.md`
- Modify: `examples/agent-workflows/*.md`
- Modify: `pyproject.toml`

**Steps:**

1. Rewrite README around the implemented operator journey: Discover → Observe → Retain → Find → Draft → Approve → Post → Confirm.
2. Before public brand use, complete a documented name/domain/package/trademark collision search and present the evidence plus residual risk for explicit user approval of “Technocore Signalbox.” If approval is absent, stop publication and retain provisional internal naming.
3. Put real deterministic TUI imagery above the fold; no mockup may be presented as execution proof.
4. Separate operator raw-data path from detached content-free check.
5. State exact row/time/byte/request/message limits and honest gap/uncertainty semantics.
6. Add CLI/JSON recipes for Hermes, OpenClaw, Codex, Claude Code, cron, dashboards, and alerting without requiring MCP.
7. Generate all demo data synthetically; include no live senders, room text, DIDs, signatures, secrets, or private paths.
8. Parse/render/visually inspect every SVG; verify PNG/GIF dimensions, crop, contrast, labels, and alt text.
9. Keep “independent project” language; imply no FLOP Labs or Arthur Hayes review/endorsement.

**Verify:**

```sh
npx --yes markdownlint-cli2 README.md SECURITY.md docs/BRAND.md examples/agent-workflows/*.md
uv run python -m compileall -q src tests examples
```

## Task 14: Full release-candidate verification

**Objective:** Prove one exact artifact set is worthy of publication.

**Required gates:**

1. Materialize the candidate in a new temporary source tree: export tracked `HEAD` bytes without `.git`, then overlay only the exact intended-file manifest from the working tree using descriptor-safe copies; reject missing, extra, duplicate, symlink, special, hard-linked, or path-traversal entries. Run normal and `python -O` full suites from that isolated tree. Its deterministic path/mode/content tree hash must reproduce on a second independent materialization. This is a clean candidate source tree, not a claim that the developer worktree is clean and not a commit.
2. TUI headless journey and deterministic screenshot/demo generation pass.
3. Independent specification review: zero critical, zero important.
4. Independent security review: zero critical, zero important.
5. Independent code-quality/integration review: zero critical, zero important.
6. `compileall`, Markdown lint, SVG parse/render, link/path checks, and `git diff --check` pass.
7. Build wheel and sdist; enumerate exact allowlists and hashes.
8. Reject `.github/` unless separately reviewed, `docs/plans`, state/cache databases, journals, drafts, pending files, event logs, keys, nonces, receipts, screenshots with private data, and any credential pattern from artifacts.
9. Build into clean temporary output directories, record exact wheel/sdist paths and hashes, install that exact wheel into a fresh venv, and smoke-test both executables, both check spellings, contracts, fixture-backed rooms/read/follow, cache/search/status, TUI help/headless boot, draft/plan, and mocked verified submit/reconcile. Test events only if Task 12 passed its real-consumer gate.
10. Upgrade-test from the current Sentinel wheel/state: existing monitor/identity/nonce/receipt files require no migration, and unknown Signalbox cache versions fail closed because v1 ships no speculative in-place database migration.
11. Inspect dependency licenses and vulnerability advisories; document residual findings rather than hiding them.
12. Scan intended Git history and release diff for secrets without printing matches.
13. Review the pre-existing `.github/` tree independently without modifying it. If an approved workflow is needed, include its exact proposed bytes and required least-privilege GitHub scope in the candidate-authorization packet; public CI cannot run until the candidate commit is explicitly authorized and pushed in Task 15.
14. Before enabling `message send` against the live origin, present the exact controlled room, public synthetic text and digest, case-sensitive DID, authorization-file bytes, request count, raw OpenAPI-operation fingerprint procedure, and no-retry procedure for separate approval. Invoke only `tools/controlled_post_exercise.py` with that exact descriptor-read authorization file. Perform at most one authorized POST through the shared pending/journal/readback service, verify exact public readback, and record only the content-free capability manifest—not live message content or identity—in the candidate. Without that approval/evidence, the release must keep the packaged manifest disabled, all live submits quarantined, and describe Participate as fixture-verified but disabled.
15. Verify `publish-profile --submit` separately against the note endpoint before ever re-enabling it; room-message evidence cannot authorize or validate profile writes.
16. Produce a pre-publication candidate packet containing intended file manifest, deterministic diff/tree hash, proposed commit message and branch, test count, artifact hashes, wheel/sdist inventories, review verdicts, locally validated CI workflow bytes if authorized, final screenshots/demo, live-write capability status, limitations, and exact proposed public targets. It deliberately has no commit SHA or CI URL yet.

## Task 15: Publish and verify GitHub

**Objective:** Publish only the reviewed release candidate and return a verified repository URL.

**Steps:**

1. Present the pre-publication candidate packet and exact remaining limitations; obtain explicit authorization for its exact reviewed files, commit message, public feature-branch push, and proposed CI workflow. The user's conditional instruction is not treated as authorization for a changed packet or unrelated dirty-tree paths.
2. Stage only the authorized reviewed files; exclude unrelated/unreviewed work and all private runtime artifacts. Verify the staged tree hash equals the authorized candidate packet.
3. Commit that exact candidate, record the SHA, push only the authorized inspected branch, and verify the remote SHA equals local SHA. This push is the publication event; if it fails or the staged hash changes, stop without substituting another scope.
4. Run/observe least-privilege pinned GitHub CI on that exact SHA. Require every required check to complete successfully; a failure returns the work to Task 14 and requires a new candidate packet before another public push.
5. Read back the public tree, README, package metadata, license, security policy, representative source/tests, CI workflow, and every visual asset; byte-compare downloadable assets and verify media types/rendering.
6. Produce the final release packet containing exact SHA, remote branch/PR URL, CI URL and conclusions, diff scope, test count, artifact hashes/inventories, review verdicts, final media, live-write capability status, limitations, and intentionally excluded material.
7. Merge PR, rename repository, create a tag/release, publish to PyPI, update Awesome Technocore, or post on X only after separately presenting and obtaining authorization for each action in the final release packet.
8. Return the verified public repository URL and an honest list of anything intentionally not published.

## Compatibility and rollback

- Existing `technocore-sentinel`, `monitor`, `scan`, `contract`, `agent-check`, identity files, monitor state, nonce state, and receipt state require no migration. Legacy live submit behavior is intentionally quarantined because preserving a known ambiguous-write path is not safe compatibility.
- `technocore-agent`, strict protocol models, cache, drafts, pending operations, events, and TUI are additive and independently versioned.
- Removing the new console script restores the previous entry point without changing distribution/import identity.
- Deleting a cache or draft does not alter monitor cursor or identity state. A pending operation must not be deleted until reconciled because its outcome may already be public.
- Unknown/newer database schemas and changed settings fail closed with backup/export guidance; v1 has no predecessor cache and performs no in-place migration.
- No rollback claim is made for a verified or uncertain public write.

## Independent-review acceptance checklist

- [ ] Every endpoint and field is grounded in the protocol baseline.
- [ ] Document disagreement is handled by capability checks, not guessed version precedence.
- [ ] Existing check/monitor compatibility is mechanically frozen.
- [ ] Observe is useful before Participate begins.
- [ ] Cache bounds include rows, age, bytes, gaps, transactions, and auxiliary-file overhead.
- [ ] TUI and CLI share services and tests.
- [ ] Approval binds to one descriptor-read canonical artifact.
- [ ] Ambiguous write outcomes never auto-retry.
- [ ] Lock ordering, path aliasing, crash recovery, and partial commit outcomes are explicit.
- [ ] Events are closed, bounded, message-body-free, and command-specific on failure.
- [ ] Package, CI, media, documentation, and public readback gates are exact.
- [ ] No critical or important issue remains.

## Sources

[1] https://technocore.chat/openapi.json — Technocore Chat OpenAPI
[2] https://technocore.chat/.well-known/agent.json — Technocore Chat agent manifest
[3] https://technocore.chat/config — Technocore Chat deployment configuration
[4] https://technocore.chat/r/events?format=json&limit=2 — Read-only events-room sample
[5] https://technocore.chat/r/events?format=json&limit=2&since=999999999999999999&wait=0 — Read-only empty incremental sample
[6] https://pypi.org/pypi/textual/json — Textual package metadata
