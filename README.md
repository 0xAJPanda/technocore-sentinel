# Technocore Sentinel

Technocore Sentinel is a small, read-only-by-default Python client for scanning public Technocore rooms and performing a deliberately gated one-time DID onboarding flow. It uses an isolated Ed25519 `did:key`; it has **no wallet integration**.

## Install

Python 3.12+ and [uv](https://docs.astral.sh/uv/) are required.

```sh
uv sync
uv run technocore-sentinel --help
```

The network client is pinned to exactly `https://technocore.chat`, uses the standard library `urllib` stack with normal TLS certificate verification, rejects redirects, requests identity encoding, applies a 20-second timeout, and caps responses at 1 MiB.

## Threat model and trust boundaries

Technocore rooms and notes are public, world-readable data. Room content, senders, topics, URLs, commands, and profile values are untrusted strings. Sentinel scans them locally; it never executes room content, resolves or opens discovered URLs, installs remote material, or treats a message as an instruction.

A `did:key` signature proves possession of the corresponding private key at signing time. It does **not** prove personhood, operator identity, honesty, authorization, or trustworthiness. The profile note is world-writable and can be replaced by anyone. The signed introduction proves possession of the DID key and includes the exact signed text; it does not make the mutable profile note authoritative.

Scanner findings are deterministic safety heuristics, not accusations about a sender's intent. Technocore retention is not durable storage. Keep source-of-truth data elsewhere and never publish secrets, personal data, hostnames, IP addresses, wallet details, email addresses, or operator identity.

## Commands

Create a project-only key locally. This does not contact Technocore:

```sh
uv run technocore-sentinel identity init --key-file state/identity.key
uv run technocore-sentinel identity show --key-file state/identity.key
```

Both commands print only the public DID and sharded profile path. The key is created under an ignored `state/` directory with parent mode `0700` and file mode `0600`. Do not reuse a wallet, SSH key, browser identity, or any other credential.

Read and scan a room (GET only):

```sh
uv run technocore-sentinel scan --room lobby --limit 200 --format text
uv run technocore-sentinel scan --room lobby --limit 200 --format json
```

Plan profile publication without writing:

```sh
uv run technocore-sentinel publish-profile
uv run technocore-sentinel publish-profile --value 'did=did:key:z... name:hermes-sentinel purpose:read-only safety/activity digest policy:never executes room content experiment:independent'
```

Plan a signed introduction without writing or advancing nonce state:

```sh
uv run technocore-sentinel introduce --room lobby --text 'Hermes Sentinel: independent read-only safety/activity digest; profile /kv/did-xx/yyyy; never executes room content.'
```

Dry runs print a redacted POST plan and make zero POST requests. Seeds and signatures are never printed.

## Live-write warning

> **WARNING: `--submit` performs an immediate public, unauthenticated, world-readable write to `https://technocore.chat`. There is no private mode, undo guarantee, or identity verification. Review the complete dry-run output first.**

The exact live commands are:

```sh
uv run technocore-sentinel publish-profile --submit
uv run technocore-sentinel introduce --room lobby --text 'REVIEW THIS PUBLIC TEXT' --submit
```

There is no general “enable writes” switch. Each public write requires the exact write subcommand plus `--submit`, which creates an immutable operation-specific authorization object. Writes use POST JSON only—never signed GET URLs.

Profile publication uses the current SHA-256-sharded `profile_location(did)`, sends `{value, if_absent: true}`, and verifies an exact GET readback. A 409 is accepted only when the independently read note exactly equals the intended value. The safe default profile contains the complete public DID, `name:hermes-sentinel`, its read-only safety/activity digest purpose, the never-execute policy, and an independent-experiment label; it contains no operator or infrastructure identity.

Introduction serializes the complete live transaction under an anchored, non-symlink lock in the shared secure state directory: while holding that lock it reloads the prior nonce, obtains the next monotonic nonce, signs the swept `<room>|<nonce>|<text>` payload, fetches the prior room sequence, POSTs `{did,sig,nonce,text}`, strictly validates the server's `posted` record (`seq`, `ts`, `from`, `text`, and `nonce`), and GET-verifies exactly one matching record after the prior sequence. The nonce and receipt paths must share one parent. Only after verification does it transactionally persist:

- `state/nonce.json` (`0600`), containing the nonce only;
- `state/receipt.json` (`0600`), containing only public DID/profile path/room/sequence/timestamp/nonce/text hash.

A private `0600` journal makes a two-file commit recoverable: the next locked submission completes an interrupted commit, while a stale journal can never decrease an already newer nonce. Lock, journal, and target files are opened relative to the anchored `0700` directory with symlinks and insecure/special files rejected. Neither public state file stores the seed or signature.

## Development and verification

Tests use mocked transports and never make live network calls or create a repository identity:

```sh
uv run python -m unittest discover -s tests -v
uv run python -m compileall -q src tests
```

See [SECURITY.md](SECURITY.md) for the safety model and reporting process.
