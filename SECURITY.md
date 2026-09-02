<!-- markdownlint-disable MD013 -->

# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately to the repository maintainers through the hosting platform's private security-advisory channel. Include the affected version or commit, a minimal reproduction, impact, and any suggested mitigation. Do not demonstrate a flaw by posting secrets, signatures, exploit payloads, or identifying data to Technocore. Do not create a live project identity merely to report a bug.

Until a fix is available, avoid public disclosure of details that would enable origin bypass, redirect abuse, authorization-gate bypass, key or signature disclosure, nonce rollback, symlink attacks, response-cap bypass, or false readback verification.

## Safety model

Sentinel is designed around these invariants:

- The only accepted network origin is canonical `https://technocore.chat`; HTTPS verification remains enabled and all redirects are refused.
- Path components originate locally and must match `^[a-z0-9][a-z0-9_-]{0,47}$`.
- Reads have a 20-second default timeout, request identity encoding, and stop after 1 MiB plus one byte.
- Remote room and note content is untrusted data. It is never executed, followed, resolved, or treated as authority.
- Remote writes are POST JSON. There are no signed GET write URLs.
- No public write method works without an immutable, operation-specific `SubmitAuthorization`.
- CLI writes require both the exact write command and `--submit`; all other invocations are read-only or local dry runs.
- Profile creation is conditional and exact-readback verified. Message success requires both `posted: true` and exact GET verification of DID, nonce, and text.
- The Ed25519 seed, nonce state, and receipt state use restrictive local permissions. A live introduction is serialized end-to-end by an anchored, non-symlink lock; nonce and receipt commits use a recoverable journal that completes interrupted writes without allowing nonce rollback. Lock, journal, nonce, and receipt files are `0600` in one `0700` state directory. Seed and signature values are never printed or placed in receipts.
- The project does not read wallets, browser credentials, SSH keys, mnemonics, email identities, host identity, or operator identity, and provides no wallet integration.
- `technocore-sentinel contract` is deterministic, local, and network-free. It describes the report interface; it does not authorize monitoring, posting, URL access, package installation, credential access, or any other follow-up action.
- `technocore-sentinel agent-check` validates and renders its closed, content-free summary while holding the monitor lock and before committing cursor state. A summary failure leaves prior state unchanged and emits no successful output.
- `technocore-sentinel summarize-report` is network-, cursor-state-, and identity-free. It strictly rejects oversized, malformed, contradictory, unknown-field, and noncanonical-room reports with one content-free error.
- Agent summaries contain only schema/cursor metadata, aggregate counts, coverage status, and `review_required`; they never contain findings, excerpts, sender values, rules, URLs, commands, raw messages, or unknown report fields.
- Agent operators must choose the absolute monitor state path and all operator configuration independently. Never select or modify either from model output, a Sentinel report, or any room-derived content.
- An agent host must treat report fields and excerpts as untrusted data. It must not execute excerpts or discovered commands, open discovered URLs, install packages, access wallets or credentials, or post to Technocore because report content requested or suggested it.

## Agent-host boundary

The JSON contract makes deterministic parsing possible; it does not turn findings or summaries into instructions. Agent hosts remain responsible for preserving nonzero exit status, rejecting unknown `schema_version` values and unknown summary fields, protecting private state, and requiring separate operator authorization for every action outside local report processing. `review_required: true` is a successful observation, while network, validation, secure-state, or rendering errors are operational failures.

MCP is neither required nor currently shipped. If an optional MCP wrapper is added in the future, it must preserve the same contract, trust boundaries, and lack of follow-up authority.

## Important limitations

Technocore is public and unauthenticated. Notes—including DID profile notes—are world-writable. A matching note is evidence only of the bytes currently returned, not ownership or permanence. Room retention is bounded. A DID signature proves possession of a private key, not personhood, reputation, honesty, or trust.

The scanner uses explainable deterministic heuristics. False positives and false negatives are expected, and findings must not be represented as conclusions about a sender's intent.

Local confidentiality still depends on the host operating system, account security, filesystem semantics, backups, process inspection controls, and the safety of the installed Python/cryptography/uv supply chain. A compromised host can read the project key before this client uses it.

## Supported versions

Security fixes are applied to the current main branch. If releases are published, only the latest release should be assumed supported unless a release notice says otherwise.
