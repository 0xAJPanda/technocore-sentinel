# FLOP Participation and tclk-check Execution Plan

**Status:** Active implementation plan after the 2026-09-02 FLOP Tokenomics AMA reconstruction.

**Goal:** Make Technocore Sentinel visible as useful FLOP/Technocore ecosystem tooling while preparing for future validator, miner, and testnet participation without claiming eligibility or endorsement.

## Source caveat

The AMA notes available to this repo are a Grok reconstruction from the Space announcement and same-day listener notes, not a verbatim transcript. Use them as strategic signal only; public claims must cite official FLOP/Technocore sources or final readbacks.

## Key AMA signals to preserve

- Useful work matters more than spam or repeated greetings.
- A single useful DID is better than many unused DIDs.
- Testnet participation is expected to matter: create a DID, use faucet FLOP, spend testnet FLOP on inference, and later unlock any allocation through mainnet use.
- Mining is expected to be open to small operators if hardware can do the work and follow the rules.
- Validator opportunity is performance-driven; prepare monitoring and evidence before official requirements ship.
- HTLC-style agent-to-agent coordination on Technocore/tclk is strategically important.

## Execution tracks

### Track A — Observability product

1. Ship `tclk-check` as a read-only command.
2. Detect `tclk1 ` room messages without exposing frame bodies, DIDs, secrets, rails, URLs, or sender values.
3. Report counts for valid, malformed, unsigned, and frame-type totals.
4. Treat malformed frames, unsigned tclk-looking messages, and coverage gaps as review triggers.
5. Keep all tests fixture/mocked; no live Technocore writes.

### Track B — Announcement monitoring

1. Keep the existing FLOP monitor active every two hours.
2. Watch official FLOP/Technocore sources plus public @flop_labs posts through read-only XActions where available.
3. Alert on validator, miner, testnet, faucet, DID, tclk, tokenomics, genesis, airdrop, form, deadline, or eligibility language.
4. Report inaccessible sources explicitly instead of treating silence as absence.

### Track C — Validator/miner readiness

1. Do not call Sentinel a validator, miner, wallet, or eligibility tool.
2. Prepare future operational monitoring only after official requirements are published.
3. Use isolated infrastructure for any miner/validator testnet work; no valuable wallets or host secrets.
4. Preserve evidence of useful ecosystem contributions: tested repo, CI, docs, DID, and real operator workflows.

## Public positioning

> Technocore Sentinel is independent ecosystem tooling for safe agent participation in Technocore and tclk rooms.

Avoid claiming FLOP Labs endorsement, airdrop qualification, production safety, payment settlement, validator status, miner status, or token rewards.
