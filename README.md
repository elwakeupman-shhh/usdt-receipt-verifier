![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Python 3.6+](https://img.shields.io/badge/python-3.6%2B-blue.svg)
# usdt-receipt-verifier — read-only USDT-TRC20 payment verifier (Tor)

**Verify USDT payments without trusting screenshots.** A read-only command-line tool that
checks a claimed USDT (TRC-20) transfer against public on-chain data and emits a
tamper-evident receipt (SHA-384 hash chain) — so freelancers and small merchants can
independently prove a crypto payment actually arrived, with the right amount and enough
confirmations. No private keys. No trust in the counterparty. Nothing is ever sent.

## Why it is useful
Crypto payments are often "proven" with a screenshot from the sender.
This tool lets the receiver verify the transfer themselves, from public
chain data, and produce a signed, tamper-evident receipt they can keep
or share — no trust in the counterparty required.

## What it does
- Reads public TRC20 transfers for an address **through a local Tor SOCKS
  proxy** (127.0.0.1:9050) — so a third party only ever sees the Tor exit
  node, never your real IP.
- Confirms incoming transfers matching an expected amount + a client tag
  (reconcile many clients by tag).
- Emits a local tamper-evident receipt (SHA-384 hash chain); touches NO
  private key, sends NOTHING.

## Safety / anonymity
- Read-only: never sends a transaction, never holds a key.
- The address is a CLI argument — nothing hard-coded.
- Refuses to run unless Tor is up; **never falls back to a bare ISP
  connection** (no real-IP leak).

## Requirements
- Python 3.6+ (standard library only — no `pip install` needed)
- `curl` on PATH
- A local Tor SOCKS proxy on 127.0.0.1:9050 (only for the live path)

## Run

Self-test (zero network, zero real IP — proves the logic offline):

    python usdt_receipt_verifier.py --selftest

Verify a payment (live, requires Tor + a public TRC20 API):

    python usdt_receipt_verifier.py \
        --address YOUR_TRC20_ADDRESS \
        --expected-usd 1500.0 \
        --client-tag clientA \
        --min-confirmations 1 \
        --out receipt.json

### Example self-test output
    SELF-TEST ALL PASS (logic/mock, 0 network, 0 real IP)

## How to verify it yourself (self-test)
The `--selftest` mode feeds the verifier a mock transfer set and asserts:
a matching amount is detected, a wrong amount is rejected, and a
below-threshold confirmation count is rejected. It makes **no network
calls and never touches a real IP**, so you can re-run it anywhere to
confirm the tool's logic is intact.

## License
MIT — see `LICENSE`.

## Contact
EL. (Inquiries: reach out via the platform you found this repository on.
No personal email is published here on purpose.)


## For your first client

This toolkit is built to be dropped into a real engagement and trusted by a paying client. It runs fully offline, leaves a verifiable evidence chain (self-test PASS), and ships with a signed integrity check (D2) so the client can re-verify the artifact they received was not tampered. Pricing/escrow via USDT-TRC20 is supported out of the box.

Companion tool: [offchain-integrity-verifier](https://github.com/elwakeupman-shhh/offchain-integrity-verifier) — same trust story, applied to reports and logs instead of payments.

## Related tools

- [zero-match-guard](https://github.com/elwakeupman-shhh/zero-match-guard) — Fail checks that examined nothing.
- [offchain-integrity-verifier](https://github.com/elwakeupman-shhh/offchain-integrity-verifier) — Prove a report has not been altered.

## Available for hire

I build this kind of tooling to order: ops automation, integrity and verification
tools, and content pipelines. Single file, zero third-party dependencies, meaningful
exit codes, and a test you can run yourself.

[zerodeptools on Fiverr](https://www.fiverr.com/zerodeptools)
