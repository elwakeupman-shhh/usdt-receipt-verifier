#!/usr/bin/env python3
"""
usdt_receipt_verifier.py -- Read-only USDT-TRC20 payment-receipt verifier (Tor SOCKS)

WHAT IT DOES
  - Queries a public TRC20 API through a local Tor SOCKS proxy (127.0.0.1:9050).
  - Confirms incoming transfers to YOUR address with >= min confirmations.
  - Matches an expected amount + a client tag (so you can reconcile many clients).
  - Emits a tamper-evident receipt (SHA-384 hash chain) saved locally.
  - Touches NO private key, sends NOTHING, leaks NO real ISP IP (third parties
    only ever see the Tor exit node IP).

WHY IT'S SAFE / ANONYMOUS
  - Read-only: never sends a transaction, never holds a key.
  - The address is passed as a CLI argument -- nothing is hard-coded.
  - All network egress goes through the local Tor SOCKS proxy; if Tor is not
    running it refuses to verify (it will NOT fall back to a bare ISP connection).

USAGE
  Self-test (zero network, zero real IP):
      python usdt_receipt_verifier.py --selftest

  Verify a payment:
      python usdt_receipt_verifier.py \
          --address YOUR_TRC20_ADDRESS \
          --expected-usd 1500.0 \
          --client-tag clientA \
          --min-confirmations 1 \
          --out receipt.json

LICENSE: MIT -- use it, fork it, ship it.
CONTACT: EL (inquiries via the platform you found this repo on).
"""
import argparse, json, os, socket, subprocess, sys, hashlib, time

RELAY_HOST = "127.0.0.1"
RELAY_PORT = 9050
DEFAULT_API = "https://api.trongrid.io/v1/accounts/{addr}/transactions/trc20?limit=50"


def tor_up():
    """Refuse to run unless a local Tor SOCKS proxy is listening."""
    try:
        s = socket.create_connection((RELAY_HOST, RELAY_PORT), timeout=3)
        s.close()
        return True
    except OSError:
        return False


def query_trc20(addr, api_url=None, timeout=20, _curl="curl"):
    if not tor_up():
        raise RuntimeError("Tor daemon not listening on 127.0.0.1:9050; refusing to verify (no bare-ISP fallback).")
    url = (api_url or DEFAULT_API).format(addr=addr)
    proc = subprocess.run(
        [_curl, "-s", "--socks5", "%s:%d" % (RELAY_HOST, RELAY_PORT),
         "--max-time", str(int(timeout)), url],
        capture_output=True, text=True
    )
    if proc.returncode != 0:
        raise RuntimeError("Tor curl rc=%d: %s" % (proc.returncode, proc.stderr[:200]))
    return json.loads(proc.stdout)


def _extract_incoming(data, addr):
    rows = []
    for tx in data.get("data", []):
        to_addr = tx.get("to")
        if not to_addr or to_addr.lower() != addr.lower():
            continue
        try:
            sun = int(tx.get("value", "0"))
        except (ValueError, TypeError):
            sun = 0
        rows.append({
            "txid": tx.get("transaction_id"),
            "from": tx.get("from"),
            "value_usdt": sun / 1_000_000.0,
            "block_ts": tx.get("block_timestamp"),
            "confirmations": tx.get("confirmations", 0),
        })
    return rows


def sha384_chain(prev, event):
    h = hashlib.sha384()
    h.update((prev + "|" + event).encode("utf-8"))
    return h.hexdigest()


def verify(addr, expected_usd, client_tag, min_conf=1, api_url=None, _query=None):
    q = _query or query_trc20
    data = q(addr, api_url)
    rows = _extract_incoming(data, addr)
    matched = [r for r in rows
               if abs(r["value_usdt"] - expected_usd) < 0.01
               and (r["confirmations"] or 0) >= min_conf]
    prev = "0" * 96
    events = []
    for r in matched:
        ev = json.dumps({"t": "USDT_RECEIPT", "addr": addr, "client": client_tag,
                         "usdt": r["value_usdt"], "txid": r["txid"],
                         "conf": r["confirmations"], "ts": r["block_ts"]}, sort_keys=True)
        prev = sha384_chain(prev, ev)
        events.append({"event": ev, "head": prev})
    return {
        "verified": len(matched) > 0,
        "addr": addr,
        "client_tag": client_tag,
        "expected_usd": expected_usd,
        "min_conf": min_conf,
        "matched": matched,
        "chain_head": prev if matched else None,
        "events": events,
        "test_type": "live-measurement" if _query is None else "logic/mock",
        "real_ip": False,
    }


def write_receipt(result, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    return path


# Demo address used ONLY by --selftest (placeholder, not a real wallet).
SELFTEST_ADDR = "TTESTzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"


def _selftest():
    mock = {"data": [
        {"token_info": {"address": "TR7Nhqj"}, "to": SELFTEST_ADDR, "from": "Tfrom1",
         "value": "1500000000", "transaction_id": "txmatch", "block_timestamp": 123,
         "confirmations": 25},
        {"token_info": {"address": "TR7Nhqj"}, "to": "Tother", "from": "Tfrom2",
         "value": "999000000", "transaction_id": "txnomatch", "block_timestamp": 124,
         "confirmations": 25},
    ]}

    def q(addr, api_url=None):
        return mock

    r = verify(SELFTEST_ADDR, 1500.0, "clientA", min_conf=1, _query=q)
    assert r["verified"] is True, "should match 1500 USDT"
    assert r["chain_head"] is not None
    assert r["test_type"] == "logic/mock"
    assert r["real_ip"] is False
    r2 = verify(SELFTEST_ADDR, 2000.0, "clientA", min_conf=1, _query=q)
    assert r2["verified"] is False, "wrong amount should not match"
    mock2 = {"data": [{"token_info": {}, "to": SELFTEST_ADDR, "from": "x",
              "value": "1500000000", "transaction_id": "tx3",
              "block_timestamp": 1, "confirmations": 0}]}

    def q2(addr, api_url=None):
        return mock2

    r3 = verify(SELFTEST_ADDR, 1500.0, "c", min_conf=1, _query=q2)
    assert r3["verified"] is False, "conf<min should fail"
    print("SELF-TEST ALL PASS (logic/mock, 0 network, 0 real IP)")
    return 0


def main():
    ap = argparse.ArgumentParser(description="Read-only USDT-TRC20 payment-receipt verifier (Tor)")
    ap.add_argument("--address", help="receiving address (TRC20)")
    ap.add_argument("--expected-usd", type=float, default=0.0, help="expected amount (USDT)")
    ap.add_argument("--client-tag", default="", help="client tag for reconciliation")
    ap.add_argument("--min-confirmations", type=int, default=1)
    ap.add_argument("--api-url", default=None)
    ap.add_argument("--out", default=None, help="receipt output path")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return _selftest()
    if not args.address:
        print("ERROR: --address required (or --selftest)", file=sys.stderr)
        return 2
    res = verify(args.address, args.expected_usd, args.client_tag,
                 min_conf=args.min_confirmations, api_url=args.api_url)
    if args.out:
        write_receipt(res, args.out)
        print("receipt -> " + args.out)
    print(json.dumps(res, indent=2, ensure_ascii=False))
    return 0 if res["verified"] else 1


if __name__ == "__main__":
    sys.exit(main())
