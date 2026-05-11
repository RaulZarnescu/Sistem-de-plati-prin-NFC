#!/usr/bin/env python3
"""
============================================================
e2e_test.py — Test End-to-End: NFC Payment PoC
============================================================

Rulează din interiorul rețelei Docker:
  docker cp tests/e2e_test.py nfc-gateway:/tmp/e2e_test.py
  docker exec nfc-gateway python /tmp/e2e_test.py

Presupuneri:
  - Toate containerele rulează (docker compose up -d)
  - Scriptul se execută DIN gateway container (are httpx + env vars)
  - Nu trece prin NGINX → CN check e skip-at automat (X-SSL-Client-DN absent)

Scenarii acoperite:
  TC-01  Happy path Visa (Bank A)          → 200 APPROVED
  TC-02  Happy path Mastercard (Bank B)    → 200 APPROVED
  TC-03  Step-Up (risk_level=55)           → 401 CHALLENGE_REQUIRED
  TC-04  MAC tampered (sumă alterată)      → 400 INVALID_CRYPTOGRAM
  TC-05  ATC Replay Attack                 → 400 INVALID_CRYPTOGRAM
  TC-06  DPAN necunoscut                   → 400 INVALID_TOKEN
  TC-07  Idempotență (retrimite TC-02)     → 200 APPROVED (din cache)
  TC-08  Lipsă X-Idempotency-Key          → 400 MISSING_IDEMPOTENCY_KEY
  TC-09  Lipsă X-Terminal-Id              → 400 MISSING_TERMINAL_ID
============================================================
"""

import hmac as hmac_lib
import hashlib
import os
import uuid
import time
from datetime import datetime, timezone

import httpx

# ============================================================
# CONFIGURARE
# ============================================================

# Din interiorul gateway container: serviciul ascultă pe localhost
GATEWAY_URL = os.getenv("TEST_GATEWAY_URL", "http://localhost:8001")

# Cheile HMAC — disponibile în container via env_file: .env
_hex_a = os.getenv("ISSUING_BANK_HMAC_MASTER_KEY", "")
HMAC_KEY_A = bytes.fromhex(_hex_a) if _hex_a else b""

_hex_b = os.getenv("ISSUING_BANK_B_HMAC_MASTER_KEY", "")
HMAC_KEY_B = bytes.fromhex(_hex_b) if _hex_b else b""

# Terminal ID folosit în teste
TERMINAL_ID = "POS-E2E-TEST-001"

# Pauză între teste (evită rate limit de 2 req/sec per terminal)
INTER_TEST_SLEEP = 0.6  # secunde


# ============================================================
# UTILITARE
# ============================================================

def compute_mac(key: bytes, amount_cents: int, currency: str,
                pos_nonce: str, terminal_timestamp: str, atc: int) -> str:
    """Replicăm exact formula din shared/crypto_utils.py."""
    mac_input = f"{amount_cents}|{currency}|{pos_nonce}|{terminal_timestamp}|{atc}"
    return hmac_lib.new(key, mac_input.encode("utf-8"), hashlib.sha256).hexdigest()


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def unique_key() -> str:
    return f"E2E-{uuid.uuid4().hex[:12].upper()}"


def unique_nonce() -> str:
    return uuid.uuid4().hex[:8].upper()


def get_nested(data: dict, dot_path: str):
    """Extrage o valoare dintr-un dict folosind calea cu puncte (ex: 'detail.error_code')."""
    node = data
    for part in dot_path.split("."):
        if not isinstance(node, dict) or part not in node:
            raise KeyError(f"Calea '{dot_path}' nu există în răspuns: {data}")
        node = node[part]
    return node


# ============================================================
# TEST RUNNER
# ============================================================

results: list[tuple[str, bool, str]] = []  # (name, passed, detail)


def run_test(
    name: str,
    method: str,
    url: str,
    headers: dict,
    body: dict | None,
    expect_status: int,
    expect_fields: dict | None = None,  # { "dot.path": expected_value }
) -> httpx.Response | None:
    """Execută un singur test și înregistrează rezultatul."""
    try:
        with httpx.Client(timeout=10.0) as client:
            if method == "get":
                resp = client.get(url, headers=headers)
            else:
                resp = getattr(client, method)(url, headers=headers, json=body)

        status_ok = resp.status_code == expect_status
        field_errors = []

        if expect_fields:
            try:
                data = resp.json()
                for path, expected in expect_fields.items():
                    try:
                        actual = get_nested(data, path)
                        if actual != expected:
                            field_errors.append(
                                f"{path}={actual!r} (așteptat {expected!r})"
                            )
                    except KeyError as e:
                        field_errors.append(str(e))
            except Exception as e:
                field_errors.append(f"JSON parse error: {e} | body: {resp.text[:200]}")

        passed = status_ok and not field_errors
        icon = "✅" if passed else "❌"

        detail_parts = []
        if not status_ok:
            detail_parts.append(f"HTTP {resp.status_code} ≠ {expect_status}")
        detail_parts.extend(field_errors)
        detail = " | ".join(detail_parts)

        print(f"  {icon} {name}" + (f"  ← {detail}" if detail else ""))
        results.append((name, passed, detail))
        return resp

    except Exception as exc:
        print(f"  ❌ {name}  ← EXCEPȚIE: {exc}")
        results.append((name, False, f"EXCEPȚIE: {exc}"))
        return None


# ============================================================
# PREFLIGHT — verifică că HMAC keys sunt setate
# ============================================================

def preflight():
    print("\n🔍 Preflight checks...")
    ok = True
    if not HMAC_KEY_A:
        print("  ❌ ISSUING_BANK_HMAC_MASTER_KEY nu este setată în mediu!")
        ok = False
    else:
        print(f"  ✅ HMAC Key A prezentă ({len(HMAC_KEY_A)} bytes)")

    if not HMAC_KEY_B:
        print("  ❌ ISSUING_BANK_B_HMAC_MASTER_KEY nu este setată în mediu!")
        ok = False
    else:
        print(f"  ✅ HMAC Key B prezentă ({len(HMAC_KEY_B)} bytes)")

    if not ok:
        print("\n  STOP: Cheile HMAC lipsesc. Verifică .env și env_file din docker-compose.yml")
        exit(1)


# ============================================================
# SUITE DE TESTE
# ============================================================

def main():
    preflight()

    # Păstrăm datele din unele teste pentru a le refolosi în altele
    tc01_atc = 100         # folosit în TC-05 (replay)
    tc02_idemp_key = None  # folosit în TC-07 (idempotency)
    tc02_body = None       # folosit în TC-07

    # ----------------------------------------------------------
    print("\n📡 [0/9] Conectivitate Gateway")
    run_test(
        "TC-00  Health Check",
        "get", f"{GATEWAY_URL}/health",
        headers={}, body=None,
        expect_status=200,
        expect_fields={"status": "healthy"},
    )
    time.sleep(INTER_TEST_SLEEP)

    # ----------------------------------------------------------
    print("\n💳 [1/9] Happy path — Visa (Bank A, prefix 4)")
    ts1, nonce1, atc1 = now_iso(), unique_nonce(), tc01_atc
    mac1 = compute_mac(HMAC_KEY_A, 15000, "RON", nonce1, ts1, atc1)
    run_test(
        "TC-01  Visa APPROVED",
        "post", f"{GATEWAY_URL}/api/v1/payments/authorize",
        headers={"X-Idempotency-Key": unique_key(), "X-Terminal-Id": TERMINAL_ID},
        body={
            "dpan": "4000000000000001",
            "transaction": {"amount": 15000, "currency": "RON",
                            "pos_nonce": nonce1, "terminal_timestamp": ts1},
            "cryptogram": {"mac": mac1, "atc": atc1},
        },
        expect_status=200,
        expect_fields={"status": "APPROVED"},
    )
    time.sleep(INTER_TEST_SLEEP)

    # ----------------------------------------------------------
    print("\n💳 [2/9] Happy path — Mastercard (Bank B, prefix 5)")
    ts2, nonce2, atc2 = now_iso(), unique_nonce(), 200
    mac2 = compute_mac(HMAC_KEY_B, 5000, "RON", nonce2, ts2, atc2)
    tc02_idemp_key = unique_key()
    tc02_body = {
        "dpan": "5000000000000002",
        "transaction": {"amount": 5000, "currency": "RON",
                        "pos_nonce": nonce2, "terminal_timestamp": ts2},
        "cryptogram": {"mac": mac2, "atc": atc2},
    }
    run_test(
        "TC-02  Mastercard APPROVED",
        "post", f"{GATEWAY_URL}/api/v1/payments/authorize",
        headers={"X-Idempotency-Key": tc02_idemp_key, "X-Terminal-Id": TERMINAL_ID},
        body=tc02_body,
        expect_status=200,
        expect_fields={"status": "APPROVED"},
    )
    time.sleep(INTER_TEST_SLEEP)

    # ----------------------------------------------------------
    print("\n🔐 [3/9] Step-Up Authentication (risk_level=55, Bank A)")
    ts3, nonce3, atc3 = now_iso(), unique_nonce(), 300
    mac3 = compute_mac(HMAC_KEY_A, 10000, "RON", nonce3, ts3, atc3)
    run_test(
        "TC-03  CHALLENGE_REQUIRED (Step-Up)",
        "post", f"{GATEWAY_URL}/api/v1/payments/authorize",
        headers={"X-Idempotency-Key": unique_key(), "X-Terminal-Id": TERMINAL_ID},
        body={
            "dpan": "TEST-STEP-UP-001",
            "transaction": {"amount": 10000, "currency": "RON",
                            "pos_nonce": nonce3, "terminal_timestamp": ts3},
            "cryptogram": {"mac": mac3, "atc": atc3},
        },
        expect_status=401,
        expect_fields={"detail.error_code": "CHALLENGE_REQUIRED"},
    )
    time.sleep(INTER_TEST_SLEEP)

    # ----------------------------------------------------------
    print("\n🚨 [4/9] MAC tampered — sumă alterată de atacator")
    # Atacatorul calculează MAC pentru 1 ban (amount=1)
    # dar trimite suma reală de 999 RON (amount=99900) în body.
    # Banca recalculează MAC cu 99900 → nepotrivire → INVALID_CRYPTOGRAM
    ts4, nonce4, atc4 = now_iso(), unique_nonce(), 400
    mac4_tampered = compute_mac(HMAC_KEY_A, 1, "RON", nonce4, ts4, atc4)  # MAC pentru 1 ban
    run_test(
        "TC-04  INVALID_CRYPTOGRAM (MAC tampered)",
        "post", f"{GATEWAY_URL}/api/v1/payments/authorize",
        headers={"X-Idempotency-Key": unique_key(), "X-Terminal-Id": TERMINAL_ID},
        body={
            "dpan": "4000000000000001",
            "transaction": {"amount": 99900, "currency": "RON",  # suma reală: 999 RON
                            "pos_nonce": nonce4, "terminal_timestamp": ts4},
            "cryptogram": {"mac": mac4_tampered, "atc": atc4},
        },
        expect_status=400,
        expect_fields={"detail.error_code": "INVALID_CRYPTOGRAM"},
    )
    time.sleep(INTER_TEST_SLEEP)

    # ----------------------------------------------------------
    print("\n🔄 [5/9] ATC Replay Attack (același ATC ca TC-01)")
    # Banca a stocat last_atc=100 după TC-01.
    # Trimitem din nou atc=100 → received_atc (100) <= stored_atc (100) → REPLAY
    # TC-04 NU avansează ATC-ul (MAC eșua înainte de ATC check).
    ts5, nonce5 = now_iso(), unique_nonce()
    mac5_replay = compute_mac(HMAC_KEY_A, 15000, "RON", nonce5, ts5, tc01_atc)  # atc=100
    run_test(
        "TC-05  INVALID_CRYPTOGRAM (ATC replay)",
        "post", f"{GATEWAY_URL}/api/v1/payments/authorize",
        headers={"X-Idempotency-Key": unique_key(), "X-Terminal-Id": TERMINAL_ID},
        body={
            "dpan": "4000000000000001",
            "transaction": {"amount": 15000, "currency": "RON",
                            "pos_nonce": nonce5, "terminal_timestamp": ts5},
            "cryptogram": {"mac": mac5_replay, "atc": tc01_atc},  # ATC deja văzut
        },
        expect_status=400,
        expect_fields={"detail.error_code": "INVALID_CRYPTOGRAM"},
    )
    time.sleep(INTER_TEST_SLEEP)

    # ----------------------------------------------------------
    print("\n❓ [6/9] DPAN necunoscut în Token Vault")
    ts6, nonce6 = now_iso(), unique_nonce()
    mac6 = compute_mac(HMAC_KEY_A, 5000, "RON", nonce6, ts6, 500)
    run_test(
        "TC-06  INVALID_TOKEN (DPAN necunoscut)",
        "post", f"{GATEWAY_URL}/api/v1/payments/authorize",
        headers={"X-Idempotency-Key": unique_key(), "X-Terminal-Id": TERMINAL_ID},
        body={
            "dpan": "9999999999999999",
            "transaction": {"amount": 5000, "currency": "RON",
                            "pos_nonce": nonce6, "terminal_timestamp": ts6},
            "cryptogram": {"mac": mac6, "atc": 500},
        },
        expect_status=400,
        expect_fields={"detail.error_code": "INVALID_TOKEN"},
    )
    time.sleep(INTER_TEST_SLEEP)

    # ----------------------------------------------------------
    print("\n♻️  [7/9] Idempotență — retrimite TC-02 (răspuns din cache)")
    # Același idempotency key ca TC-02 → Gateway returnează răspunsul stocat în Redis
    # Body-ul poate fi identic sau diferit — idempotența e per key, nu per body
    run_test(
        "TC-07  Idempotent response (APPROVED din cache)",
        "post", f"{GATEWAY_URL}/api/v1/payments/authorize",
        headers={"X-Idempotency-Key": tc02_idemp_key, "X-Terminal-Id": TERMINAL_ID},
        body=tc02_body,
        expect_status=200,
        expect_fields={"status": "APPROVED"},
    )
    time.sleep(INTER_TEST_SLEEP)

    # ----------------------------------------------------------
    print("\n⚠️  [8/9] Header X-Idempotency-Key lipsă")
    run_test(
        "TC-08  MISSING_IDEMPOTENCY_KEY",
        "post", f"{GATEWAY_URL}/api/v1/payments/authorize",
        headers={"X-Terminal-Id": TERMINAL_ID},  # fără X-Idempotency-Key
        body={
            "dpan": "4000000000000001",
            "transaction": {"amount": 5000, "currency": "RON",
                            "pos_nonce": "AABBCCDD", "terminal_timestamp": now_iso()},
            "cryptogram": {"mac": "fakemac", "atc": 999},
        },
        expect_status=400,
        expect_fields={"detail.error_code": "MISSING_IDEMPOTENCY_KEY"},
    )
    time.sleep(INTER_TEST_SLEEP)

    # ----------------------------------------------------------
    print("\n⚠️  [9/9] Header X-Terminal-Id lipsă")
    run_test(
        "TC-09  MISSING_TERMINAL_ID",
        "post", f"{GATEWAY_URL}/api/v1/payments/authorize",
        headers={"X-Idempotency-Key": unique_key()},  # fără X-Terminal-Id
        body={
            "dpan": "4000000000000001",
            "transaction": {"amount": 5000, "currency": "RON",
                            "pos_nonce": "AABBCCDD", "terminal_timestamp": now_iso()},
            "cryptogram": {"mac": "fakemac", "atc": 999},
        },
        expect_status=400,
        expect_fields={"detail.error_code": "MISSING_TERMINAL_ID"},
    )

    # ----------------------------------------------------------
    print("\n" + "=" * 60)
    passed_count = sum(1 for _, ok, _ in results if ok)
    total_count = len(results)
    print(f"REZULTAT FINAL: {passed_count}/{total_count} teste trecute\n")

    if passed_count == total_count:
        print("🎉 Toate testele au trecut! Fluxul end-to-end este funcțional.")
    else:
        print("❌ Teste eșuate:")
        for name, ok, detail in results:
            if not ok:
                print(f"   • {name}: {detail}")

    print("=" * 60)
    exit(0 if passed_count == total_count else 1)


if __name__ == "__main__":
    main()
