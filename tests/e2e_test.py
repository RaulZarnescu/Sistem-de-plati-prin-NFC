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
  TC-10  Rate Limiting (3 req < 1s)        → 429 RATE_LIMIT_EXCEEDED
  TC-11  DECLINED (tsp_risk=90 > 75)      → 200 status:DECLINED
  TC-12  Fail-Closed Redis               → PowerShell: tests/redis_failover_test.ps1
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
_hex_a = os.getenv("BANK_BT_HMAC_KEY", "")
HMAC_KEY_A = bytes.fromhex(_hex_a) if _hex_a else b""

_hex_b = os.getenv("BANK_BCR_HMAC_KEY", "")
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
    """
    Replicăm exact formula 2-step din shared/crypto_utils.py + Android CryptoUtils.kt:
      Step 1: Session_Key = HMAC-SHA256(master_key, str(atc))
      Step 2: MAC = HMAC-SHA256(Session_Key, mac_input)
    """
    session_key = hmac_lib.new(
        key, str(atc).encode("utf-8"), hashlib.sha256
    ).digest()
    mac_input = f"{amount_cents}|{currency}|{pos_nonce}|{terminal_timestamp}|{atc}"
    return hmac_lib.new(session_key, mac_input.encode("utf-8"), hashlib.sha256).hexdigest()


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


def reset_fraud_state(pan: str) -> None:
    """Șterge cheile Redis de fraudă pentru a reseta riscul velocity."""
    try:
        import redis
        redis_pw = os.getenv("REDIS_PASSWORD", "")
        r = redis.Redis(
            host=os.getenv("REDIS_HOST", "redis-master"),
            port=int(os.getenv("REDIS_PORT", "6379")),
            password=redis_pw if redis_pw else None,
            decode_responses=True,
        )
        keys = [f"velocity:{pan}", f"risk:{pan}", f"amounts:{pan}"]
        r.delete(*keys)
        r.close()
    except Exception as e:
        print(f"      [WARNING] Failed to reset fraud state in Redis: {e}")


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
        print("  ❌ BANK_BT_HMAC_KEY nu este setată în mediu!")
        ok = False
    else:
        print(f"  ✅ HMAC Key BT/A prezentă ({len(HMAC_KEY_A)} bytes)")

    if not HMAC_KEY_B:
        print("  ❌ BANK_BCR_HMAC_KEY nu este setată în mediu!")
        ok = False
    else:
        print(f"  ✅ HMAC Key BCR/B prezentă ({len(HMAC_KEY_B)} bytes)")

    if not ok:
        print("\n  STOP: Cheile HMAC lipsesc. Verifică .env și env_file din docker-compose.yml")
        exit(1)


# ============================================================
# SUITE DE TESTE
# ============================================================

def main():
    preflight()

    # Reset all test card fraud states in Redis to ensure a clean slate for the test run
    print("\n🧹 Cleaning Redis fraud states for all test cards...")
    reset_fraud_state("4000001111111111")
    reset_fraud_state("5000002222222222")
    reset_fraud_state("4222222222222222")
    reset_fraud_state("4444444444444444")
    print("  ✅ Redis clean-up complete.")

    # ATC-uri bazate pe timestamp Unix — garantat crescătoare între rulări succesive.
    # Redis persistă ATC-urile (AOF), deci rularea 2 cu aceiași ATC statici (100, 200)
    # ar fi respinsă ca replay. time.time() crește la fiecare rulare → ATC nou, valid.
    _atc_base = int(time.time() * 1000)
    tc01_atc  = _atc_base        # folosit și în TC-05 (replay)
    atc2      = _atc_base + 1
    atc3      = _atc_base + 2
    atc4      = _atc_base + 3    # TC-04: MAC tampered — banca nu ajunge la ATC check
    atc11     = _atc_base + 10   # TC-11: DECLINED — offset mare, nu intră în conflict cu atc2..4

    tc02_idemp_key = None  # folosit în TC-07 (idempotency)
    tc02_body = None       # folosit în TC-07

    # ----------------------------------------------------------
    print("\n📡 [0/14] Conectivitate Gateway")
    run_test(
        "TC-00  Health Check",
        "get", f"{GATEWAY_URL}/health",
        headers={}, body=None,
        expect_status=200,
        expect_fields={"status": "healthy"},
    )
    time.sleep(INTER_TEST_SLEEP)

    # ----------------------------------------------------------
    print("\n💳 [1/14] Happy path — Visa (Bank A, prefix 4)")
    ts1, nonce1, atc1 = now_iso(), unique_nonce(), tc01_atc  # atc1 == tc01_atc
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
    print("\n💳 [2/14] Happy path — Mastercard (Bank B, prefix 5)")
    ts2, nonce2 = now_iso(), unique_nonce()  # atc2 definit în _atc_base block de sus
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
    print("\n🔐 [3/14] Step-Up Authentication (risk_level=55, Bank A)")
    ts3, nonce3 = now_iso(), unique_nonce()  # atc3 definit în _atc_base block de sus
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
    print("\n🚨 [4/14] MAC tampered — sumă alterată de atacator")
    # Atacatorul calculează MAC pentru 1 ban (amount=1)
    # dar trimite suma reală de 999 RON (amount=99900) în body.
    # Banca recalculează MAC cu 99900 → nepotrivire → INVALID_CRYPTOGRAM
    ts4, nonce4 = now_iso(), unique_nonce()  # atc4 definit în _atc_base block de sus
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
    print("\n🔄 [5/14] ATC Replay Attack (același ATC ca TC-01)")
    # Reset fraud state in Redis to avoid triggering CHALLENGE_REQUIRED due to high velocity
    reset_fraud_state("4000001111111111")
    # Banca a stocat last_atc=tc01_atc după TC-01.
    # Trimitem din nou același ATC → received_atc <= stored_atc → REPLAY DETECTED.
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
    print("\n❓ [6/14] DPAN necunoscut în Token Vault")
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
    print("\n♻️  [7/14] Idempotență — retrimite TC-02 (răspuns din cache)")
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
    print("\n⚠️  [8/14] Header X-Idempotency-Key lipsă")
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
    print("\n⚠️  [9/14] Header X-Terminal-Id lipsă")
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

    time.sleep(INTER_TEST_SLEEP)

    # ----------------------------------------------------------
    print("\n🚦 [10/14] Rate Limiting — 3 cereri < 1s → 429 RATE_LIMIT_EXCEEDED")
    # Terminal dedicat pentru a nu interfera cu celelalte teste.
    # Gateway-ul limitează la 2 req/s per terminal (fereastră fixă pe secundă).
    rl_terminal = "POS-RATELIMIT-E2E"

    # Sincronizăm la chiar începutul unui nou secundă:
    # toate cele 3 cereri trebuie să cadă în aceeași fereastră int(time.time()).
    next_sec = int(time.time()) + 1
    while time.time() < next_sec:
        time.sleep(0.005)

    # Cererile 1 și 2 — trec rate limiter-ul (count=1, 2),
    # eșuează la TSP (DPAN necunoscut) → 400 INVALID_TOKEN. Normal, nu le verificăm.
    for i in range(2):
        with httpx.Client(timeout=5.0) as client:
            client.post(
                f"{GATEWAY_URL}/api/v1/payments/authorize",
                headers={"X-Idempotency-Key": unique_key(), "X-Terminal-Id": rl_terminal},
                json={
                    "dpan": "9999999999999999",
                    "transaction": {"amount": 1000, "currency": "RON",
                                    "pos_nonce": unique_nonce(), "terminal_timestamp": now_iso()},
                    "cryptogram": {"mac": "fakemac", "atc": i + 1},
                }
            )

    # Cererea 3 în aceeași secundă — trebuie să primească 429 RATE_LIMIT_EXCEEDED.
    run_test(
        "TC-10  RATE_LIMIT_EXCEEDED (req 3/3 < 1s)",
        "post", f"{GATEWAY_URL}/api/v1/payments/authorize",
        headers={"X-Idempotency-Key": unique_key(), "X-Terminal-Id": rl_terminal},
        body={
            "dpan": "9999999999999999",
            "transaction": {"amount": 1000, "currency": "RON",
                            "pos_nonce": unique_nonce(), "terminal_timestamp": now_iso()},
            "cryptogram": {"mac": "fakemac", "atc": 3},
        },
        expect_status=429,
        expect_fields={"detail.error_code": "RATE_LIMIT_EXCEEDED"},
    )
    time.sleep(INTER_TEST_SLEEP)

    # ----------------------------------------------------------
    print("\n🚫 [11/14] DECLINED — Fraud score > 75 (tsp_risk=90, Bank A)")
    # TEST-DECLINE-001 → PAN 4444444444444444 → prefix 4 → Bank A → HMAC_KEY_A
    # Prima tranzacție pentru acest PAN: decayed_base=0, velocity=0, amount_dev=0
    # final_risk = int(min(0 + 0 + 0 + 90, 100)) = 90 > 75 → DECLINED
    ts11, nonce11 = now_iso(), unique_nonce()
    mac11 = compute_mac(HMAC_KEY_A, 5000, "RON", nonce11, ts11, atc11)
    run_test(
        "TC-11  DECLINED (fraud score > 75)",
        "post", f"{GATEWAY_URL}/api/v1/payments/authorize",
        headers={"X-Idempotency-Key": unique_key(), "X-Terminal-Id": TERMINAL_ID},
        body={
            "dpan": "TEST-DECLINE-001",
            "transaction": {"amount": 5000, "currency": "RON",
                            "pos_nonce": nonce11, "terminal_timestamp": ts11},
            "cryptogram": {"mac": mac11, "atc": atc11},
        },
        expect_status=200,
        expect_fields={"status": "DECLINED"},
    )

    # ----------------------------------------------------------
    print("\n🚫 [12/14] Terminal Blacklist — terminal revocat")
    blacklist_terminal = "POS-BLACKLIST-TEST"

    # Step 12a: Adaugă în blacklist
    run_test(
        "TC-12a Add terminal to blacklist",
        "post", f"{GATEWAY_URL}/api/v1/admin/terminals/blacklist",
        headers={},
        body={"terminal_id": blacklist_terminal, "action": "ADD"},
        expect_status=200,
        expect_fields={"status": "BLACKLISTED"},
    )
    time.sleep(0.1)

    # Step 12b: Tranzacție cu terminal blacklistat → 403
    ts12, nonce12 = now_iso(), unique_nonce()
    mac12 = compute_mac(HMAC_KEY_A, 5000, "RON", nonce12, ts12, _atc_base + 20)
    run_test(
        "TC-12b TERMINAL_REVOKED (blacklisted)",
        "post", f"{GATEWAY_URL}/api/v1/payments/authorize",
        headers={
            "X-Idempotency-Key": unique_key(),
            "X-Terminal-Id": blacklist_terminal
        },
        body={
            "dpan": "4000000000000001",
            "transaction": {"amount": 5000, "currency": "RON",
                            "pos_nonce": nonce12, "terminal_timestamp": ts12},
            "cryptogram": {"mac": mac12, "atc": _atc_base + 20},
        },
        expect_status=403,
        expect_fields={"detail.error_code": "TERMINAL_REVOKED"},
    )
    time.sleep(0.1)

    # Step 12c: Elimină din blacklist
    run_test(
        "TC-12c Remove terminal from blacklist",
        "post", f"{GATEWAY_URL}/api/v1/admin/terminals/blacklist",
        headers={},
        body={"terminal_id": blacklist_terminal, "action": "REMOVE"},
        expect_status=200,
        expect_fields={"status": "ACTIVE"},
    )
    time.sleep(INTER_TEST_SLEEP)

    # ----------------------------------------------------------
    print("\n💳 [13/14] Card Expired — card cu exp_year 2020")
    # TEST-EXPIRED-001 → PAN 4000009999999999 (BT), exp_year='20' (2020)
    # Seeded în db/init/tsp/01_schema.sql și db/init/bank/01_schema.sql.template
    ts13, nonce13 = now_iso(), unique_nonce()
    atc13 = _atc_base + 30
    mac13 = compute_mac(HMAC_KEY_A, 5000, "RON", nonce13, ts13, atc13)
    run_test(
        "TC-13  CARD_EXPIRED",
        "post", f"{GATEWAY_URL}/api/v1/payments/authorize",
        headers={"X-Idempotency-Key": unique_key(), "X-Terminal-Id": TERMINAL_ID},
        body={
            "dpan": "TEST-EXPIRED-001",
            "transaction": {"amount": 5000, "currency": "RON",
                            "pos_nonce": nonce13, "terminal_timestamp": ts13},
            "cryptogram": {"mac": mac13, "atc": atc13},
        },
        expect_status=400,
        expect_fields={"detail.error_code": "CARD_EXPIRED"},
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

    print("\nNOTĂ: Fail-Closed Redis rulează separat din PowerShell:")
    print("  .\\tests\\redis_failover_test.ps1")
    print("=" * 60)
    exit(0 if passed_count == total_count else 1)


if __name__ == "__main__":
    main()
