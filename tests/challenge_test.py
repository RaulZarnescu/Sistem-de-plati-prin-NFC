"""
Test manual pentru fluxul Step-Up PIN Challenge.
Rulează după ce TC-03 returnează 401 CHALLENGE_REQUIRED.
"""
import hmac as hmac_lib
import hashlib
import base64
import os
import uuid
import time
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

import httpx
import redis as redis_sync

GATEWAY_URL = os.getenv("TEST_GATEWAY_URL", "http://localhost:8001")
TSP_URL = os.getenv("TEST_TSP_URL", "http://tsp:8002")
TERMINAL_ID = "POS-CHALLENGE-TEST"

_hex_a = os.getenv("BANK_BT_HMAC_KEY", "")
HMAC_KEY_BT = bytes.fromhex(_hex_a) if _hex_a else b""

# DPAN dedicat testelor de challenge PIN
# Token TSP: TEST-CHALLENGE-PIN → PAN 4000001111111118 (BT SC1), risk_level=50
# risk_level=50: cu Redis fresh → final_risk=50 → CHALLENGE_REQUIRED (40≤50≤75)
CHALLENGE_DPAN = "TEST-CHALLENGE-PIN"
CHALLENGE_PAN  = "4000001111111118"  # PAN din accounts bank_bt cu pin_hash setat

# Conexiune Redis pentru reset stare fraudă între teste
REDIS_HOST     = os.getenv("REDIS_HOST", "redis-master")
REDIS_PORT     = int(os.getenv("REDIS_PORT", "6379"))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "")


def reset_fraud_state(pan: str) -> None:
    """
    Șterge cheile Redis de fraudă (velocity, risk, amounts) pentru un PAN.
    Apelat înainte de fiecare trigger CHALLENGE_REQUIRED pentru teste izolate.
    Fără reset, acumularea velocity din rulări anterioare poate muta scorul
    din zona CHALLENGE_REQUIRED (40-75) în DECLINED (>75).
    """
    r = redis_sync.Redis(
        host=REDIS_HOST, port=REDIS_PORT,
        password=REDIS_PASSWORD, decode_responses=True
    )
    deleted = r.delete(
        f"velocity:{pan}",
        f"risk:{pan}",
        f"amounts:{pan}"
    )
    r.close()
    print(f"  [Redis] Reset stare fraudă pentru {pan[:4]}****{pan[-4:]} ({deleted} chei șterse)")


def derive_session_key(master_key: bytes, atc: int) -> bytes:
    return hmac_lib.new(
        key=master_key,
        msg=str(atc).encode("utf-8"),
        digestmod=hashlib.sha256
    ).digest()

def compute_mac(key, amount_cents, currency, nonce, timestamp, atc):
    session_key = derive_session_key(key, atc)
    mac_input = f"{amount_cents}|{currency}|{nonce}|{timestamp}|{atc}"
    return hmac_lib.new(session_key, mac_input.encode("utf-8"), hashlib.sha256).hexdigest()


def load_public_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def create_pin_block(pin: str, transaction_id: str) -> bytes:
    """
    PoC PIN Block: '{transaction_id}:{pin}' encodat UTF-8.
    Producție: ISO 9564 Format 4.
    """
    return f"{transaction_id}:{pin}".encode("utf-8")


def encrypt_pin_block(pin_block: bytes, public_key) -> str:
    encrypted = public_key.encrypt(
        pin_block,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode("utf-8")


def _trigger_challenge(pub_key) -> tuple[str, str, str]:
    """
    Helper comun: trimite o tranzacție Step-Up și returnează
    (transaction_id, dpan, idemp_key) pentru challenge-ul următor.
    Resetează starea Redis înainte de fiecare trigger pentru teste izolate.
    """
    # Reset stare Redis: garantăm că velocity=0 și risk=0 pentru test curat
    reset_fraud_state(CHALLENGE_PAN)

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    nonce = uuid.uuid4().hex[:8].upper()
    atc = int(time.time() * 1000)
    amount = 10000  # 100 RON în cenți
    dpan = CHALLENGE_DPAN  # TEST-CHALLENGE-PIN → 4000001111111118, risk_level=50
    idemp_key = f"CHALLENGE-{uuid.uuid4().hex[:8].upper()}"

    mac = compute_mac(HMAC_KEY_BT, amount, "RON", nonce, ts, atc)

    with httpx.Client(timeout=10.0) as client:
        resp = client.post(
            f"{GATEWAY_URL}/api/v1/payments/authorize",
            headers={
                "X-Idempotency-Key": idemp_key,
                "X-Terminal-Id": TERMINAL_ID
            },
            json={
                "dpan": dpan,
                "transaction": {
                    "amount": amount,
                    "currency": "RON",
                    "pos_nonce": nonce,
                    "terminal_timestamp": ts
                },
                "cryptogram": {"mac": mac, "atc": atc}
            }
        )

    if resp.status_code != 401:
        raise RuntimeError(f"Așteptat 401 CHALLENGE_REQUIRED, primit {resp.status_code}: {resp.json()}")

    challenge_data = resp.json().get("detail", {})
    transaction_id = challenge_data.get("transaction_id")
    if not transaction_id:
        raise RuntimeError(f"transaction_id lipsă din răspuns: {resp.json()}")

    return transaction_id, dpan, idemp_key


def _send_challenge(transaction_id: str, dpan: str, idemp_key: str, pin: str, pub_key) -> dict:
    """
    Helper: construiește PIN Block pentru `pin`, îl criptează și trimite challenge.
    Returnează dict cu {status_code, body}.
    """
    pin_block = create_pin_block(pin, transaction_id)
    encrypted_pin = encrypt_pin_block(pin_block, pub_key)
    challenge_idemp = f"{idemp_key}-CHALLENGE"

    with httpx.Client(timeout=10.0) as client:
        resp = client.post(
            f"{GATEWAY_URL}/api/v1/payments/challenge",
            headers={
                "X-Idempotency-Key": challenge_idemp,
                "X-Terminal-Id": TERMINAL_ID
            },
            json={
                "transaction_id": transaction_id,
                "original_dpan": dpan,
                "pin_block_encrypted": encrypted_pin
            }
        )

    return {"status_code": resp.status_code, "body": resp.json()}


INTER_TEST_SLEEP = 1.1  # > 1s: resetează fereastra rate limiter (2 req/s per terminal)


def _extract_error_code(body: dict) -> str:
    detail = body.get("detail", body)
    if isinstance(detail, dict):
        return detail.get("error_code", "")
    return body.get("error_code", "")


def test_correct_pin(pub_key) -> bool:
    """
    TC-01: PIN corect (1234) → 200 APPROVED.
    Verifică că fluxul complet Step-Up funcționează end-to-end.
    """
    time.sleep(INTER_TEST_SLEEP)
    print("\n[TC-01] PIN corect (1234) → așteptat 200 APPROVED")
    try:
        txn_id, dpan, idemp_key = _trigger_challenge(pub_key)
        print(f"  ✅ 401 CHALLENGE_REQUIRED. Transaction ID: {txn_id}")

        result = _send_challenge(txn_id, dpan, idemp_key, "1234", pub_key)

        if result["status_code"] == 200 and result["body"].get("status") == "APPROVED":
            auth_code = result["body"].get("auth_code", "N/A")
            print(f"  ✅ PASSED — APPROVED. Auth code: {auth_code}")
            return True
        else:
            print(f"  ❌ FAILED — HTTP {result['status_code']}: {result['body']}")
            return False
    except Exception as e:
        print(f"  ❌ EXCEPTION: {e}")
        return False


def test_wrong_pin(pub_key) -> bool:
    """
    TC-02: PIN greșit (9999) → 400 INCORRECT_PIN.
    Verifică că PIN-ul incorect este respins fără a dezvălui informații
    despre PIN-ul corect (mesaj deliberat vag).
    """
    time.sleep(INTER_TEST_SLEEP)
    print("\n[TC-02] PIN greșit (9999) → așteptat 400 INCORRECT_PIN")
    try:
        txn_id, dpan, idemp_key = _trigger_challenge(pub_key)
        print(f"  ✅ 401 CHALLENGE_REQUIRED. Transaction ID: {txn_id}")

        result = _send_challenge(txn_id, dpan, idemp_key, "9999", pub_key)

        body = result["body"]
        error_code = body.get("detail", body).get("error_code", "") if isinstance(body.get("detail"), dict) else body.get("error_code", "")

        if result["status_code"] == 400 and error_code == "INCORRECT_PIN":
            print(f"  ✅ PASSED — 400 INCORRECT_PIN (mesaj: '{body}')")
            return True
        else:
            print(f"  ❌ FAILED — HTTP {result['status_code']}: {body}")
            return False
    except Exception as e:
        print(f"  ❌ EXCEPTION: {e}")
        return False


def test_invalid_pin_format(pub_key) -> bool:
    """
    TC-03: PIN prea scurt (2 cifre) → 400 INVALID_PIN.
    Verifică validarea formatului PIN (4-6 cifre obligatoriu).
    NOTĂ: eroarea de format este specifică — nu dezvăluie nimic despre
    PIN-ul corect (validarea are loc înainte de compararea cu hash-ul stocat).
    """
    time.sleep(INTER_TEST_SLEEP)
    print("\n[TC-03] PIN prea scurt ('12') → așteptat 400 INVALID_PIN")
    try:
        txn_id, dpan, idemp_key = _trigger_challenge(pub_key)
        print(f"  ✅ 401 CHALLENGE_REQUIRED. Transaction ID: {txn_id}")

        result = _send_challenge(txn_id, dpan, idemp_key, "12", pub_key)

        body = result["body"]
        error_code = body.get("detail", body).get("error_code", "") if isinstance(body.get("detail"), dict) else body.get("error_code", "")

        if result["status_code"] == 400 and error_code == "INVALID_PIN":
            print(f"  ✅ PASSED — 400 INVALID_PIN (mesaj: '{body}')")
            return True
        else:
            print(f"  ❌ FAILED — HTTP {result['status_code']}: {body}")
            return False
    except Exception as e:
        print(f"  ❌ EXCEPTION: {e}")
        return False


def test_pin_retry_blocking(pub_key) -> bool:
    """
    TC-04: PIN retry limiting — 4 încercări greșite pentru același transaction_id.
    Primele 3 → 400 INCORRECT_PIN
    Al 4-lea → 403 PIN_BLOCKED
    """
    time.sleep(INTER_TEST_SLEEP)
    print("\n[TC-04] PIN retry blocking → primele 3: 400 INCORRECT_PIN, al 4-lea: 403 PIN_BLOCKED")
    try:
        txn_id, dpan, _ = _trigger_challenge(pub_key)
        print(f"  ✅ 401 CHALLENGE_REQUIRED. Transaction ID: {txn_id}")

        for attempt_num in range(1, 4):
            attempt_idemp = f"RETRY-{uuid.uuid4().hex[:8].upper()}"
            result = _send_challenge(txn_id, dpan, attempt_idemp, "9999", pub_key)
            ec = _extract_error_code(result["body"])
            if result["status_code"] != 400 or ec != "INCORRECT_PIN":
                print(f"  ❌ FAILED — Attempt {attempt_num}: HTTP {result['status_code']}: {result['body']}")
                return False
            print(f"  ✅ Attempt {attempt_num}/3: 400 INCORRECT_PIN")

        # Al 4-lea → PIN_BLOCKED (403)
        attempt_idemp = f"RETRY-{uuid.uuid4().hex[:8].upper()}"
        result = _send_challenge(txn_id, dpan, attempt_idemp, "9999", pub_key)
        ec = _extract_error_code(result["body"])
        if result["status_code"] == 403 and ec == "PIN_BLOCKED":
            print(f"  ✅ PASSED — Attempt 4: 403 PIN_BLOCKED")
            return True
        else:
            print(f"  ❌ FAILED — Attempt 4: HTTP {result['status_code']}: {result['body']}")
            return False
    except Exception as e:
        print(f"  ❌ EXCEPTION: {e}")
        return False


def test_token_suspended(pub_key) -> bool:
    """
    TC-05: Token suspendat (TEST-STEP-UP-BT) → HTTP 403 TOKEN_SUSPENDED.
    Reactivează token-ul în finally pentru a nu afecta alte teste.
    """
    time.sleep(INTER_TEST_SLEEP)
    print("\n[TC-05] Token suspendat → așteptat 403 TOKEN_SUSPENDED")
    try:
        # 1. Suspendă token-ul via TSP
        with httpx.Client(timeout=10.0) as client:
            resp = client.patch(
                f"{TSP_URL}/api/v1/tokens/status",
                json={"dpan": "TEST-STEP-UP-BT", "status": "SUSPENDED"}
            )
        if resp.status_code != 200:
            print(f"  ❌ FAILED — Nu s-a putut suspenda token-ul: {resp.status_code}: {resp.json()}")
            return False
        print(f"  ✅ Token TEST-STEP-UP-BT suspendat")

        # 2. Încearcă o tranzacție cu DPAN-ul suspendat
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        nonce = uuid.uuid4().hex[:8].upper()
        atc = int(time.time() * 1000)
        amount = 5000
        idemp_key = f"SUSPENDED-{uuid.uuid4().hex[:8].upper()}"
        mac = compute_mac(HMAC_KEY_BT, amount, "RON", nonce, ts, atc)

        with httpx.Client(timeout=10.0) as client:
            resp = client.post(
                f"{GATEWAY_URL}/api/v1/payments/authorize",
                headers={
                    "X-Idempotency-Key": idemp_key,
                    "X-Terminal-Id": TERMINAL_ID
                },
                json={
                    "dpan": "TEST-STEP-UP-BT",
                    "transaction": {
                        "amount": amount,
                        "currency": "RON",
                        "pos_nonce": nonce,
                        "terminal_timestamp": ts
                    },
                    "cryptogram": {"mac": mac, "atc": atc}
                }
            )

        ec = _extract_error_code(resp.json())
        if resp.status_code == 403 and ec == "TOKEN_SUSPENDED":
            print(f"  ✅ PASSED — 403 TOKEN_SUSPENDED")
            return True
        else:
            print(f"  ❌ FAILED — HTTP {resp.status_code}: {resp.json()}")
            return False
    except Exception as e:
        print(f"  ❌ EXCEPTION: {e}")
        return False
    finally:
        # Reactivează token-ul indiferent de rezultat
        try:
            with httpx.Client(timeout=5.0) as client:
                client.patch(
                    f"{TSP_URL}/api/v1/tokens/status",
                    json={"dpan": "TEST-STEP-UP-BT", "status": "ACTIVE"}
                )
            print(f"  ✅ Token TEST-STEP-UP-BT reactivat")
        except Exception:
            pass


def main():
    print("\n🔐 Test Flow Step-Up PIN Challenge")
    print("=" * 50)

    # Încărcare cheie publică BT — necesară pentru criptarea PIN Block
    print("\n[0/5] Încărcare cheie publică RSA BT...")
    try:
        pub_key = load_public_key("/tmp/bank_bt_public.pem")
        print("  ✅ Cheie publică încărcată.")
    except FileNotFoundError:
        print("  ❌ /tmp/bank_bt_public.pem lipsă — generează cheile RSA mai întâi")
        print("     Rulează: docker exec nfc-issuing-bank-bt cat /app/keys/bank_bt_public.pem > /tmp/bank_bt_public.pem")
        return

    # Rulăm toate testele
    results = {
        "TC-01 PIN corect":            test_correct_pin(pub_key),
        "TC-02 PIN greșit":            test_wrong_pin(pub_key),
        "TC-03 PIN format invalid":    test_invalid_pin_format(pub_key),
        "TC-04 PIN retry blocking":    test_pin_retry_blocking(pub_key),
        "TC-05 Token suspendat":       test_token_suspended(pub_key),
    }

    # Sumar final
    print("\n" + "=" * 50)
    print("SUMAR TESTE:")
    passed = 0
    for name, ok in results.items():
        status = "✅ PASSED" if ok else "❌ FAILED"
        print(f"  {status}  {name}")
        if ok:
            passed += 1

    total = len(results)
    print(f"\n{passed}/{total} teste trecute.")
    if passed == total:
        print("🎉 Toate testele au trecut!")
    else:
        print("⚠️  Unele teste au eșuat — verifică logurile serviciului.")
    print("=" * 50)


if __name__ == "__main__":
    main()