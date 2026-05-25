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

GATEWAY_URL = os.getenv("TEST_GATEWAY_URL", "http://localhost:8001")
TERMINAL_ID = "POS-CHALLENGE-TEST"

_hex_a = os.getenv("BANK_BT_HMAC_KEY", "")
HMAC_KEY_BT = bytes.fromhex(_hex_a) if _hex_a else b""


def compute_mac(key, amount_cents, currency, nonce, timestamp, atc):
    mac_input = f"{amount_cents}|{currency}|{nonce}|{timestamp}|{atc}"
    return hmac_lib.new(key, mac_input.encode("utf-8"), hashlib.sha256).hexdigest()


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


def main():
    print("\n🔐 Test Flow Step-Up PIN Challenge")
    print("=" * 50)

    # Pasul 1 — Tranzacție inițială care declanșează CHALLENGE_REQUIRED
    print("\n[1/3] Trimitere tranzacție cu DPAN Step-Up...")
    
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    nonce = uuid.uuid4().hex[:8].upper()
    atc = int(time.time() * 1000)
    amount = 10000  # 100 RON în cenți
    dpan = "TEST-STEP-UP-BT"  # DPAN cu risk_level ridicat în Token Vault BT
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
        print(f"  ❌ Așteptat 401, primit {resp.status_code}: {resp.json()}")
        return

    challenge_data = resp.json().get("detail", {})
    transaction_id = challenge_data.get("transaction_id")
    print(f"  ✅ 401 CHALLENGE_REQUIRED. Transaction ID: {transaction_id}")

    # Pasul 2 — Construim și criptăm PIN Block
    print("\n[2/3] Construire și criptare PIN Block...")
    
    # Cheia publică BT — în producție e descărcată de ESP32 via /api/pki/renew
    try:
        pub_key = load_public_key("/tmp/bank_bt_public.pem")
    except FileNotFoundError:
        print("  ❌ /tmp/bank_bt_public.pem lipsă — generează cheile RSA mai întâi")
        return

    pin = "1234"  # PIN de test
    pin_block = create_pin_block(pin, transaction_id)
    encrypted_pin = encrypt_pin_block(pin_block, pub_key)
    print(f"  ✅ PIN Block criptat ({len(encrypted_pin)} chars base64)")

    # Pasul 3 — Trimitem challenge
    print("\n[3/3] Trimitere challenge cu PIN...")
    
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

    if resp.status_code == 200 and resp.json().get("status") == "APPROVED":
        print(f"  ✅ APPROVED! Auth code: {resp.json().get('auth_code')}")
    else:
        print(f"  ❌ HTTP {resp.status_code}: {resp.json()}")

    print("\n" + "=" * 50)


if __name__ == "__main__":
    main()