#!/usr/bin/env python3
"""
============================================================
phone_wifi_simulator.py — Simulator telefon Android (Wi-Fi)
============================================================

Simulează exact ce face aplicația Android (WifiPaymentClient)
conectându-se la POS prin WebSocket.

Util pentru a testa pos_wifi_server.py fără a folosi telefonul.
Reproduce același protocol și aceeași criptografie ca aplicația.

Folosire:
  python tests/phone_wifi_simulator.py --pos-ip 192.168.1.100
  python tests/phone_wifi_simulator.py --pos-ip localhost --port 8090
============================================================
"""

import asyncio
import json
import hmac as hmac_lib
import hashlib
import argparse
import sys
import time

try:
    import websockets
except ImportError:
    print("❌ Lipsă: pip install websockets")
    sys.exit(1)

# ── Date card de test (identice cu ce are banca în TSP) ───────────────────────

TEST_CARDS = {
    "BT_VISA": {
        "dpan":        "4000000000000001",
        "hmac_key_hex": "",   # completat din .env: BANK_BT_HMAC_KEY / ISSUING_BANK_HMAC_MASTER_KEY
        "description": "Visa BT (Bank A) — happy path"
    },
    "BCR_MASTERCARD": {
        "dpan":        "5000000000000002",
        "hmac_key_hex": "",   # completat din .env: BANK_BCR_HMAC_KEY / ISSUING_BANK_B_HMAC_MASTER_KEY
        "description": "Mastercard BCR (Bank B) — happy path"
    },
    "ING_MASTERCARD": {
        "dpan":        "5000000000000003",
        "hmac_key_hex": "",   # completat din .env: BANK_ING_HMAC_KEY
        "description": "Mastercard ING (Bank C) — happy path"
    },
    "STEP_UP": {
        "dpan":        "TEST-STEP-UP-001",
        "hmac_key_hex": "",   # BT key
        "description": "Step-Up (risk_level=55) → CHALLENGE_REQUIRED"
    },
    "DECLINE": {
        "dpan":        "TEST-DECLINE-001",
        "hmac_key_hex": "",   # BT key
        "description": "Fraud score > 75 → DECLINED"
    },
}

# ── Criptografie (identică cu shared/crypto_utils.py și CryptoUtils.kt) ───────

def compute_mac(hmac_key_bytes: bytes, amount_cents: int, currency: str,
                pos_nonce: str, terminal_timestamp: str, atc: int) -> str:
    """
    Formula exactă agreată între Android, ESP32 și backend:
      session_key = HMAC-SHA256(K_user, str(atc))
      mac_input   = "{amount_cents}|{currency}|{nonce}|{timestamp}|{atc}"
      mac         = HMAC-SHA256(session_key, mac_input.encode("utf-8")).hexdigest()
    """
    session_key = hmac_lib.new(
        hmac_key_bytes,
        str(atc).encode("utf-8"),
        hashlib.sha256
    ).digest()

    mac_input = f"{amount_cents}|{currency}|{pos_nonce}|{terminal_timestamp}|{atc}"
    return hmac_lib.new(
        session_key,
        mac_input.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

# ── Simulator ─────────────────────────────────────────────────────────────────

async def simulate_phone(pos_ip: str, pos_port: int, card_key: str,
                         hmac_key_hex: str, atc: int):

    uri = f"ws://{pos_ip}:{pos_port}/pay"
    card = TEST_CARDS[card_key]

    if not hmac_key_hex:
        print("❌ HMAC key lipsă! Furnizează --hmac-key sau setează variabila de mediu.")
        return

    hmac_key_bytes = bytes.fromhex(hmac_key_hex)

    print(f"\n📱 Simulator telefon pornit")
    print(f"   Card     : {card['description']}")
    print(f"   DPAN     : ...{card['dpan'][-4:]}")
    print(f"   POS      : {uri}")
    print(f"   ATC init : {atc}")

    try:
        async with websockets.connect(uri, open_timeout=10) as ws:
            print(f"\n✅ Conectat la POS: {uri}")

            # Așteptăm REQUEST de la POS
            raw = await asyncio.wait_for(ws.recv(), timeout=30.0)
            request = json.loads(raw)

            if request.get("type") != "REQUEST":
                print(f"❌ Mesaj neașteptat de la POS: {request}")
                return

            amount_cents = request["amount_cents"]
            currency     = request["currency"]
            nonce        = request["nonce"]
            timestamp    = request["timestamp"]

            print(f"\n📥 Cerere POS: {amount_cents/100:.2f} {currency} | nonce={nonce}")

            # Calculăm MAC (identic cu CryptoUtils.kt)
            mac = compute_mac(hmac_key_bytes, amount_cents, currency,
                              nonce, timestamp, atc)

            response = json.dumps({
                "type": "RESPONSE",
                "dpan": card["dpan"],
                "atc":  atc,
                "mac":  mac
            })

            print(f"📤 Trimitere răspuns: ATC={atc} | MAC={mac[:16]}...")
            await ws.send(response)

            # Așteptăm RESULT
            raw_result = await asyncio.wait_for(ws.recv(), timeout=30.0)
            result = json.loads(raw_result)

            status = result.get("status", "unknown")
            reason = result.get("reason", "")

            print(f"\n{'✅ APROBAT!' if status == 'approved' else '❌ REFUZAT'}")
            if reason:
                print(f"   Motiv: {reason}")
            print(f"   Status raw: {status}")

    except websockets.exceptions.ConnectionRefusedError:
        print(f"❌ Conexiune refuzată la {uri} — rulează pos_wifi_server.py?")
    except asyncio.TimeoutError:
        print("⏱️  Timeout — POS nu a răspuns")
    except Exception as e:
        print(f"❌ Eroare: {e}")


# ── Main ──────────────────────────────────────────────────────────────────────

def load_keys_from_env():
    """Încearcă să încarce cheile HMAC din .env sau variabile de mediu."""
    import os
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

    key_bt  = os.getenv("BANK_BT_HMAC_KEY") or os.getenv("ISSUING_BANK_HMAC_MASTER_KEY", "")
    key_bcr = os.getenv("BANK_BCR_HMAC_KEY") or os.getenv("ISSUING_BANK_B_HMAC_MASTER_KEY", "")
    key_ing = os.getenv("BANK_ING_HMAC_KEY", "")

    TEST_CARDS["BT_VISA"]["hmac_key_hex"]       = key_bt
    TEST_CARDS["STEP_UP"]["hmac_key_hex"]        = key_bt
    TEST_CARDS["DECLINE"]["hmac_key_hex"]        = key_bt
    TEST_CARDS["BCR_MASTERCARD"]["hmac_key_hex"] = key_bcr
    TEST_CARDS["ING_MASTERCARD"]["hmac_key_hex"] = key_ing


def main():
    load_keys_from_env()

    parser = argparse.ArgumentParser(description="Simulator telefon Android (Wi-Fi payment)")
    parser.add_argument("--pos-ip",   default="localhost",   help="IP-ul POS-ului (default: localhost)")
    parser.add_argument("--port",     type=int, default=8090, help="Portul WebSocket (default: 8090)")
    parser.add_argument("--card",     default="BT_VISA",
                        choices=list(TEST_CARDS.keys()),
                        help="Cardul de folosit (default: BT_VISA)")
    parser.add_argument("--hmac-key", default="",
                        help="HMAC key hex (override față de .env)")
    parser.add_argument("--atc",      type=int, default=int(time.time() * 1000) % 100000,
                        help="ATC de pornire (default: bazat pe timestamp)")

    args = parser.parse_args()

    hmac_key = args.hmac_key or TEST_CARDS[args.card]["hmac_key_hex"]
    if not hmac_key:
        print("\n⚠️  HMAC key lipsă!")
        print("   Opțiuni:")
        print("   1. Setează BANK_BT_HMAC_KEY în .env")
        print("   2. Furnizează --hmac-key <hex_key>")
        print("\n   Cheia se găsește în .env la: ISSUING_BANK_HMAC_MASTER_KEY")
        sys.exit(1)

    print("\n" + "=" * 55)
    print("  📱 SIMULATOR TELEFON ANDROID — Wi-Fi Payment")
    print("=" * 55)
    print(f"\n  Carduri disponibile:")
    for key, card in TEST_CARDS.items():
        marker = "→" if key == args.card else " "
        print(f"  {marker} [{key}] {card['description']}")

    asyncio.run(simulate_phone(
        pos_ip      = args.pos_ip,
        pos_port    = args.port,
        card_key    = args.card,
        hmac_key_hex = hmac_key,
        atc          = args.atc
    ))


if __name__ == "__main__":
    main()
