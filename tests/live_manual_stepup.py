#!/usr/bin/env python3
"""
============================================================
live_manual_stepup.py — Test Step-Up PIN Manual pe ESP32
============================================================
Acest script inițiază o plată reală pe terminalul fizic ESP32,
folosind un card de test cu risc ridicat (risk_level=55) care
forțează fluxul de Step-Up PIN Challenge.

Procedură:
  1. Șterge automat cache-ul de fraudă din Redis pentru contul de test.
  2. Trimite comanda de inițiere a plății la ESP32 (12.50 RON).
  3. Pollează ESP32 pentru a obține datele tranzacției.
  4. Generează o criptogramă validă (MAC) folosind cheia de securitate.
  5. Trimite datele de plată la ESP32.
  6. ESP32 trimite cererea la Gateway, primește 401 CHALLENGE_REQUIRED
     și afișează ecranul de introducere PIN ("INTRODU PIN").
  7. Utilizatorul introduce manual PIN-ul "1234" + "#" pe tastatura fizică.
  8. Scriptul monitorizează tranzacția până când este aprobată de bancă.
============================================================
"""

import os
import sys
import time
import hmac as hmac_lib
import hashlib
import uuid
import httpx
import redis
from datetime import datetime, timezone

# Configurații
ESP32_URL = "http://192.168.101.67"
BANK_BT_API = "http://nfc-issuing-bank-bt:8004"
PAN = "4000001111111111"
DPAN = "TEST-STEP-UP-BT"

def compute_mac(key: bytes, amount_cents: int, currency: str,
                pos_nonce: str, terminal_timestamp: str, atc: int) -> str:
    mac_input = f"{amount_cents}|{currency}|{pos_nonce}|{terminal_timestamp}|{atc}"
    return hmac_lib.new(key, mac_input.encode("utf-8"), hashlib.sha256).hexdigest()

def reset_fraud_state() -> None:
    """Resetează starea de fraudă în Redis pentru a garanta scor de risc stabil (exact 55)."""
    try:
        redis_pw = os.getenv("REDIS_PASSWORD", "")
        r = redis.Redis(
            host=os.getenv("REDIS_HOST", "redis-master"),
            port=int(os.getenv("REDIS_PORT", "6379")),
            password=redis_pw if redis_pw else None,
            decode_responses=True
        )
        keys = [f"velocity:{PAN}", f"risk:{PAN}", f"amounts:{PAN}"]
        r.delete(*keys)
        r.close()
        print("  🧹 Cache Redis de fraudă curățat cu succes pentru test curat.")
    except Exception as e:
        print(f"  ⚠️ Avertisment: Nu s-a putut curăța cache-ul Redis: {e}")

def get_latest_transaction_status() -> tuple[str, str]:
    """Interoghează istoricul băncii pentru a afla statusul ultimei tranzacții."""
    try:
        r = httpx.get(f"{BANK_BT_API}/api/v1/admin/transactions?pan={PAN}", timeout=3.0)
        if r.status_code == 200:
            txs = r.json().get("transactions", [])
            if txs:
                latest = txs[0]
                return latest.get("status"), latest.get("transaction_id")
    except Exception:
        pass
    return "UNKNOWN", ""

def main():
    # Asigurăm UTF-8 în terminal
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    print("\n" + "="*70)
    print("🌟 FLUX LIVE PIN CHALLENGE — TEST MANUAL PE ESP32 🌟")
    print("="*70)

    # 1. Preflight checks
    hex_key = os.getenv("BANK_BT_HMAC_KEY", "")
    if not hex_key:
        print("❌ EROARE: Cheia BANK_BT_HMAC_KEY nu este setată în mediu!")
        sys.exit(1)
    
    hmac_key = bytes.fromhex(hex_key)

    # 2. Resetăm riscul în Redis
    reset_fraud_state()

    # Preluăm starea tranzacțiilor anterioare pentru referință
    initial_status, initial_tx_id = get_latest_transaction_status()

    # 3. Inițiem plata de 12.50 RON pe ESP32
    print("\n👉 [1/5] Se trimite comanda de inițiere a plății către ESP32...")
    try:
        resp = httpx.post(
            f"{ESP32_URL}/initiate",
            json={"amount_cents": 1250, "currency": "RON"},
            timeout=5.0
        )
        if resp.status_code != 200:
            print(f"❌ ESP32 a respins inițierea: HTTP {resp.status_code} - {resp.text}")
            sys.exit(1)
        print("  ✅ Plata a fost inițiată cu succes pe terminal!")
        print("  📱 Ecranul ESP32 ar trebui să afișeze acum suma de 12.50 RON.")
    except Exception as e:
        print(f"❌ Nu s-a putut contacta terminalul ESP32 la {ESP32_URL}: {e}")
        print("   Verificați că ESP32 este pornit și conectat la rețea.")
        sys.exit(1)

    time.sleep(1.0)

    # 4. Polling pentru a citi datele tranzacției generate de ESP32
    print("\n👉 [2/5] Se preiau datele tranzacției de pe ESP32...")
    txn_data = None
    for _ in range(10):
        try:
            r = httpx.get(f"{ESP32_URL}/payment-request", timeout=2.0)
            if r.status_code == 200:
                data = r.json()
                if data.get("status") == "PENDING":
                    txn_data = data
                    break
        except Exception:
            pass
        time.sleep(0.5)

    if not txn_data:
        print("❌ EROARE: Nu s-au putut prelua datele tranzacției (timeout).")
        sys.exit(1)

    print("  ✅ Date tranzacție preluate:")
    print(f"     Suma: {txn_data['amount'] / 100:.2f} RON")
    print(f"     Nonce POS: {txn_data['pos_nonce']}")
    print(f"     Timestamp: {txn_data['terminal_timestamp']}")

    # 5. Generare MAC și trimitere răspuns (telefonul virtual se apropie de POS)
    atc = int(time.time())
    mac = compute_mac(
        hmac_key,
        txn_data["amount"],
        txn_data["currency"],
        txn_data["pos_nonce"],
        txn_data["terminal_timestamp"],
        atc
    )

    print("\n👉 [3/5] Se trimite răspunsul de plată (simulare NFC/apropiere telefon)...")
    try:
        resp = httpx.post(
            f"{ESP32_URL}/payment-response",
            json={"dpan": DPAN, "atc": atc, "mac": mac},
            timeout=5.0
        )
        if resp.status_code != 200:
            print(f"❌ ESP32 a respins plata: HTTP {resp.status_code} - {resp.text}")
            sys.exit(1)
        print("  ✅ Criptograma a fost trimisă cu succes către ESP32!")
    except Exception as e:
        print(f"❌ EROare la transmiterea criptogramei: {e}")
        sys.exit(1)

    # 6. ESP32 trimite la Gateway și primește 401 CHALLENGE_REQUIRED
    print("\n👉 [4/5] Terminalul procesează tranzacția cu sistemele centrale...")
    print("  ⏳ Se așteaptă ca ESP32 să contacteze NGINX/Gateway...")
    time.sleep(2.0)

    # Afișăm instrucțiunile clare pentru utilizator
    print("\n" + "="*70)
    print("🔒 tastatura fizică a terminalului ESP32 ar trebui să solicite PIN-ul! 🔒")
    print("="*70)
    print(" Ecranul ar trebui să afișeze acum ecranul galben 'INTRODU PIN'.")
    print("\n Instrucțiuni:")
    print("  1. Introduceți pe tastatura fizică a ESP32-ului PIN-ul de test:")
    print("     👉   1 2 3 4")
    print("  2. Apăsați tasta '#' pentru a confirma introducerea PIN-ului.")
    print("="*70)
    print("  ⏳ Se monitorizează rețeaua pentru detectarea aprobării tranzacției...")
    
    # 7. Monitorizare rezultat
    start_time = time.time()
    approved = False
    last_checked_tx_id = initial_tx_id

    while time.time() - start_time < 45.0:
        status, tx_id = get_latest_transaction_status()
        if tx_id != last_checked_tx_id and tx_id != initial_tx_id:
            if status == "APPROVED":
                print(f"\n🎉 APROBAT! Tranzacția {tx_id} a fost aprobată cu succes!")
                print("  ✅ Pe ecranul ESP32 ar trebui să apară ecranul verde cu 'APROBAT'!")
                approved = True
                break
            elif status == "DECLINED":
                print(f"\n❌ REFUZAT! Tranzacția {tx_id} a fost refuzată de bancă (PIN greșit sau eroare).")
                break
            elif status == "CHALLENGE_REQUIRED":
                # Încă așteptăm
                pass
        time.sleep(1.0)

    if not approved:
        print("\n⏳ Timpul de așteptare a expirat sau tranzacția nu a putut fi aprobată.")
        print("  Verificați că ați introdus PIN-ul corect '1234' și ați apăsat '#'.")
    
    print("\n" + "="*70)
    print("🌟 SFÂRȘIT TEST PIN MANUAL 🌟")
    print("="*70 + "\n")

if __name__ == "__main__":
    main()
