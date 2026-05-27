#!/usr/bin/env python3
"""
============================================================
pos_wifi_server.py — Server WebSocket POS (înlocuiește PN532)
============================================================

Simulează terminalul de plată POS prin Wi-Fi.
Rulează pe laptop/PC în loc de ESP32 + PN532 (care nu merge).

Flux:
  1. Telefonul (Android) se conectează la ws://{IP_LAPTOP}:8090/pay
  2. Serverul trimite cererea de plată (sumă, nonce, timestamp)
  3. Telefonul răspunde cu {dpan, atc, mac}
  4. Serverul trimite la Gateway pentru autorizare
  5. Trimite rezultatul înapoi la telefon

Pornire:
  pip install websockets httpx
  python tests/pos_wifi_server.py

  Sau cu sumă custom:
  python tests/pos_wifi_server.py --amount 150.00 --port 8090
============================================================
"""

import asyncio
import json
import uuid
import httpx
import argparse
import os
import sys
from datetime import datetime, timezone

try:
    import websockets
except ImportError:
    print("❌ Lipsă: pip install websockets")
    sys.exit(1)

# ── Configurare ───────────────────────────────────────────────────────────────

GATEWAY_URL   = os.getenv("GATEWAY_URL", "http://localhost:8001")
TERMINAL_ID   = os.getenv("TERMINAL_ID", "POS-WIFI-001")
WS_PORT       = int(os.getenv("WS_PORT", "8090"))
DEFAULT_AMOUNT_CENTS = 5000   # 50.00 RON

# ── Utilitare ─────────────────────────────────────────────────────────────────

def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def unique_nonce() -> str:
    return uuid.uuid4().hex[:8].upper()

def unique_idemp_key() -> str:
    return f"POS-WIFI-{uuid.uuid4().hex[:12].upper()}"

# ── Handler conexiune WebSocket ────────────────────────────────────────────────

async def handle_payment(websocket, amount_cents: int):
    client_ip = websocket.remote_address[0]
    print(f"\n📱 Telefon conectat: {client_ip}")

    # Pasul 1: Trimitem cererea de plată
    nonce     = unique_nonce()
    timestamp = now_iso()

    request_msg = json.dumps({
        "type":         "REQUEST",
        "amount_cents": amount_cents,
        "currency":     "RON",
        "nonce":        nonce,
        "timestamp":    timestamp
    })

    print(f"📤 Trimitere cerere: {amount_cents/100:.2f} RON | nonce={nonce}")
    await websocket.send(request_msg)

    # Pasul 2: Așteptăm răspunsul de la telefon (timeout 60s pentru biometrie)
    try:
        raw = await asyncio.wait_for(websocket.recv(), timeout=60.0)
    except asyncio.TimeoutError:
        print("⏱️  Timeout — telefonul nu a răspuns în 60s")
        await websocket.send(json.dumps({
            "type": "RESULT", "status": "declined", "reason": "Timeout"
        }))
        return

    try:
        response = json.loads(raw)
    except json.JSONDecodeError:
        print(f"❌ Răspuns invalid (nu e JSON): {raw}")
        await websocket.send(json.dumps({
            "type": "RESULT", "status": "declined", "reason": "Invalid response"
        }))
        return

    if response.get("type") != "RESPONSE":
        print(f"❌ Tip mesaj neașteptat: {response.get('type')}")
        return

    dpan = response.get("dpan", "")
    atc  = response.get("atc", 0)
    mac  = response.get("mac", "")

    print(f"📥 Răspuns primit: DPAN=...{dpan[-4:]} | ATC={atc} | MAC={mac[:16]}...")

    # Pasul 3: Autorizare la Gateway
    print(f"🔗 Trimitere la Gateway ({GATEWAY_URL})...")
    idemp_key = unique_idemp_key()

    gateway_body = {
        "dpan": dpan,
        "transaction": {
            "amount":             amount_cents,
            "currency":           "RON",
            "pos_nonce":          nonce,
            "terminal_timestamp": timestamp
        },
        "cryptogram": {
            "mac": mac,
            "atc": atc
        }
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{GATEWAY_URL}/api/v1/payments/authorize",
                json=gateway_body,
                headers={
                    "X-Idempotency-Key": idemp_key,
                    "X-Terminal-Id":     TERMINAL_ID
                }
            )

        resp_data = resp.json()
        print(f"🏦 Gateway: HTTP {resp.status_code} → {resp_data}")

        if resp.status_code == 200:
            status = resp_data.get("status", "DECLINED").lower()
            result_msg = json.dumps({"type": "RESULT", "status": status})
            print(f"{'✅ APROBAT' if status == 'approved' else '❌ REFUZAT'}")

        elif resp.status_code == 401:
            # Step-Up (CHALLENGE_REQUIRED) — pentru PoC tratăm ca declined
            result_msg = json.dumps({
                "type": "RESULT", "status": "declined",
                "reason": "Autentificare suplimentară necesară (Step-Up)"
            })
            print("🔐 CHALLENGE_REQUIRED (Step-Up)")

        else:
            error_code = resp_data.get("detail", {}).get("error_code", "UNKNOWN")
            result_msg = json.dumps({
                "type": "RESULT", "status": "declined",
                "reason": error_code
            })
            print(f"⚠️  Eroare Gateway: {error_code}")

    except httpx.ConnectError:
        print(f"❌ Nu pot ajunge la Gateway ({GATEWAY_URL}) — rulează docker compose up?")
        result_msg = json.dumps({
            "type": "RESULT", "status": "declined",
            "reason": "Gateway indisponibil"
        })
    except Exception as e:
        print(f"❌ Eroare neașteptată: {e}")
        result_msg = json.dumps({
            "type": "RESULT", "status": "declined", "reason": str(e)
        })

    # Pasul 4: Trimitem rezultatul la telefon
    await websocket.send(result_msg)
    print(f"📤 Rezultat trimis la telefon.")


# ── Main ──────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(description="POS WebSocket Server")
    parser.add_argument("--amount", type=float, default=DEFAULT_AMOUNT_CENTS / 100,
                        help="Suma de plată în RON (default: 50.00)")
    parser.add_argument("--port", type=int, default=WS_PORT,
                        help=f"Portul WebSocket (default: {WS_PORT})")
    parser.add_argument("--gateway", type=str, default=GATEWAY_URL,
                        help=f"URL Gateway (default: {GATEWAY_URL})")
    return parser.parse_args()


async def main():
    args = parse_args()
    amount_cents = int(round(args.amount * 100))
    port         = args.port

    # Detectăm IP-ul local pentru a-l afișa userului
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        local_ip = "localhost"

    print("=" * 55)
    print(f"  🖥️  POS Wi-Fi Server pornit")
    print(f"  Port WebSocket : {port}")
    print(f"  IP local       : {local_ip}")
    print(f"  Suma de plată  : {amount_cents/100:.2f} RON")
    print(f"  Gateway        : {args.gateway}")
    print(f"  Terminal ID    : {TERMINAL_ID}")
    print("=" * 55)
    print(f"\n  📱 Pe telefon, introdu IP-ul: {local_ip}")
    print(f"  Portul e setat automat la {port}\n")

    async def handler(websocket):
        try:
            await handle_payment(websocket, amount_cents)
        except websockets.exceptions.ConnectionClosed:
            print("📵 Telefon deconectat.")
        except Exception as e:
            print(f"❌ Eroare handler: {e}")

    async with websockets.serve(handler, "0.0.0.0", port):
        print(f"⏳ Așteptare conexiune telefon pe portul {port}...\n")
        await asyncio.Future()  # rulează indefinit


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n🛑 Server oprit.")
