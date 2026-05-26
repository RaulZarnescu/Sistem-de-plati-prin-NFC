#!/usr/bin/env python3
"""
generate_demo_macs.py — Generează MAC-uri pre-calculate pentru demo-ul NFC Payment PoC.

Rulare (din interiorul containerului Gateway — are accesul la env vars și shared/):
    docker cp scripts/generate_demo_macs.py nfc-gateway:/tmp/
    docker exec nfc-gateway python /tmp/generate_demo_macs.py

Sau cu output JSON pur (pentru pipe):
    docker exec nfc-gateway python /tmp/generate_demo_macs.py | python -m json.tool

NOTĂ: MAC-urile produse de acest script sunt REPRODUCTIBILE (nonce și
timestamp fixe) — ideal pentru demo. În producție, ESP32 generează
nonce și timestamp noi la fiecare tranzacție → MAC unic.

Verificare: poți rula scriptul de mai multe ori — output-ul e identic
dacă cheile HMAC din .env nu s-au schimbat.
"""

import sys
import os
import hmac
import hashlib
import json
import textwrap

# Adaugă /app la sys.path pentru a importa shared/ din containerul Gateway
sys.path.insert(0, "/app")

# ──────────────────────────────────────────────────────────
# Import formula exactă din shared/crypto_utils.py
# ──────────────────────────────────────────────────────────
try:
    from shared.crypto_utils import compute_mac
    print("[INFO] shared.crypto_utils importat cu succes.", file=sys.stderr)
except ImportError:
    # Fallback dacă scriptul rulează în afara containerului
    print("[WARN] shared.crypto_utils indisponibil — folosesc implementare locală.", file=sys.stderr)
    def compute_mac(session_key, amount_cents, currency, pos_nonce, terminal_timestamp, atc):
        mac_input = "|".join([str(amount_cents), currency, pos_nonce, terminal_timestamp, str(atc)])
        return hmac.new(key=session_key, msg=mac_input.encode("utf-8"), digestmod=hashlib.sha256).hexdigest()


# ──────────────────────────────────────────────────────────
# Citire chei HMAC din environment
# (injectate de Docker Compose din .env)
# ──────────────────────────────────────────────────────────
def load_bank_key(env_var: str) -> bytes:
    """
    Citește o cheie HMAC din environment și o convertește la bytes.
    Dacă valoarea nu e hex valid, returnează b'' și afișează un warning.
    """
    val = os.getenv(env_var, "")
    if not val:
        print(f"[WARN] {env_var} lipsește din environment!", file=sys.stderr)
        return b""
    try:
        key_bytes = bytes.fromhex(val)
        print(f"[INFO] {env_var}: {len(key_bytes)} bytes încărcați.", file=sys.stderr)
        return key_bytes
    except ValueError:
        print(
            f"[ERROR] {env_var} nu este hex valid!\n"
            f"        Valoare: {val[:20]}...\n"
            f"        Caractere invalide detectate. Folosesc b'' — MAC-urile pentru această bancă\n"
            f"        vor fi calculate cu cheie goală (vor funcționa cu issuing bank care face același fallback).\n"
            f"        REMEDIERE: înlocuiți valoarea din .env cu 64 caractere hex (0-9, a-f).\n"
            f"        Generare cheie: python -c \"import secrets; print(secrets.token_hex(32))\"",
            file=sys.stderr
        )
        return b""


BT_KEY  = load_bank_key("BANK_BT_HMAC_KEY")
BCR_KEY = load_bank_key("BANK_BCR_HMAC_KEY")
ING_KEY = load_bank_key("BANK_ING_HMAC_KEY")


# ──────────────────────────────────────────────────────────
# Date fixe per scenariu (nonce și timestamp FIXE = MAC reproductibil)
# ──────────────────────────────────────────────────────────
GATEWAY_URL = "http://localhost:8001"  # schimbați cu https://localhost:8443 pt Android
TERMINAL_TS = "2026-06-01T10:00:00Z"  # timestamp fix pentru reproductibilitate

SCENARIOS = {
    "scenario_1_happy_path": {
        "description": "Happy Path Normal — 10 tranzacții APPROVED, risk <= 12",
        "bank": "BT",
        "key": BT_KEY,
        "pan_for_reference": "4000001111111118",
        "exp_month": "12",
        "exp_year": "28",
        "dpan": "<<COMPLETAȚI_DUPĂ_ENROLL>>",
        "amount_cents": 8750,
        "currency": "RON",
        "pos_nonce": "DEMO0001",
        "terminal_timestamp": TERMINAL_TS,
        "atc": 1001,
        "terminal_id": "POS-DEMO-BUC-001",
        "idempotency_key": "DEMO-SC1-IKEA-001",
        "expected_status": "APPROVED",
        "note": "ATC 1001 — prima tranzacție demo. Dacă a mai fost folosit, incrementați ATC.",
    },
    "scenario_2_velocity_fraud": {
        "description": "Velocity Fraud — 8 tranzacții rapide, risk 0→91 în 14 minute",
        "bank": "BCR",
        "key": BCR_KEY,
        "pan_for_reference": "5105105105105100",
        "exp_month": "12",
        "exp_year": "28",
        "dpan": "<<COMPLETAȚI_DUPĂ_ENROLL>>",
        "amount_cents": 5000,
        "currency": "RON",
        "pos_nonce": "DEMO0002",
        "terminal_timestamp": TERMINAL_TS,
        "atc": 2001,   # Incrementat automat mai jos pentru fiecare sub-cerere
        "terminal_id": "POS-DEMO-ONLINE-001",
        "idempotency_key": "DEMO-SC2-VEL-001",
        "expected_status": "APPROVED → CHALLENGE_REQUIRED → DECLINED",
        "note": (
            "Trimiteți 8 cereri cu ATC 2001-2008 și idempotency_key diferite.\n"
            "Folosiți scriptul de velocity de mai jos."
        ),
    },
    "scenario_3_amount_deviation": {
        "description": "Amount Deviation — 4500 RON anomalie față de media 44 RON",
        "bank": "ING",
        "key": ING_KEY,
        "pan_for_reference": "5200828282828210",
        "exp_month": "12",
        "exp_year": "28",
        "dpan": "<<COMPLETAȚI_DUPĂ_ENROLL>>",
        "amount_cents": 450000,
        "currency": "RON",
        "pos_nonce": "DEMO0003",
        "terminal_timestamp": TERMINAL_TS,
        "atc": 3007,   # Vine după 6 tranzacții normale (atc 3001-3006)
        "terminal_id": "POS-DEMO-ING-001",
        "idempotency_key": "DEMO-SC3-AMT-007",
        "expected_status": "CHALLENGE_REQUIRED (risk ~58)",
        "note": (
            "Înainte de această tranzacție, trimiteți 6 normale (30-90 RON, atc 3001-3006).\n"
            "MAC-urile pentru tranzacțiile pre-warm sunt mai jos în 'scenario_3_prewarm'."
        ),
    },
    "scenario_4_insufficient_funds": {
        "description": "Sold Insuficient — 50 RON disponibil, cerere 100 RON",
        "bank": "BT",
        "key": BT_KEY,
        "pan_for_reference": "4000002222222224",
        "exp_month": "06",
        "exp_year": "27",
        "dpan": "<<COMPLETAȚI_DUPĂ_ENROLL>>",
        "amount_cents": 10000,
        "currency": "RON",
        "pos_nonce": "DEMO0004",
        "terminal_timestamp": TERMINAL_TS,
        "atc": 4001,
        "terminal_id": "POS-DEMO-ATM-001",
        "idempotency_key": "DEMO-SC4-INS-001",
        "expected_status": "DECLINED (INSUFFICIENT_FUNDS)",
        "note": "Sold cont: 5000 cenți (50 RON). Cerere: 10000 cenți (100 RON).",
    },
}

# Pre-warm SC3: 6 tranzacții normale pentru a construi istoricul Redis
SC3_PREWARM = [
    (3200, "DEMO3001", 3001, "DEMO-SC3-PRE-001"),
    (4100, "DEMO3002", 3002, "DEMO-SC3-PRE-002"),
    (2800, "DEMO3003", 3003, "DEMO-SC3-PRE-003"),
    (8900, "DEMO3004", 3004, "DEMO-SC3-PRE-004"),
    (5600, "DEMO3005", 3005, "DEMO-SC3-PRE-005"),
    (1900, "DEMO3006", 3006, "DEMO-SC3-PRE-006"),
]

# SC2: 8 velocity tranzacții
SC2_VELOCITY = [
    (5000, f"DEMO200{i+1}", 2001 + i, f"DEMO-SC2-VEL-{i+1:03d}")
    for i in range(8)
]


def build_curl(dpan: str, amount: int, currency: str, nonce: str, ts: str,
               atc: int, mac: str, terminal_id: str, idempotency_key: str) -> str:
    body = json.dumps({
        "dpan": dpan,
        "transaction": {
            "amount": amount,
            "currency": currency,
            "pos_nonce": nonce,
            "terminal_timestamp": ts
        },
        "cryptogram": {
            "mac": mac,
            "atc": atc
        }
    }, separators=(',', ':'))
    return (
        f"curl.exe -s -X POST {GATEWAY_URL}/api/v1/payments/authorize "
        f"-H \"Content-Type: application/json\" "
        f"-H \"X-Idempotency-Key: {idempotency_key}\" "
        f"-H \"X-Terminal-Id: {terminal_id}\" "
        f"-d '{body}'"
    )


# ──────────────────────────────────────────────────────────
# Calculare MAC-uri și construire output
# ──────────────────────────────────────────────────────────
output = {}

for sc_key, sc in SCENARIOS.items():
    mac_val = compute_mac(
        session_key=sc["key"],
        amount_cents=sc["amount_cents"],
        currency=sc["currency"],
        pos_nonce=sc["pos_nonce"],
        terminal_timestamp=sc["terminal_timestamp"],
        atc=sc["atc"]
    )
    curl_cmd = build_curl(
        dpan=sc["dpan"],
        amount=sc["amount_cents"],
        currency=sc["currency"],
        nonce=sc["pos_nonce"],
        ts=sc["terminal_timestamp"],
        atc=sc["atc"],
        mac=mac_val,
        terminal_id=sc["terminal_id"],
        idempotency_key=sc["idempotency_key"]
    )
    output[sc_key] = {
        "description": sc["description"],
        "bank": sc["bank"],
        "pan_for_reference": sc["pan_for_reference"],
        "exp_month": sc["exp_month"],
        "exp_year": sc["exp_year"],
        "dpan": sc["dpan"],
        "amount_ron": sc["amount_cents"] / 100,
        "amount_cents": sc["amount_cents"],
        "currency": sc["currency"],
        "pos_nonce": sc["pos_nonce"],
        "terminal_timestamp": sc["terminal_timestamp"],
        "atc": sc["atc"],
        "mac": mac_val,
        "expected_status": sc["expected_status"],
        "curl_command": curl_cmd,
        "note": sc["note"],
    }

# SC2 velocity — toate 8 MACs
velocity_cmds = []
sc2_dpan = SCENARIOS["scenario_2_velocity_fraud"]["dpan"]
sc2_tid  = SCENARIOS["scenario_2_velocity_fraud"]["terminal_id"]
for amount, nonce, atc, idem_key in SC2_VELOCITY:
    mac_val = compute_mac(BCR_KEY, amount, "RON", nonce, TERMINAL_TS, atc)
    cmd = build_curl(sc2_dpan, amount, "RON", nonce, TERMINAL_TS, atc, mac_val, sc2_tid, idem_key)
    velocity_cmds.append({
        "atc": atc, "nonce": nonce, "mac": mac_val,
        "idempotency_key": idem_key, "curl_command": cmd
    })
output["scenario_2_velocity_all_8_requests"] = velocity_cmds

# SC3 prewarm — 6 tranzacții normale
prewarm_cmds = []
sc3_dpan = SCENARIOS["scenario_3_amount_deviation"]["dpan"]
sc3_tid  = SCENARIOS["scenario_3_amount_deviation"]["terminal_id"]
for amount, nonce, atc, idem_key in SC3_PREWARM:
    mac_val = compute_mac(ING_KEY, amount, "RON", nonce, TERMINAL_TS, atc)
    cmd = build_curl(sc3_dpan, amount, "RON", nonce, TERMINAL_TS, atc, mac_val, sc3_tid, idem_key)
    prewarm_cmds.append({
        "atc": atc, "amount_cents": amount, "amount_ron": amount / 100,
        "nonce": nonce, "mac": mac_val,
        "idempotency_key": idem_key, "curl_command": cmd
    })
output["scenario_3_prewarm_6_normal_txns"] = prewarm_cmds

# ──────────────────────────────────────────────────────────
# Output JSON
# ──────────────────────────────────────────────────────────
print(json.dumps(output, indent=2, ensure_ascii=False))
