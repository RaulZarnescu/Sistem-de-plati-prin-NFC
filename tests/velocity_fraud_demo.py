#!/usr/bin/env python3
"""
velocity_fraud_demo.py — Demo Scenariul 2: Velocity Fraud Detection

Trimite 8 tranzacții consecutive BCR pentru a demonstra escaladarea
scorului de risc: 0 → APPROVED → CHALLENGE_REQUIRED → DECLINED.

Utilizare:
    # Demo rapid (2s interval, resetare automată Redis):
    python tests/velocity_fraud_demo.py

    # Demo realist (90s interval ≈ 14 minute):
    DEMO_INTERVAL=90 python tests/velocity_fraud_demo.py

Resetare manuală Redis dacă este nevoie:
    docker exec nfc-redis-master redis-cli -a <REDIS_PASSWORD> \\
        DEL velocity:<PAN> risk:<PAN> amounts:<PAN>
"""

import os
import sys
import time
import hmac as hmac_lib
import hashlib
import uuid
from datetime import datetime, timezone

# Forțăm UTF-8 pe stdout/stderr (necesar pe Windows cu terminal cp1252)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

try:
    import httpx
except ImportError:
    print("❌ Lipsește httpx. Instalează cu: pip install httpx")
    sys.exit(1)

try:
    from dotenv import load_dotenv
    load_dotenv(
        dotenv_path=os.path.join(os.path.dirname(__file__), "..", ".env"),
        override=False,
    )
except ImportError:
    pass  # variabilele trebuie setate manual dacă python-dotenv lipsește


# ============================================================
# CONFIGURARE
# ============================================================

GATEWAY_URL = os.getenv("TEST_GATEWAY_URL", "http://localhost:8001")
TERMINAL_ID = "POS-DEMO-ONLINE-001"

# DPAN BCR seeded în TSP (funcționează fără enrollment suplimentar).
# Mapează la PAN 5000002222222222 (BCR).
# Înlocuiește cu DPAN-ul enrolled pentru PAN 5105105105105100 dacă este disponibil.
DPAN_BCR = os.getenv("DPAN_BCR_DEMO", "5000000000000002")

# PAN folosit pentru resetarea cheilor Redis (velocity:{PAN}, risk:{PAN}, amounts:{PAN})
PAN_BCR = os.getenv("PAN_BCR_DEMO", "5000002222222222")

AMOUNT_CENTS = 5000   # 50 RON per tranzacție
CURRENCY = "RON"
INTERVAL_SECONDS = float(os.getenv("DEMO_INTERVAL", "2"))  # default 2s (rapid demo)

hex_key = os.getenv("BANK_BCR_HMAC_KEY", "")
if not hex_key:
    print("❌ BANK_BCR_HMAC_KEY nu este setată. Verifică fișierul .env")
    sys.exit(1)

try:
    HMAC_KEY = bytes.fromhex(hex_key)
except ValueError:
    print(f"❌ BANK_BCR_HMAC_KEY nu este hex valid: {hex_key[:20]}...")
    sys.exit(1)


# ============================================================
# UTILITARE CRIPTOGRAFICE (identice cu shared/crypto_utils.py)
# ============================================================

def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def derive_session_key(master_key: bytes, atc: int) -> bytes:
    """Step 1 din formula 2-step HMAC: Session_Key = HMAC-SHA256(master_key, str(atc))."""
    return hmac_lib.new(
        key=master_key,
        msg=str(atc).encode("utf-8"),
        digestmod=hashlib.sha256,
    ).digest()


def compute_mac(master_key: bytes, amount_cents: int, currency: str,
                pos_nonce: str, terminal_timestamp: str, atc: int) -> str:
    """
    Formula 2-step HMAC (identică cu shared/crypto_utils.py și Android CryptoUtils.kt):
      Step 1: session_key = HMAC-SHA256(master_key, str(atc))
      Step 2: mac_input   = f"{amount_cents}|{currency}|{pos_nonce}|{terminal_timestamp}|{atc}"
              mac         = HMAC-SHA256(session_key, mac_input.encode('utf-8')).hexdigest()
    """
    session_key = derive_session_key(master_key, atc)
    mac_input = f"{amount_cents}|{currency}|{pos_nonce}|{terminal_timestamp}|{atc}"
    return hmac_lib.new(
        session_key,
        mac_input.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


# ============================================================
# RESETARE REDIS
# ============================================================

def reset_redis_fraud_state(pan: str) -> bool:
    """
    Șterge cheile de fraudă Redis pentru PAN-ul dat.
    Încearcă mai întâi docker exec (de pe laptop), apoi conexiune directă Python.
    """
    import subprocess

    redis_pw = os.getenv("REDIS_PASSWORD", "")
    keys = [f"velocity:{pan}", f"risk:{pan}", f"amounts:{pan}"]

    # Strategie 1: docker exec (accesibil de pe laptop fără port Redis expus)
    try:
        cmd = [
            "docker", "exec", "nfc-redis-master",
            "redis-cli",
            *(["-a", redis_pw, "--no-auth-warning"] if redis_pw else []),
            "DEL", *keys,
        ]
        result = subprocess.run(cmd, capture_output=True, timeout=5, check=True)
        deleted = result.stdout.decode(errors="replace").strip()
        print(f"  ✅ Redis curățat ({deleted} chei șterse) pentru PAN {pan}")
        return True
    except Exception:
        pass

    # Strategie 2: conexiune Python directă (din interiorul containerului)
    try:
        import redis as redis_mod  # type: ignore
        r = redis_mod.Redis(
            host=os.getenv("REDIS_HOST", "redis-master"),
            port=int(os.getenv("REDIS_PORT", "6379")),
            password=redis_pw if redis_pw else None,
        )
        deleted = r.delete(*keys)
        r.close()
        print(f"  ✅ Redis curățat ({deleted} chei șterse) pentru PAN {pan}")
        return True
    except Exception as e:
        print(f"  ⚠️  Nu s-a putut curăța Redis: {e}")
        print(f"     Curăță manual: docker exec nfc-redis-master redis-cli -a {redis_pw} DEL {' '.join(keys)}")
        return False


# ============================================================
# TRANZACȚIE INDIVIDUALĂ
# ============================================================

def send_transaction(txn_num: int, base_atc: int) -> dict:
    """
    Construiește și trimite o cerere de autorizare la Gateway.

    ATC = int(time.time() * 1000) + txn_num
      → garantat crescător față de orice ATC stocat anterior
      → previne INVALID_ATC_REPLAY între rulări consecutive

    Returnează dict cu: txn_num, atc, http_status, status, risk_score, error (opțional).
    """
    atc = base_atc + txn_num
    nonce = uuid.uuid4().hex[:8].upper()
    timestamp = _now_iso()
    mac = compute_mac(HMAC_KEY, AMOUNT_CENTS, CURRENCY, nonce, timestamp, atc)
    idempotency_key = f"SC2-VEL-{txn_num:03d}-{uuid.uuid4().hex[:6].upper()}"

    payload = {
        "dpan": DPAN_BCR,
        "transaction": {
            "amount":             AMOUNT_CENTS,
            "currency":           CURRENCY,
            "pos_nonce":          nonce,
            "terminal_timestamp": timestamp,
        },
        "cryptogram": {"mac": mac, "atc": atc},
    }

    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(
                f"{GATEWAY_URL}/api/v1/payments/authorize",
                headers={
                    "X-Idempotency-Key": idempotency_key,
                    "X-Terminal-Id":     TERMINAL_ID,
                },
                json=payload,
            )

        data = resp.json() if resp.content else {}

        if resp.status_code == 200:
            status = data.get("status", "UNKNOWN")
        elif resp.status_code == 401:
            status = "CHALLENGE_REQUIRED"
        else:
            detail = data.get("detail", {})
            error_code = detail.get("error_code", "ERROR") if isinstance(detail, dict) else str(resp.status_code)
            status = error_code

        return {
            "txn_num":        txn_num,
            "atc":            atc,
            "http_status":    resp.status_code,
            "status":         status,
            "risk_score":     data.get("risk_score", "N/A"),
            "auth_code":      data.get("auth_code", ""),
            "idempotency_key": idempotency_key,
        }

    except Exception as e:
        return {
            "txn_num":        txn_num,
            "atc":            base_atc + txn_num,
            "http_status":    -1,
            "status":         "CONNECTION_ERROR",
            "risk_score":     "N/A",
            "auth_code":      "",
            "error":          str(e),
            "idempotency_key": idempotency_key,
        }


# ============================================================
# MAIN
# ============================================================

STATUS_ICON = {
    "APPROVED":           "✅",
    "CHALLENGE_REQUIRED": "🔐",
    "DECLINED":           "❌",
    "CONNECTION_ERROR":   "💥",
}


def main():
    print("\n" + "=" * 65)
    print("🚨 DEMO SC2 — Velocity Fraud Detection (BCR)")
    print("=" * 65)
    print(f"Gateway:    {GATEWAY_URL}")
    print(f"DPAN:       {DPAN_BCR}")
    print(f"PAN Redis:  {PAN_BCR}")
    print(f"Sumă/txn:   {AMOUNT_CENTS / 100:.2f} RON")
    print(f"Interval:   {INTERVAL_SECONDS}s între tranzacții")
    if INTERVAL_SECONDS < 10:
        print("  (mod rapid — scorul crește imediat, fără decay)")
    else:
        print(f"  (mod realist — {INTERVAL_SECONDS * 8 / 60:.1f} min total)")
    print("=" * 65)

    print("\n🧹 Resetare stare fraudă Redis...")
    reset_redis_fraud_state(PAN_BCR)

    # ATC bazat pe millisecunde — garantat > orice ATC din rulări anterioare
    base_atc = int(time.time() * 1000)
    print(f"\n📤 Trimitere 8 tranzacții (ATC base: {base_atc})...\n")

    print(f"{'Nr':>2}  {'ATC':>18}  {'HTTP':>4}  {'Decizie':<22}  {'Risk':>6}")
    print("-" * 65)

    results = []
    for i in range(1, 9):
        result = send_transaction(i, base_atc)
        results.append(result)

        icon = STATUS_ICON.get(result["status"], "❓")
        error_info = f"  ← {result.get('error', '')}" if result["status"] == "CONNECTION_ERROR" else ""

        print(
            f"{i:>2}  {result['atc']:>18}  {result['http_status']:>4}  "
            f"{icon} {result['status']:<20}  {str(result['risk_score']):>6}"
            f"{error_info}"
        )

        if i < 8:
            time.sleep(INTERVAL_SECONDS)

    # Sumar
    print("\n" + "=" * 65)
    approved = sum(1 for r in results if r["status"] == "APPROVED")
    step_up  = sum(1 for r in results if r["status"] == "CHALLENGE_REQUIRED")
    declined = sum(1 for r in results if r["status"] == "DECLINED")
    errors   = sum(1 for r in results if r["status"] in ("CONNECTION_ERROR", "ERROR"))

    print(f"Rezultat: ✅ {approved} APPROVED  🔐 {step_up} STEP-UP  ❌ {declined} DECLINED", end="")
    if errors:
        print(f"  💥 {errors} ERORI")
    else:
        print()
    print("=" * 65)

    if declined > 0:
        print("\n✅ Demo SC2 reușit — Fraud Engine a escaladat la DECLINED!")
        print("   Verifică în Grafana escaladarea scorului de risc per tranzacție.")
        print("   Verifică în pgAdmin: SELECT pan, status, risk_score FROM transactions ORDER BY created_at DESC;")
    elif step_up > 0:
        print("\n🔐 STEP-UP detectat — Fraud Engine funcționează.")
        print("   Rulează din nou fără resetare Redis pentru a ajunge la DECLINED.")
    elif errors > 0:
        print("\n💥 Erori de conexiune — verifică că sistemul Docker este pornit.")
        print(f"   Gateway URL: {GATEWAY_URL}")
        print("   Comandă verificare: docker compose ps")
    else:
        print("\n⚠️  Nu s-a detectat fraud — verifică că Redis s-a resetat corect")
        print("   și că DPAN-ul este valid pentru bancă BCR (BIN routing corect).")

    print()


if __name__ == "__main__":
    main()


# ============================================================
# INSTRUCȚIUNI DE RULARE
# ============================================================
# Prerequisite:
#   pip install httpx python-dotenv
#   pip install redis  # opțional, pentru resetare Redis din container
#
# Variabile de mediu necesare (încărcate automat din .env):
#   BANK_BCR_HMAC_KEY  — cheia HMAC pentru banca BCR
#   REDIS_PASSWORD     — parola Redis (pentru resetare automată)
#   TEST_GATEWAY_URL   — URL Gateway (default: http://localhost:8001)
#
# Variabile opționale pentru DPAN personalizat:
#   DPAN_BCR_DEMO      — DPAN BCR (default: 5000000000000002, seeded în TSP)
#   PAN_BCR_DEMO       — PAN asociat pentru reset Redis (default: 5000002222222222)
#   DEMO_INTERVAL      — interval între tranzacții în secunde (default: 2)
#
# Demo rapid (default 2s):
#   python tests/velocity_fraud_demo.py
#
# Demo realist (90s interval ≈ 14 minute):
#   $env:DEMO_INTERVAL=90; python tests/velocity_fraud_demo.py
#
# Cu DPAN enrolled pentru PAN 5105105105105100 (vedere pgAdmin istorică completă):
#   $env:DPAN_BCR_DEMO="<DPAN_DIN_TSP>"; $env:PAN_BCR_DEMO="5105105105105100"
#   python tests/velocity_fraud_demo.py
#
# Resetare manuală Redis (PowerShell):
#   docker exec nfc-redis-master redis-cli -a Ion_Filotti_Cantacuzino `
#     DEL velocity:5000002222222222 risk:5000002222222222 amounts:5000002222222222
