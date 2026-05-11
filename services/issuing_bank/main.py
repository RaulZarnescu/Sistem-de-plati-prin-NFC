# ============================================================
# main.py — Issuing Bank (Banca Emitentă)
#
# Responsabilități:
#   1. Validează criptograma HMAC (AC-02) pentru a asigura integritatea sumei.
#   2. Evaluează scorul de fraudă pe baza risk_level.
#   3. Autorizează sau respinge tranzacția.
# ============================================================

import sys
sys.path.append("/app")

import os
import json
import re
import uuid
import logging
import math
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel, Field, field_validator
from dotenv import load_dotenv
from contextlib import asynccontextmanager

from shared.crypto_utils import verify_mac

load_dotenv()

_key_hex = os.getenv("ISSUING_BANK_HMAC_MASTER_KEY", "")
HMAC_KEY = bytes.fromhex(_key_hex) if _key_hex else b""

# --- CONFIGURAREA LOG-URILOR CU MASCARE PII ---

class MaskedJSONFormatter(logging.Formatter):
    """
    Formatter personalizat care convertește log-urile în JSON
    și maschează automat numerele de card (PAN/DPAN) conform PCI-DSS.
    """
    def format(self, record: logging.LogRecord) -> str:
        def mask_pan(match):
            pan = match.group(0)
            if len(pan) >= 13 and len(pan) <= 19:
                return f"{pan[:4]}********{pan[-4:]}"
            return pan

        message = record.getMessage()
        masked_message = re.sub(r'\b\d{13,19}\b', mask_pan, message)

        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "service": "issuing-bank",
            "event_type": getattr(record, "event_type", "GENERAL"),
            "message": masked_message,
        }
        
        # Extracție avansată pentru logurile de access HTTP ale Uvicorn
        if record.name == "uvicorn.access":
            log_entry["event_type"] = "HTTP_ACCESS"
            if record.args and len(record.args) >= 5:
                try:
                    log_entry["http_method"] = record.args[1]
                    log_entry["http_path"] = record.args[2]
                    log_entry["http_status"] = record.args[4]
                    log_entry["client_addr"] = record.args[0]
                except Exception:
                    pass
        
        if hasattr(record, "trace_id"):
            log_entry["trace_id"] = record.trace_id
            
        return json.dumps(log_entry, ensure_ascii=False)


logger = logging.getLogger("issuing_bank")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(MaskedJSONFormatter())

if not logger.handlers:
    logger.addHandler(handler)

# Stocare ATC per PAN pentru protecție anti-replay (Cap. 7.6, T1)
# LIMITARE PoC: ATC-ul trebuie stocat persistent (PostgreSQL cu FOR UPDATE).
# La restart Docker, protecția anti-replay se pierde complet.
# Producție: SELECT last_atc FROM accounts WHERE pan = ? FOR UPDATE
last_atc_store: dict[str, int] = {}

# Store-uri in-memory pentru Fraud Engine (vor fi înlocuite cu PostgreSQL)
# LIMITARE PoC: se resetează la restart Docker

# pan -> lista de unix timestamps (pentru Velocity, Cap. 6.1)
transaction_history: dict[str, list[float]] = {}

# pan -> lista de sume (pentru media Amount Deviation, Cap. 6.2)
amount_history: dict[str, list[int]] = {}

# pan -> (scor_acumulat, timestamp_ultima_tranzactie) (pentru Risk Decay, Cap. 6.3)
risk_profiles: dict[str, tuple[float, datetime]] = {}

# --- MODELE PYDANTIC ---

class TransactionData(BaseModel):
    amount: int = Field(..., description="Suma tranzacției in bani")
    currency: str = Field(..., description="Moneda (ex: RON)")
    pos_nonce: str = Field(..., description="Nonce generat de POS")
    terminal_timestamp: str = Field(..., description="Timestamp terminal")
    
    @field_validator("terminal_timestamp")
    @classmethod
    def validate_timestamp(cls, v: str) -> str:
        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
            return v
        except ValueError:
            raise ValueError("terminal_timestamp trebuie să fie ISO 8601 valid")

class CryptogramData(BaseModel):
    mac: str = Field(..., description="HMAC-SHA256")
    atc: int = Field(..., description="Application Transaction Counter")

class IssuingBankRequest(BaseModel):
    pan: str = Field(..., description="Primary Account Number (Decriptat de TSP)")
    risk_level: int = Field(..., description="Scorul de risc al DPAN-ului de la TSP")
    transaction: TransactionData
    cryptogram: CryptogramData
    idempotency_key: str = Field(..., description="ID-ul unic de idempotență")
    terminal_id: str = Field(..., description="ID-ul terminalului POS")

class IssuingBankResponse(BaseModel):
    status: str = Field(..., description="APPROVED | DECLINED | CHALLENGE_REQUIRED")
    transaction_id: str = Field(..., description="ID-ul unic al tranzacției")
    auth_code: Optional[str] = Field(None, description="Codul de autorizare")
    risk_score: Optional[int] = Field(None, description="Scorul de risc calculat intern")
    processed_at: str = Field(..., description="Timestamp procesare")


# --- APLICAȚIA FASTAPI ---

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Suprascriem logger-ele implicite din uvicorn pentru a folosi formatul JSON
    for logger_name in ("uvicorn", "uvicorn.access", "uvicorn.error"):
        u_logger = logging.getLogger(logger_name)
        u_logger.handlers = [handler]
        u_logger.propagate = False

    logger.info("Issuing Bank pornit", extra={"event_type": "SERVICE_STARTUP"})
    
    if not HMAC_KEY:
        logger.error("ISSUING_BANK_HMAC_MASTER_KEY lipsește din mediu!", extra={"event_type": "CONFIG_ERROR"})
        
    yield

app = FastAPI(title="NFC Issuing Bank", version="1.0.0", lifespan=lifespan)


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "issuing-bank",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.post("/api/v1/transactions/authorize", response_model=IssuingBankResponse)
async def authorize_transaction(payload: IssuingBankRequest):
    trace_id = payload.idempotency_key
    
    logger.info(
        f"Cerere autorizare primită pentru PAN-ul: {payload.pan} de la terminalul: {payload.terminal_id}",
        extra={"event_type": "AUTH_REQUEST_RECEIVED", "trace_id": trace_id}
    )
    
    # 1. Extragem datele pentru calculul HMAC
    amount_cents = payload.transaction.amount
    
    # 2. Verificăm MAC-ul (AC-02)
    is_valid_mac = verify_mac(
        session_key=HMAC_KEY,
        amount_cents=amount_cents,
        currency=payload.transaction.currency,
        pos_nonce=payload.transaction.pos_nonce,
        terminal_timestamp=payload.transaction.terminal_timestamp,
        atc=payload.cryptogram.atc,
        received_mac=payload.cryptogram.mac
    )
    
    if not is_valid_mac:
        logger.error(
            f"Validare MAC EȘUATĂ pentru PAN: {payload.pan}. Posibilă alterare a sumei!",
            extra={"event_type": "MAC_VALIDATION_FAILED", "trace_id": trace_id}
        )
        # Dacă MAC-ul pică, tranzacția este imediat respinsă ca suspectă de fraudă.
        raise HTTPException(
            status_code=400,
            detail={
                "error_code": "INVALID_CRYPTOGRAM",
                "message": "Validarea criptogramei a eșuat. Tranzacție refuzată.",
                "action_required": "DECLINE_TRANSACTION"
            }
        )
        
    logger.info(
        "Criptograma validată cu succes. Integritatea sumei este confirmată.",
        extra={"event_type": "CRYPTO_VALIDATED", "trace_id": trace_id}
    )
    
    # --- VALIDARE ATC (Anti-Replay, Cap. 7.6) ---
    received_atc = payload.cryptogram.atc
    stored_atc = last_atc_store.get(payload.pan, -1)
    
    if received_atc <= stored_atc:
        logger.error(
            f"ATC invalid: primit {received_atc}, stocat {stored_atc}. Posibil Replay Attack.",
            extra={"event_type": "REPLAY_ATTACK_DETECTED", "trace_id": trace_id}
        )
        raise HTTPException(
            status_code=400,
            detail={
                "error_code": "INVALID_CRYPTOGRAM",
                "message": "ATC invalid. Tranzacție refuzată.",
                "action_required": "DECLINE_TRANSACTION"
            }
        )
    
    # ATC valid — actualizăm referința
    last_atc_store[payload.pan] = received_atc

    # --- FRAUD ENGINE COMPLET (Cap. 6.1, 6.2, 6.3) ---
    tsp_risk = payload.risk_level
    now = datetime.now(timezone.utc)

    # === RISK DECAY (Cap. 6.3) ===
    # Aplicat ÎNAINTE de a adăuga riscul noii tranzacții
    # Formula: RiskScore = RiskScore_curent × e^(-λΔt), λ=0.173, half-life=4h
    stored_score, last_ts = risk_profiles.get(payload.pan, (0.0, None))

    if last_ts is not None:
        delta_t_hours = (now - last_ts).total_seconds() / 3600
        decayed_base = stored_score * math.exp(-0.173 * delta_t_hours)
    else:
        decayed_base = 0.0

    # === FACTOR V — VELOCITY (W1=30) ===
    history = transaction_history.get(payload.pan, [])
    recent = [ts for ts in history if (now.timestamp() - ts) <= 600]
    velocity = len(recent)  # tranzacții anterioare, fără cea curentă
    n1 = min(velocity / 5.0, 1.0)
    velocity_contribution = 30 * n1

    # Actualizăm istoricul după calcul
    recent.append(now.timestamp())
    transaction_history[payload.pan] = recent

    # === FACTOR A — AMOUNT DEVIATION (W2=40) ===
    amounts = amount_history.get(payload.pan, [])
    current_amount = payload.transaction.amount

    if not amounts:
        # Primul utilizator — nu avem baseline, N2=0
        n2 = 0.0
    else:
        avg_amount = sum(amounts) / len(amounts)
        if avg_amount == 0:
            n2 = 0.0
        else:
            ratio = current_amount / avg_amount
            raw = 1 / (1 + math.exp(-0.5 * (ratio - 1)))
            n2 = max(0.0, min(1.0, (raw - 0.5) * 2))
            # shift cu -0.5, rescalezi × 2, clampezi la [0, 1]
            # duce la: ratio=1 → 0.0, ratio=10 → ~0.978

    amount_contribution = 40 * n2

    # Actualizăm istoricul sumelor după calcul
    amounts.append(current_amount)
    amount_history[payload.pan] = amounts

    # === FACTOR L — LOCATION VELOCITY (W3=30) ===
    # TODO: Necesită coordonate GPS de la POS — neimplementat în PoC.
    # N3 = 0 până la integrarea hardware ESP32.
    location_contribution = 0.0

    # === SCOR FINAL ===
    # decayed_base = riscul acumulat din tranzacțiile anterioare, degradat în timp
    # tsp_risk = riscul static al DPAN-ului (proprietate a tokenului, nu se degradează)
    new_accumulated = decayed_base + velocity_contribution + amount_contribution + location_contribution
    final_risk = int(min(new_accumulated + tsp_risk, 100))

    # Salvăm scorul acumulat (fără tsp_risk — acela e proprietatea tokenului)
    risk_profiles[payload.pan] = (new_accumulated, now)

    logger.info(
        f"Fraud scored. Decay base: {decayed_base:.1f}, Velocity: +{velocity_contribution:.1f} (T={velocity}), "
        f"Amount Dev: +{amount_contribution:.1f} (N2={n2:.2f}), TSP Risk: {tsp_risk}, Final: {final_risk}/100",
        extra={"event_type": "FRAUD_SCORED", "trace_id": trace_id}
    )

    if final_risk > 75:
        status = "DECLINED"
        auth_code = None
        logger.warning(
            f"Tranzacție RESPINSĂ. Risk score: {final_risk}",
            extra={"event_type": "TX_REJECTED", "trace_id": trace_id}
        )
    elif final_risk >= 40:
        logger.info(
            f"Step-Up Authentication cerut. Risk score: {final_risk}",
            extra={"event_type": "TX_STEP_UP", "trace_id": trace_id}
        )
        raise HTTPException(
            status_code=401,
            detail={
                "error_code": "CHALLENGE_REQUIRED",
                "risk_score": final_risk,
                "transaction_id": f"TXN-{uuid.uuid4().hex[:12].upper()}"
            }
        )
    else:
        status = "APPROVED"
        auth_code = str(uuid.uuid4())[:8].upper()
        # TODO: PoC — LEDGER_UPDATED logat fără scriere reală.
        # Producție: UPDATE accounts SET balance = balance - amount WHERE pan = ?
        logger.info(
            f"Tranzacție APROBATĂ. Risk score: {final_risk}",
            extra={"event_type": "LEDGER_UPDATED", "trace_id": trace_id}
        )

    # APPROVED și DECLINED returnează HTTP 200 — decizia bancară e business logic, nu eroare tehnică.
    # CHALLENGE_REQUIRED ridică excepție HTTP 401 (spec Cap. 6.2).
    return IssuingBankResponse(
        status=status,
        transaction_id=f"TXN-{uuid.uuid4().hex[:12].upper()}",
        auth_code=auth_code,
        risk_score=final_risk,
        processed_at=now.isoformat()
    )
