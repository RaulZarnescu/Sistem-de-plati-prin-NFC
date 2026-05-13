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
import redis.asyncio as aioredis

redis_client: Optional[aioredis.Redis] = None

from shared.crypto_utils import verify_mac

load_dotenv()

_key_hex = os.getenv("ISSUING_BANK_HMAC_MASTER_KEY", "")
try:
    HMAC_KEY = bytes.fromhex(_key_hex) if _key_hex else b""
except ValueError:
    HMAC_KEY = b""

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
            "service": "issuing-bank-b",
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


logger = logging.getLogger("issuing_bank_b")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(MaskedJSONFormatter())

if not logger.handlers:
    logger.addHandler(handler)

# --- MODELE PYDANTIC ---

class TransactionData(BaseModel):
    amount: int = Field(..., description="Suma tranzacției în cenți (ex: 5000 pentru 50 RON)")
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
    risk_level: int = Field(0, description="Scorul de risc al DPAN-ului de la TSP")
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
    global redis_client
    # Suprascriem logger-ele implicite din uvicorn pentru a folosi formatul JSON
    for logger_name in ("uvicorn", "uvicorn.access", "uvicorn.error"):
        u_logger = logging.getLogger(logger_name)
        u_logger.handlers = [handler]
        u_logger.propagate = False

    logger.info("Issuing Bank B pornit", extra={"event_type": "SERVICE_STARTUP"})
    
    if not HMAC_KEY:
        logger.error("ISSUING_BANK_HMAC_MASTER_KEY lipsește din mediu!", extra={"event_type": "CONFIG_ERROR"})

    try:
        redis_client = aioredis.Redis(
            host=os.getenv("REDIS_HOST", "redis-master"),
            port=int(os.getenv("REDIS_PORT", 6379)),
            password=os.getenv("REDIS_PASSWORD"),
            decode_responses=True
        )
        await redis_client.ping()
        logger.info(
            "Conexiune Redis stabilită",
            extra={"event_type": "REDIS_CONNECTED"}
        )
    except Exception as e:
        logger.error(
            f"Redis indisponibil la startup: {e}",
            extra={"event_type": "REDIS_ERROR"}
        )

    yield

    if redis_client:
        await redis_client.aclose()

app = FastAPI(title="NFC Issuing Bank B", version="1.0.0", lifespan=lifespan)


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "issuing-bank-b",
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

    if not redis_client:
        logger.error(
            "Redis indisponibil. Validare ATC imposibilă.",
            extra={"event_type": "REDIS_ERROR", "trace_id": trace_id}
        )
        raise HTTPException(
            status_code=503,
            detail={
                "error_code": "SERVICE_UNAVAILABLE",
                "message": "Serviciu temporar indisponibil.",
                "action_required": "RETRY_LATER"
            }
        )

    # --- VALIDARE ATC (Anti-Replay, Cap. 7.6) ---
    received_atc = payload.cryptogram.atc
    atc_key = f"atc:{payload.pan}"

    # GET → verificăm ÎNAINTE de a scrie în Redis.
    # GETSET (varianta anterioară) scria valoarea ÎNAINTE de check — bug:
    # un ATC de replay suprascria valoarea legitimă din Redis.
    # Producție: înlocuiți cu script Lua pentru atomicitate completă la concurență.
    old_atc_raw = await redis_client.get(atc_key)
    stored_atc = int(old_atc_raw) if old_atc_raw is not None else -1

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

    # ATC valid — scriem în Redis DUPĂ validare
    await redis_client.set(atc_key, received_atc, ex=86400 * 30)  # TTL 30 zile
    
    logger.info(
        f"ATC valid. Primit: {received_atc}, anterior: {stored_atc}.",
        extra={"event_type": "ATC_VALIDATED", "trace_id": trace_id}
    )

    # --- FRAUD ENGINE COMPLET (Cap. 6.1, 6.2, 6.3) ---
    tsp_risk = payload.risk_level
    now = datetime.now(timezone.utc)

    # === RISK DECAY (Cap. 6.3) ===
    risk_key = f"risk:{payload.pan}"
    risk_data = await redis_client.hgetall(risk_key)

    if risk_data:
        stored_score = float(risk_data["score"])
        last_ts = datetime.fromisoformat(risk_data["timestamp"])
        delta_t_hours = (now - last_ts).total_seconds() / 3600
        decayed_base = stored_score * math.exp(-0.173 * delta_t_hours)
    else:
        decayed_base = 0.0

    # === FACTOR V — VELOCITY (W1=30) ===
    # Redis Sorted Set: score = timestamp Unix, member = timestamp Unix ca string
    # ZRANGEBYSCORE returnează tranzacțiile din ultimele 10 minute
    velocity_key = f"velocity:{payload.pan}"
    now_ts = now.timestamp()
    window_start = now_ts - 600  # 10 minute în secunde

    pipe = redis_client.pipeline()
    # 1. Șterge tranzacțiile mai vechi de 10 minute
    pipe.zremrangebyscore(velocity_key, 0, window_start)
    # 2. Numără tranzacțiile rămase (anterioare celei curente)
    pipe.zcard(velocity_key)
    # 3. Adaugă tranzacția curentă
    pipe.zadd(velocity_key, {str(now_ts): now_ts})
    # 4. TTL de curățare — 20 minute (dublu față de fereastră)
    pipe.expire(velocity_key, 1200)
    _, velocity, _, _ = await pipe.execute()

    n1 = min(velocity / 5.0, 1.0)
    velocity_contribution = 30 * n1

    # === FACTOR A — AMOUNT DEVIATION (W2=40) ===
    amount_key = f"amounts:{payload.pan}"
    current_amount = payload.transaction.amount

    # Citim istoricul INAINTE sa adaugam suma curenta
    amounts_raw = await redis_client.lrange(amount_key, 0, -1)
    amounts = [int(x) for x in amounts_raw]

    if not amounts:
        n2 = 0.0
    else:
        avg_amount = sum(amounts) / len(amounts)
        if avg_amount == 0:
            n2 = 0.0
        else:
            ratio = current_amount / avg_amount
            raw = 1 / (1 + math.exp(-0.5 * (ratio - 1)))
            n2 = max(0.0, min(1.0, (raw - 0.5) * 2))

    amount_contribution = 40 * n2

    # Adaugam suma curenta DUPA calcul
    pipe = redis_client.pipeline()
    pipe.lpush(amount_key, current_amount)
    pipe.ltrim(amount_key, 0, 99)   # pastram ultimele 100 tranzactii
    pipe.expire(amount_key, 86400 * 30)
    await pipe.execute()

    # === FACTOR L — LOCATION VELOCITY (W3=30) ===
    # TODO: Necesită coordonate GPS de la POS — neimplementat în PoC.
    # N3 = 0 până la integrarea hardware ESP32.
    location_contribution = 0.0

    # === SCOR FINAL ===
    # decayed_base = riscul acumulat din tranzacțiile anterioare, degradat în timp
    # tsp_risk = riscul static al DPAN-ului (proprietate a tokenului, nu se degradează)
    new_accumulated = decayed_base + velocity_contribution + amount_contribution + location_contribution
    final_risk = int(min(new_accumulated + tsp_risk, 100))

    # Salvăm scorul acumulat în Redis Hash
    await redis_client.hset(risk_key, mapping={
        "score": str(new_accumulated),
        "timestamp": now.isoformat()
    })
    await redis_client.expire(risk_key, 86400 * 7)  # TTL 7 zile

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

    # APPROVED și DECLINED returnează HTTP 200 (decizie de business).
    # CHALLENGE_REQUIRED ridică HTTPException(401) și nu ajunge aici.
    return IssuingBankResponse(
        status=status,
        transaction_id=f"TXN-{uuid.uuid4().hex[:12].upper()}",
        auth_code=auth_code,
        risk_score=final_risk,
        processed_at=now.isoformat()
    )
