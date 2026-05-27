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
import hmac
import hashlib
import logging
import math
import calendar
from datetime import datetime, timezone, date
from typing import Optional

from fastapi import FastAPI, HTTPException, Header, Query
from pydantic import BaseModel, Field, field_validator
from dotenv import load_dotenv
from contextlib import asynccontextmanager
# pyrefly: ignore [missing-import]
import redis.asyncio as aioredis
import asyncpg

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import base64

BANK_PRIVATE_KEY = None

redis_client: Optional[aioredis.Redis] = None
db_pool: Optional[asyncpg.Pool] = None

from shared.crypto_utils import verify_mac, verify_pin

load_dotenv()

_key_hex = os.getenv("ISSUING_BANK_HMAC_MASTER_KEY", "")
try:
    HMAC_KEY = bytes.fromhex(_key_hex) if _key_hex else b""
except ValueError:
    HMAC_KEY = b""

BANK_ID = os.getenv("BANK_ID", "UNKNOWN")

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
            
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
            
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry, ensure_ascii=False)


logger = logging.getLogger("issuing_bank")
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
    global redis_client, db_pool, BANK_PRIVATE_KEY

    for logger_name in ("uvicorn", "uvicorn.access", "uvicorn.error"):
        u_logger = logging.getLogger(logger_name)
        u_logger.handlers = [handler]
        u_logger.propagate = False

    logger.info("Issuing Bank pornit", extra={"event_type": "SERVICE_STARTUP"})
    
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

    try:
        db_pool = await asyncpg.create_pool(
            host=os.getenv("POSTGRES_BANK_HOST", "postgres-bank"),
            port=int(os.getenv("POSTGRES_BANK_PORT", 5432)),
            database=os.getenv("POSTGRES_BANK_DB", "bank_db"),
            user=os.getenv("POSTGRES_BANK_USER", "bank_user"),
            password=os.getenv("POSTGRES_BANK_PASSWORD", "bank_secret"),
            min_size=2,
            max_size=10
        )
        logger.info("Conexiune PostgreSQL stabilită", extra={"event_type": "DB_CONNECTED"})
    except Exception as e:
        logger.error(f"PostgreSQL indisponibil: {e}", extra={"event_type": "DB_ERROR"})

    try:
        with open("/app/certs/bank_private.pem", "rb") as f:
            BANK_PRIVATE_KEY = serialization.load_pem_private_key(f.read(), password=None)
        logger.info("Cheie privată RSA încărcată", extra={"event_type": "RSA_KEY_LOADED"})
    except Exception as e:
        logger.error(f"Cheie privată RSA lipsă: {e}", extra={"event_type": "RSA_KEY_ERROR"})


    logger.info("Issuing Bank pornit", extra={"event_type": "SERVICE_STARTUP"})
    yield

    if redis_client:
        await redis_client.aclose()
    if db_pool:
        await db_pool.close()

app = FastAPI(title="NFC Issuing Bank", version="1.0.0", lifespan=lifespan)


from prometheus_fastapi_instrumentator import Instrumentator

Instrumentator().instrument(app).expose(app)

class ChallengeRequest(BaseModel):
    transaction_id: str = Field(..., description="ID-ul tranzacției originale")
    idempotency_key: str = Field(..., description="Cheie nouă de idempotență pentru challenge")
    terminal_id: str = Field(..., description="ID-ul terminalului POS")
    pin_block_encrypted: str = Field(..., description="PIN Block criptat RSA-OAEP, encodat Base64")

class VerifyCardRequest(BaseModel):
    pan: str = Field(..., description="PAN-ul cardului de verificat")
    expiry_month: str = Field(..., description="Luna de expirare (ex: '12')")
    expiry_year: str = Field(..., description="Anul de expirare (ex: '28')")
    cvv_hash: str = Field(..., description="SHA256(pan + cvv) — CVV-ul plain text NU se transmite niciodată")



@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "issuing-bank",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.post("/api/v1/payments/challenge")
async def challenge_payment(payload: ChallengeRequest):
    trace_id = payload.idempotency_key

    logger.info(
        f"Challenge primit pentru tranzacția: {payload.transaction_id}",
        extra={"event_type": "CHALLENGE_RECEIVED", "trace_id": trace_id}
    )

    if not BANK_PRIVATE_KEY:
        raise HTTPException(
            status_code=503,
            detail={"error_code": "SERVICE_UNAVAILABLE",
                    "message": "Cheie RSA indisponibilă"}
        )

    # PIN Retry Limiting — cheie per transaction_id (nu per PAN)
    # INCR atomic garantează thread-safety între workeri multipli
    pin_attempts_key = f"pin_attempts:{payload.transaction_id}"
    if redis_client:
        try:
            attempts = await redis_client.incr(pin_attempts_key)
            if attempts == 1:
                await redis_client.expire(pin_attempts_key, 300)
            if attempts > 3:
                logger.warning(
                    f"PIN blocat — {attempts} încercări pentru "
                    f"tranzacția {payload.transaction_id}",
                    extra={"event_type": "PIN_BLOCKED", "trace_id": trace_id}
                )
                raise HTTPException(
                    status_code=403,
                    detail={
                        "error_code": "PIN_BLOCKED",
                        "message": "Prea multe încercări PIN. Tranzacție anulată.",
                        "action_required": "CONTACT_BANK",
                        "attempts_used": int(attempts),
                        "max_attempts": 3
                    }
                )
            logger.info(
                f"Încercare PIN {attempts}/3 pentru "
                f"tranzacția {payload.transaction_id}",
                extra={"event_type": "PIN_ATTEMPT", "trace_id": trace_id}
            )
        except HTTPException:
            raise
        except Exception as e:
            logger.warning(
                f"Redis indisponibil pentru PIN retry limiting: {e}",
                extra={"event_type": "REDIS_ERROR", "trace_id": trace_id}
            )

    # Decriptare PIN Block
    try:
        encrypted_bytes = base64.b64decode(payload.pin_block_encrypted)
        pin_block = BANK_PRIVATE_KEY.decrypt(
            encrypted_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        logger.error(
            "Decriptare PIN Block eșuată.",
            extra={"event_type": "PIN_DECRYPT_FAILED", "trace_id": trace_id}
        )
        raise HTTPException(
            status_code=400,
            detail={
                "error_code": "INVALID_PIN_BLOCK",
                "message": "PIN Block invalid sau corupt.",
                "action_required": "RETRY_WITH_PIN"
            }
        )

    # Verificare anti-replay — transaction_id din PIN Block
    # ISO 9564 Format 4: PIN Block conține transaction_id în payload intern
    # PoC: verificăm că transaction_id din request e prezent în PIN Block decriptat
    pin_block_str = pin_block.decode("utf-8", errors="ignore")
    if payload.transaction_id not in pin_block_str:
        logger.error(
            "PIN Block nu conține transaction_id corect — posibil replay.",
            extra={"event_type": "PIN_REPLAY_DETECTED", "trace_id": trace_id}
        )
        raise HTTPException(
            status_code=400,
            detail={
                "error_code": "INVALID_PIN_BLOCK",
                "message": "PIN Block invalid.",
                "action_required": "DECLINE_TRANSACTION"
            }
        )

    # Parsare format PIN Block: "{transaction_id}:{pin}"
    # Anti-replay verificat deja — transaction_id e prezent în pin_block_str
    parts = pin_block_str.split(":")
    if len(parts) != 2:
        raise HTTPException(
            status_code=400,
            detail={
                "error_code": "INVALID_PIN_BLOCK",
                "message": "Format PIN Block invalid.",
                "action_required": "RETRY_WITH_PIN"
            }
        )

    pin = parts[1].strip()

    # Validare format PIN: 4-6 cifre
    # NOTĂ SECURITATE: mesaj deliberat vag după decriptare — nu dezvăluie
    # dacă PIN-ul e prea scurt, prea lung sau conține caractere invalide.
    # EXCEPȚIE: validare format (înainte de lookup DB) poate fi specifică.
    if not pin.isdigit() or len(pin) < 4 or len(pin) > 6:
        logger.warning(
            "PIN format invalid.",
            extra={"event_type": "PIN_INVALID", "trace_id": trace_id}
        )
        raise HTTPException(
            status_code=400,
            detail={
                "error_code": "INVALID_PIN",
                "message": "PIN trebuie să fie 4-6 cifre.",
                "action_required": "RETRY_WITH_PIN"
            }
        )

    if not db_pool:
        raise HTTPException(
            status_code=503,
            detail={"error_code": "SERVICE_UNAVAILABLE"}
        )

    # Citim PAN-ul și suma din tranzacția CHALLENGE_REQUIRED stocată în DB
    # (stocarea se face în authorize_transaction ÎNAINTE de a ridica 401)
    async with db_pool.acquire() as conn:
        txn_row = await conn.fetchrow(
            "SELECT pan, amount FROM transactions WHERE transaction_id = $1",
            payload.transaction_id
        )
        if not txn_row:
            logger.error(
                f"Transaction ID necunoscut în challenge: {payload.transaction_id}",
                extra={"event_type": "PIN_VERIFY_FAILED", "trace_id": trace_id}
            )
            raise HTTPException(
                status_code=400,
                detail={
                    "error_code": "TRANSACTION_NOT_FOUND",
                    "message": "Tranzacția originală nu a fost găsită.",
                    "action_required": "DECLINE_TRANSACTION"
                }
            )
        pan = txn_row["pan"]
        account_row = await conn.fetchrow(
            "SELECT pin_hash FROM accounts WHERE pan = $1", pan
        )

    if not account_row or not account_row["pin_hash"]:
        logger.error(
            "PIN hash lipsă pentru cont — configurare incompletă.",
            extra={"event_type": "PIN_VERIFY_FAILED", "trace_id": trace_id}
        )
        raise HTTPException(
            status_code=503,
            detail={
                "error_code": "SERVICE_UNAVAILABLE",
                "message": "Configurare cont incompletă."
            }
        )

    # verify_pin folosește hmac.compare_digest — timing-safe obligatoriu
    # PIN-ul NU apare niciodată în log-uri (nici ca hint în mesajul de eroare)
    pin_valid = verify_pin(pin, pan, account_row["pin_hash"])
    if not pin_valid:
        logger.warning(
            f"PIN incorect pentru tranzacția {payload.transaction_id}.",
            extra={"event_type": "PIN_INCORRECT", "trace_id": trace_id}
        )
        raise HTTPException(
            status_code=400,
            detail={
                "error_code": "INCORRECT_PIN",
                "message": "PIN incorect. Tranzacție refuzată.",
                "action_required": "RETRY_WITH_PIN"
            }
        )

    # PIN corect — șterge counter-ul retry (tranzacție finalizată cu succes)
    if redis_client:
        try:
            await redis_client.delete(pin_attempts_key)
        except Exception:
            pass
    logger.info(
        "PIN corect. Counter retry șters.",
        extra={"event_type": "PIN_CORRECT", "trace_id": trace_id}
    )

    # PIN corect — aprobăm tranzacția Step-Up
    logger.info(
        "PIN verificat cu succes.",
        extra={"event_type": "PIN_VALIDATED", "trace_id": trace_id}
    )

    approval_txn_id = f"TXN-{uuid.uuid4().hex[:12].upper()}"
    now = datetime.now(timezone.utc)

    try:
        async with db_pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute("""
                    INSERT INTO transactions
                        (transaction_id, pan, amount, currency,
                         status, risk_score, terminal_id, bank, created_at)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                """,
                    approval_txn_id, pan, txn_row["amount"],
                    "RON", "APPROVED", 0, payload.terminal_id, BANK_ID, now
                )
    except Exception as e:
        logger.error(
            f"Eroare scriere APPROVED challenge în DB: {e}",
            extra={"event_type": "DB_ERROR", "trace_id": trace_id}
        )

    return {
        "status": "APPROVED",
        "transaction_id": approval_txn_id,
        "auth_code": uuid.uuid4().hex[:8].upper(),
        "processed_at": now.isoformat()
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
    pipe.expire(velocity_key, 30 * 86400)
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
    await redis_client.expire(risk_key, 86400 * 30)  # TTL 30 zile

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
        # Generăm transaction_id ÎNAINTE de stocare — challenge endpoint îl va căuta în DB
        challenge_txn_id = f"TXN-{uuid.uuid4().hex[:12].upper()}"
        if db_pool:
            try:
                async with db_pool.acquire() as conn:
                    async with conn.transaction():
                        await conn.execute("""
                            INSERT INTO transactions
                                (transaction_id, pan, amount, currency,
                                 status, risk_score, terminal_id, bank, created_at)
                            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                        """,
                            challenge_txn_id, payload.pan,
                            payload.transaction.amount, payload.transaction.currency,
                            "CHALLENGE_REQUIRED", final_risk, payload.terminal_id, BANK_ID, now
                        )
            except Exception as e:
                logger.error(
                    f"Eroare stocare CHALLENGE_REQUIRED în DB: {e}",
                    extra={"event_type": "DB_ERROR", "trace_id": trace_id}
                )
        logger.info(
            f"Step-Up Authentication cerut. Risk score: {final_risk}",
            extra={"event_type": "TX_STEP_UP", "trace_id": trace_id}
        )
        raise HTTPException(
            status_code=401,
            detail={
                "error_code": "CHALLENGE_REQUIRED",
                "risk_score": final_risk,
                "transaction_id": challenge_txn_id
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

    
    # --- VALIDARE ATC, SOLD SI SALVARE TRANZACTIE ---
    received_atc = payload.cryptogram.atc

    if not db_pool:
        logger.error("PostgreSQL indisponibil.", extra={"event_type": "DB_ERROR", "trace_id": trace_id})
        raise HTTPException(status_code=503, detail={"error_code": "SERVICE_UNAVAILABLE"})

    txn_id = f"TXN-{uuid.uuid4().hex[:12].upper()}"

    async with db_pool.acquire() as conn:
        async with conn.transaction():
            account = await conn.fetchrow(
                "SELECT pan, balance, last_atc, exp_month, exp_year FROM accounts WHERE pan = $1 FOR UPDATE",
                payload.pan
            )

            if not account:
                # Auto-create: cont creat on-the-fly la primul payment.
                # exp_month/exp_year iau DEFAULT ('12'/'28'), cvv_hash=NULL.
                # Contul auto-creat NU poate fi înrolat via Android (cvv_hash=NULL).
                await conn.execute(
                    """INSERT INTO accounts (pan, balance, last_atc, exp_month, exp_year)
                       VALUES ($1, 100000, -1, '12', '28')""",
                    payload.pan
                )
                stored_atc = -1
                current_balance = 100000
                acc_exp_month = '12'
                acc_exp_year = '28'
            else:
                stored_atc = account["last_atc"]
                current_balance = account["balance"]
                acc_exp_month = account["exp_month"]
                acc_exp_year = account["exp_year"]

            # Verificare expirare card
            # NOTĂ: exp_year stocat ca 2 cifre ("28" = 2028), valabil până în 2099
            try:
                exp_year_full = int("20" + acc_exp_year)
                exp_month_int = int(acc_exp_month)
                last_day = calendar.monthrange(exp_year_full, exp_month_int)[1]
                expiry_date = date(exp_year_full, exp_month_int, last_day)
                if date.today() > expiry_date:
                    logger.warning(
                        f"Card expirat. Expiry: {exp_month_int}/{exp_year_full}",
                        extra={"event_type": "CARD_EXPIRED", "trace_id": trace_id}
                    )
                    raise HTTPException(
                        status_code=400,
                        detail={
                            "error_code": "CARD_EXPIRED",
                            "message": "Cardul a expirat.",
                            "action_required": "USE_DIFFERENT_CARD"
                        }
                    )
            except HTTPException:
                raise
            except (ValueError, TypeError) as e:
                logger.error(
                    f"Eroare parsare dată expirare: {e}",
                    extra={"event_type": "DB_ERROR", "trace_id": trace_id}
                )

            # Validare ATC
            if received_atc <= stored_atc:
                logger.error(
                    f"ATC invalid: primit {received_atc}, stocat {stored_atc}.",
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

            logger.info(
                f"ATC valid. Primit: {received_atc}, anterior: {stored_atc}.",
                extra={"event_type": "ATC_VALIDATED", "trace_id": trace_id}
            )

            # Verificare sold suficient
            if status != "DECLINED" and current_balance < payload.transaction.amount:
                logger.warning(
                    f"Sold insuficient. Disponibil: {current_balance}, cerut: {payload.transaction.amount}",
                    extra={"event_type": "INSUFFICIENT_FUNDS", "trace_id": trace_id}
                )
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error_code": "INSUFFICIENT_FUNDS",
                        "message": "Sold insuficient.",
                        "action_required": "DECLINE_TRANSACTION"
                    }
                )

            # Deducere sold dacă APPROVED
            if status == "APPROVED":
                await conn.execute(
                    "UPDATE accounts SET balance = balance - $1, last_atc = $2 WHERE pan = $3",
                    payload.transaction.amount, received_atc, payload.pan
                )
            else:
                await conn.execute(
                    "UPDATE accounts SET last_atc = $1 WHERE pan = $2",
                    received_atc, payload.pan
                )

            # Inserare tranzactie
            await conn.execute("""
                INSERT INTO transactions
                    (transaction_id, pan, amount, currency, status,
                    risk_score, terminal_id, bank, created_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            """,
                txn_id, payload.pan, payload.transaction.amount,
                payload.transaction.currency, status,
                final_risk, payload.terminal_id, BANK_ID, now
            )

    return IssuingBankResponse(
        status=status,
        transaction_id=txn_id,
        auth_code=auth_code,
        risk_score=final_risk,
        processed_at=now.isoformat()
)

# --- ENDPOINT-URI ADMIN (Dashboard) ---

@app.post("/api/v1/admin/verify-card")
async def verify_card(payload: VerifyCardRequest):
    """
    Verifică datele unui card fizic (PAN, expiry, CVV hash).
    Apelat exclusiv de Gateway în fluxul de enroll Android.
    CVV-ul plain text NU circulă niciodată pe rețea — doar SHA256(pan+cvv).
    """
    if not db_pool:
        raise HTTPException(status_code=503, detail={"error_code": "SERVICE_UNAVAILABLE"})

    async with db_pool.acquire() as conn:
        row = await conn.fetchrow("""
            SELECT pan, exp_month, exp_year, cvv_hash
            FROM accounts WHERE pan = $1
        """, payload.pan)

    if not row:
        logger.warning(
            "Verificare card eșuată — card negăsit",
            extra={"event_type": "CARD_VERIFY_FAILED"}
        )
        raise HTTPException(status_code=404, detail={"error_code": "CARD_NOT_FOUND"})

    if (row["exp_month"] != payload.expiry_month or
            row["exp_year"] != payload.expiry_year):
        logger.warning(
            "Verificare card eșuată — date invalide",
            extra={"event_type": "CARD_VERIFY_FAILED"}
        )
        raise HTTPException(status_code=400, detail={"error_code": "INVALID_CARD_DATA"})

    # Comparare timing-safe pentru cvv_hash (previne timing attacks)
    stored_hash = row["cvv_hash"] or ""
    if not hmac.compare_digest(stored_hash, payload.cvv_hash):
        logger.warning(
            "Verificare card eșuată — date invalide",
            extra={"event_type": "CARD_VERIFY_FAILED"}
        )
        raise HTTPException(status_code=400, detail={"error_code": "INVALID_CARD_DATA"})

    pan = payload.pan
    logger.info(
        f"Card verificat cu succes pentru PAN mascat: {pan[:4]}****{pan[-4:]}",
        extra={"event_type": "CARD_VERIFY_SUCCESS"}
    )
    return {"status": "valid", "pan_masked": f"{pan[:4]}****{pan[-4:]}"}


@app.get("/api/v1/admin/balance")
async def get_balance(pan: str = Query(..., description="PAN-ul contului")):
    """
    Returnează soldul unui cont.
    Apelat de Gateway în fluxul balance Android (după detokenizare JWT).
    """
    if not db_pool:
        raise HTTPException(status_code=503, detail={"error_code": "SERVICE_UNAVAILABLE"})

    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT balance FROM accounts WHERE pan = $1", pan
        )

    if not row:
        raise HTTPException(status_code=404, detail={"error_code": "ACCOUNT_NOT_FOUND"})

    return {
        "balance_ron": row["balance"] / 100,
        "balance_cents": row["balance"]
    }


@app.get("/api/v1/admin/transactions")
async def get_transactions(pan: Optional[str] = Query(None, description="Filtru opțional după PAN")):
    """
    Returnează istoricul tranzacțiilor.
    Cu pan= → filtrare per card (Android history, max 20).
    Fără pan= → toate tranzacțiile (Dashboard, max 100).
    """
    if not db_pool:
        return {"transactions": []}

    async with db_pool.acquire() as conn:
        if pan:
            rows = await conn.fetch("""
                SELECT transaction_id, pan, amount, currency, status,
                       risk_score, terminal_id, bank, created_at
                FROM transactions
                WHERE pan = $1
                ORDER BY created_at DESC
                LIMIT 20
            """, pan)
        else:
            rows = await conn.fetch("""
                SELECT transaction_id, pan, amount, currency, status,
                       risk_score, terminal_id, bank, created_at
                FROM transactions
                ORDER BY created_at DESC
                LIMIT 100
            """)

    return {"transactions": [
        {
            "transaction_id": r["transaction_id"],
            "pan_masked": f"{r['pan'][:4]}********{r['pan'][-4:]}",
            "amount": r["amount"],
            "currency": r["currency"],
            "status": r["status"],
            "risk_score": r["risk_score"],
            "terminal_id": r["terminal_id"],
            "bank": r["bank"],
            "timestamp": r["created_at"].isoformat()
        }
        for r in rows
    ]}


@app.get("/api/v1/admin/risk-profiles")
async def get_risk_profiles():
    if not redis_client:
        return {"profiles": []}
    profiles = []
    try:
        keys = await redis_client.keys("risk:*")
        for key in keys:
            data = await redis_client.hgetall(key)
            if data:
                pan = key.replace("risk:", "")
                score = float(data.get("score", 0))
                profiles.append({
                    "pan_masked": f"{pan[:4]}********{pan[-4:]}",
                    "current_score": round(score, 2),
                    "last_transaction": data.get("timestamp", "N/A"),
                    "risk_level": "HIGH" if score > 75 else "MEDIUM" if score > 40 else "LOW"
                })
    except Exception as e:
        logger.error(f"Eroare citire risk profiles: {e}")
    return {"profiles": profiles}

# --- PORNIRE ---
if __name__ == "__main__":
    import uvicorn
    import os
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("ISSUING_BANK_PORT", 8004)), reload=True)