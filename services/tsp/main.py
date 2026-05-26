# ============================================================
# main.py — Token Service Provider (TSP)
#
# Responsabilități:
#   1. Primește cereri de la Gateway (conținând un DPAN)
#   2. Caută token-ul în baza de date (Token Vault)
#   3. Returnează datele cardului real (PAN, Expiration Date)
# ============================================================

import os
import re
import json
import logging
import asyncpg
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from dotenv import load_dotenv


load_dotenv()

# --- CONFIGURAREA LOG-URILOR CU MASCARE PII ---

class MaskedJSONFormatter(logging.Formatter):
    """
    Formatter personalizat care convertește log-urile în JSON
    și maschează automat numerele de card (PAN/DPAN) conform PCI-DSS.
    """
    def format(self, record: logging.LogRecord) -> str:
        def mask_pan(match):
            pan = match.group(0)
            return f"{pan[:4]}********{pan[-4:]}" if 13 <= len(pan) <= 19 else pan
        message = re.sub(r'\b\d{13,19}\b', mask_pan, record.getMessage())
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "service": "tsp",
            "event_type": getattr(record, "event_type", "GENERAL"),
            "message": message,
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


logger = logging.getLogger("tsp")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(MaskedJSONFormatter())

if not logger.handlers:
    logger.addHandler(handler)

# Connection pool — partajat între toți workerii
db_pool: Optional[asyncpg.Pool] = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global db_pool
    # Suprascriem logger-ele implicite din uvicorn pentru a folosi formatul JSON
    for logger_name in ("uvicorn", "uvicorn.access", "uvicorn.error"):
        u_logger = logging.getLogger(logger_name)
        u_logger.handlers = [handler]
        u_logger.propagate = False

    try:
        db_pool = await asyncpg.create_pool(
            host=os.getenv("POSTGRES_TSP_HOST", "postgres-tsp"),
            port=int(os.getenv("POSTGRES_TSP_PORT", 5432)),
            database=os.getenv("POSTGRES_TSP_DB", "tsp_db"),
            user=os.getenv("POSTGRES_TSP_USER", "tsp_user"),
            password=os.getenv("POSTGRES_TSP_PASSWORD", "tsp_secret"),
            min_size=2,
            max_size=10
        )
        logger.info("Conexiune PostgreSQL stabilită", extra={"event_type": "DB_CONNECTED"})
    except Exception as e:
        logger.error(f"PostgreSQL indisponibil: {e}", extra={"event_type": "DB_ERROR"})

    logger.info("TSP pornit", extra={"event_type": "SERVICE_STARTUP"})
    yield

    if db_pool:
        await db_pool.close()

# --- APLICAȚIA FASTAPI ---

app = FastAPI(title="NFC TSP", version="1.0.0", lifespan=lifespan)

from prometheus_fastapi_instrumentator import Instrumentator

Instrumentator().instrument(app).expose(app)

# --- MODELE PYDANTIC ---

class DetokenizeRequest(BaseModel):
    dpan: str = Field(..., description="Device PAN (token)")
    trace_id: Optional[str] = Field(None, description="Trace ID pentru corelarea log-urilor")

class RegisterTokenRequest(BaseModel):
    dpan: str = Field(..., description="Device PAN (token nou generat de Gateway)")
    pan: str = Field(..., description="PAN real al cardului fizic")
    risk_level: int = Field(0, description="Scorul de risc inițial al token-ului")


# --- ENDPOINT-URI ---



@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "tsp",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@app.post("/api/v1/tokens/detokenize")
async def detokenize(request: DetokenizeRequest):
    trace_id = request.trace_id or "UNKNOWN"

    logger.info(
        f"Cerere detokenizare primită pentru token: {request.dpan}",
        extra={"event_type": "DETOKENIZE_REQUEST", "trace_id": trace_id}
    )

    if not db_pool:
        logger.error("PostgreSQL indisponibil", extra={"event_type": "DB_ERROR", "trace_id": trace_id})
        raise HTTPException(status_code=503, detail={"error_code": "SERVICE_UNAVAILABLE"})

    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT pan, exp_month, exp_year, risk_level FROM tokens WHERE dpan = $1",
            request.dpan
        )

    if not row:
        logger.warning(
            f"Token negăsit în baza de date: {request.dpan}",
            extra={"event_type": "DETOKENIZE_FAILED_NOT_FOUND", "trace_id": trace_id}
        )
        raise HTTPException(
            status_code=404,
            detail={
                "error_code": "DPAN_NOT_FOUND",
                "message": "Token-ul nu există în Token Vault."
            }
        )

    pan = row["pan"]
    logger.info(
        f"Token rezolvat cu succes în PAN: {pan}",
        extra={"event_type": "DETOKENIZE_SUCCESS", "trace_id": trace_id}
    )

    return {
        "pan": pan,
        "exp_month": row["exp_month"],
        "exp_year": row["exp_year"],
        "risk_level": row["risk_level"],
        "status": "ACTIVE"
    }
@app.post("/api/v1/tokens/register")
async def register_token(request: RegisterTokenRequest):
    """
    Înregistrează un DPAN nou în Token Vault.
    Apelat de Gateway în fluxul de enroll Android.
    Folosește ON CONFLICT DO UPDATE pentru idempotență.
    """
    logger.info(
        f"Înregistrare token nou pentru DPAN: {request.dpan}",
        extra={"event_type": "TOKEN_REGISTERED"}
    )

    if not db_pool:
        logger.error("PostgreSQL indisponibil", extra={"event_type": "DB_ERROR"})
        raise HTTPException(status_code=503, detail={"error_code": "SERVICE_UNAVAILABLE"})

    try:
        async with db_pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO tokens (dpan, pan, exp_month, exp_year, risk_level)
                VALUES ($1, $2, '12', '28', $3)
                ON CONFLICT (dpan) DO UPDATE
                SET pan = EXCLUDED.pan, risk_level = EXCLUDED.risk_level
            """, request.dpan, request.pan, request.risk_level)
    except Exception as e:
        logger.error(
            f"Eroare la înregistrarea token-ului: {e}",
            extra={"event_type": "TOKEN_REGISTER_FAILED"}
        )
        raise HTTPException(status_code=500, detail={"error_code": "DB_ERROR"})

    return {"status": "registered", "dpan": request.dpan}


# --- PORNIRE ---
if __name__ == "__main__":
    import uvicorn
    import os
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("TSP_PORT", 8002)), reload=True)
