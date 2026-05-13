# services/card_network/main.py
import os
import json
import logging
import re
import httpx
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from dotenv import load_dotenv

load_dotenv()

# --- LOGGING (același pattern ca celelalte servicii) ---

class MaskedJSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        def mask_pan(match):
            pan = match.group(0)
            return f"{pan[:4]}********{pan[-4:]}" if 13 <= len(pan) <= 19 else pan

        message = re.sub(r'\b\d{13,19}\b', mask_pan, record.getMessage())

        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "service": "card-network",
            "event_type": getattr(record, "event_type", "GENERAL"),
            "message": message,
        }
        if hasattr(record, "trace_id"):
            log_entry["trace_id"] = record.trace_id

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

        return json.dumps(log_entry, ensure_ascii=False)


logger = logging.getLogger("card_network")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(MaskedJSONFormatter())
if not logger.handlers:
    logger.addHandler(handler)


# --- ROUTING TABLE ---
# IIN prefix → URL-ul băncii emitente corespunzătoare
# În producție: tabel în bază de date, actualizat de Visa/Mastercard
ROUTING_TABLE = {
    "400000": os.getenv("ISSUING_BANK_A_URL", "http://issuing-bank:8004"),
    "500000": os.getenv("ISSUING_BANK_B_URL", "http://issuing-bank-b:8006"),
    "4":      os.getenv("ISSUING_BANK_A_URL", "http://issuing-bank:8004"),
    "5":      os.getenv("ISSUING_BANK_B_URL", "http://issuing-bank-b:8006"),
}

AUTHORIZE_PATH = "/api/v1/transactions/authorize"


def find_bank_url(pan: str, table: dict) -> str | None:
    """Caută cel mai specific prefix IIN în routing table (longest-prefix-match).

    Caută de la 6 cifre (specific) la 1 cifră (fallback general), toate lungimile.
    Ex: pentru PAN "400000...", verifică '400000', '40000', '4000', '400', '40', '4'.
    """
    for length in range(6, 0, -1):
        prefix = pan[:length]
        if prefix in table:
            return table[prefix]
    return None


# --- MODELE ---

class TransactionData(BaseModel):
    amount: int
    currency: str
    pos_nonce: str
    terminal_timestamp: str

class CryptogramData(BaseModel):
    mac: str
    atc: int

class CardNetworkRequest(BaseModel):
    pan: str
    risk_level: int = 0
    transaction: TransactionData
    cryptogram: CryptogramData
    idempotency_key: str
    terminal_id: str


# --- LIFESPAN ---

@asynccontextmanager
async def lifespan(app: FastAPI):
    for logger_name in ("uvicorn", "uvicorn.access", "uvicorn.error"):
        u_logger = logging.getLogger(logger_name)
        u_logger.handlers = [handler]
        u_logger.propagate = False

    logger.info("Card Network Router pornit", extra={"event_type": "SERVICE_STARTUP"})
    yield


app = FastAPI(title="NFC Card Network Router", version="1.0.0", lifespan=lifespan)

from prometheus_fastapi_instrumentator import Instrumentator

Instrumentator().instrument(app).expose(app)

# --- ENDPOINTS ---

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "card-network",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.post("/api/v1/transactions/route")
async def route_transaction(payload: CardNetworkRequest):
    trace_id = payload.idempotency_key

    bank_base_url = find_bank_url(payload.pan, ROUTING_TABLE)

    if not bank_base_url:
        logger.error(
            f"PAN cu prefix necunoscut: {payload.pan[0]}. Rutare imposibilă.",
            extra={"event_type": "ROUTING_FAILED", "trace_id": trace_id}
        )
        raise HTTPException(
            status_code=400,
            detail={
                "error_code": "UNSUPPORTED_CARD_NETWORK",
                "message": "Rețeaua cardului nu este suportată.",
                "action_required": "USE_DIFFERENT_CARD"
            }
        )

    bank_url = f"{bank_base_url}{AUTHORIZE_PATH}"
    matched_prefix = next((p for l in (6,4,2,1) if (p := payload.pan[:l]) in ROUTING_TABLE), payload.pan[0])

    logger.info(
        f"Rutare tranzacție către banca emitentă (prefix PAN: {matched_prefix})",
        extra={"event_type": "ROUTING_INITIATED", "trace_id": trace_id}
    )

    try:
        async with httpx.AsyncClient(timeout=1.2) as client:
            bank_response = await client.post(
                bank_url,
                json=payload.model_dump()
            )

        # Propagăm răspunsurile semantice direct către Gateway
        if bank_response.status_code == 400:
            raise HTTPException(
                status_code=400,
                detail=bank_response.json().get("detail", {})
            )

        if bank_response.status_code == 401:
            logger.warning(
                "Issuing Bank cere Step-Up. Propagare către Gateway.",
                extra={"event_type": "STEP_UP_PROPAGATED", "trace_id": trace_id}
            )
            # TODO: PoC — idemp_key rămâne "PROCESSING" cu TTL 30s.
            # Producție: salvează starea CHALLENGE_REQUIRED în Redis ca stare finală.
            raise HTTPException(
                status_code=401,
                detail=bank_response.json().get("detail", {})
            )

        bank_response.raise_for_status()

        response_data = bank_response.json()
        routed_status = response_data.get("status", "UNKNOWN")
        log_event = "ROUTING_SUCCESS" if routed_status == "APPROVED" else "ROUTING_COMPLETED"

        logger.info(
            f"Răspuns Issuing Bank propagat. Status: {routed_status}",
            extra={"event_type": log_event, "trace_id": trace_id}
        )

        return response_data

    except httpx.TimeoutException:
        logger.error(
            "Timeout la comunicarea cu Issuing Bank via Card Network.",
            extra={"event_type": "ISSUING_BANK_TIMEOUT", "trace_id": trace_id}
        )
        raise HTTPException(
            status_code=503,
            detail={
                "error_code": "ISSUING_BANK_TIMEOUT",
                "message": "Banca emitentă nu a răspuns în timp util.",
                "retry_after_ms": 1000,
                "action_required": "RETRY_LATER"
            }
        )

    except httpx.RequestError as exc:
        logger.error(
            f"Eroare rețea la comunicarea cu Issuing Bank: {exc}",
            extra={"event_type": "ISSUING_BANK_NETWORK_ERROR", "trace_id": trace_id}
        )
        raise HTTPException(status_code=503, detail="Issuing Bank connection failed")

    except httpx.HTTPStatusError as exc:
        logger.error(
            f"Eroare HTTP de la Issuing Bank: {exc.response.status_code}",
            extra={"event_type": "ISSUING_BANK_HTTP_ERROR", "trace_id": trace_id}
        )
        raise HTTPException(
            status_code=503,
            detail={
                "error_code": "ISSUING_BANK_SERVICE_ERROR",
                "message": "Issuing Bank a returnat o eroare internă.",
                "retry_after_ms": 1000,
                "action_required": "RETRY_LATER"
            }
        )