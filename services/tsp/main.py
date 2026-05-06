# ============================================================
# main.py — Token Service Provider (TSP)
#
# Responsabilități:
#   1. Primește cereri de la Gateway (conținând un DPAN)
#   2. Caută token-ul în baza de date (Token Vault)
#   3. Returnează datele cardului real (PAN, Expiration Date)
# ============================================================

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field
from typing import Optional
import os
import logging
import json
import re
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

# --- CONFIGURAREA LOG-URILOR CU MASCARE PII ---

class MaskedJSONFormatter(logging.Formatter):
    """
    Formatter personalizat care convertește log-urile în JSON
    și maschează automat numerele de card (PAN/DPAN) conform PCI-DSS.
    """
    def format(self, record: logging.LogRecord) -> str:
        # Mascare numere între 13 și 19 cifre (standard PAN length)
        # Regex caută grupuri de cifre.
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
            "service": "tsp",
            "event_type": getattr(record, "event_type", "GENERAL"),
            "message": masked_message,
        }
        
        if hasattr(record, "trace_id"):
            log_entry["trace_id"] = record.trace_id
            
        return json.dumps(log_entry, ensure_ascii=False)


logger = logging.getLogger("tsp")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(MaskedJSONFormatter())

if not logger.handlers:
    logger.addHandler(handler)

# --- APLICAȚIA FASTAPI ---

app = FastAPI(
    title="NFC Token Service Provider",
    description="Microserviciu care mapează DPAN la PAN real",
    version="1.0.0",
)

# --- MOCK DATA (Token Vault temporar) ---
# Simulează baza de date PostgreSQL. Cheia este DPAN, valoarea este PAN și expirare.
# AC-07: PAN-urile de mai jos NU trebuie să apară NICIODATĂ în loguri complet.

TOKEN_VAULT = {
    "4000000000000001": {
        "pan": "4111111111111111",
        "exp_month": "12",
        "exp_year": "28",
        "risk_level": "0"
    },
    "5000000000000002": {
        "pan": "5555555555555555",
        "exp_month": "10",
        "exp_year": "27",
        "risk_level": "1"
    },
    "0000000000000001": {
        "pan": "0000000000000001",
        "exp_month": "01",
        "exp_year": "30",
        "risk_level": "0"
    },
    "TEST-STEP-UP-001": {
    "pan": "4222222222222222",
    "exp_month": "12",
    "exp_year": "28",
    "risk_level": "55"
}
}

# --- MODELE PYDANTIC ---

class TokenLookupRequest(BaseModel):
    dpan: str = Field(..., description="Device PAN (Token)")
    trace_id: Optional[str] = Field(None, description="Idempotency Key / Trace ID trimis de Gateway")

class TokenLookupResponse(BaseModel):
    pan: str = Field(..., description="Primary Account Number (Card Real)")
    exp_month: str = Field(..., description="Luna expirării (MM)")
    exp_year: str = Field(..., description="Anul expirării (YY)")
    risk_level: Optional[str] = Field("0", description="Nivelul de risc al token-ului")

# --- ENDPOINT-URI ---

@app.on_event("startup")
async def startup_event():
    # Suprascriem logger-ele implicite din uvicorn pentru a folosi formatul JSON
    for logger_name in ("uvicorn", "uvicorn.access", "uvicorn.error"):
        u_logger = logging.getLogger(logger_name)
        u_logger.handlers = [handler]
        u_logger.propagate = False

    logger.info("TSP Service pornit", extra={"event_type": "SERVICE_STARTUP"})

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "tsp",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@app.post("/api/v1/tokens/detokenize", response_model=TokenLookupResponse)
async def detokenize(request: Request, payload: TokenLookupRequest):
    """
    Caută DPAN-ul în seif și returnează datele reale ale cardului.
    """
    dpan = payload.dpan
    trace_id = payload.trace_id or "UNKNOWN"
    
    logger.info(
        f"Cerere detokenizare primită pentru token: {dpan}", 
        extra={"event_type": "DETOKENIZE_REQUEST", "trace_id": trace_id}
    )
    
    # Căutare în baza de date temporară
    card_data = TOKEN_VAULT.get(dpan)
    
    if not card_data:
        logger.warning(
            f"Token negăsit în baza de date: {dpan}",
            extra={"event_type": "DETOKENIZE_FAILED_NOT_FOUND", "trace_id": trace_id}
        )
        raise HTTPException(
            status_code=404,
            detail={
                "error_code": "TOKEN_NOT_FOUND",
                "message": "DPAN-ul furnizat nu a fost găsit în sistem"
            }
        )
        
    logger.info(
        f"Token rezolvat cu succes în PAN: {card_data['pan']}",
        extra={"event_type": "DETOKENIZE_SUCCESS", "trace_id": trace_id}
    )
    
    return TokenLookupResponse(
        pan=card_data["pan"],
        exp_month=card_data["exp_month"],
        exp_year=card_data["exp_year"],
        risk_level=card_data.get("risk_level", "0")
    )

# --- PORNIRE ---
if __name__ == "__main__":
    import uvicorn
    import os
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("TSP_PORT", 8002)), reload=True)
