# ============================================================
# main.py — Payment Gateway
#
# Acesta este "creierul" primului microserviciu.
# Responsabilitățile sale (din specificație):
#   1. Primește cereri HTTP de la terminalul POS (ESP32)
#   2. Verifică rate limiting (max 2 req/sec per terminal)
#   3. Verifică idempotența (aceeași cerere nu se procesează de 2 ori)
#   4. Rutează cererea mai departe către TSP și Issuing Bank
#
# Deocamdată implementăm scheletul și endpoint-ul /health.
# Logica completă se adaugă pas cu pas.
# ============================================================


# --- IMPORTURI ----------------------------------------------
# "import" = încarcă o librărie/modul în memorie ca să îl putem folosi

# FastAPI — framework-ul principal
# FastAPI() = creează aplicația web
# HTTPException = eroare HTTP standard (ex: 400, 401, 429)
# Request = reprezintă o cerere HTTP primită
import collections
from fastapi import FastAPI, HTTPException, Request, Header

# Pydantic — pentru definirea structurii datelor așteptate
# BaseModel = clasa de bază pentru orice "model" de date
from pydantic import BaseModel, Field

# Typing — pentru a specifica tipuri de date mai complexe
# Optional = un câmp care poate lipsi (e opțional)
from typing import Optional

# os — pentru a citi variabilele de mediu (din .env)
import os

# logging — pentru a scrie log-uri structurate
# În producție, log-urile sunt esențiale pentru debugging și audit
import logging

# json — pentru a formata log-urile ca JSON (Structured Logging din spec)
import json
import re
import httpx

# datetime — pentru timestamp-uri în log-uri
from datetime import datetime, timezone

# dotenv — citește automat fișierul .env și populează os.environ
from dotenv import load_dotenv
load_dotenv()  # Apelat imediat la import, înainte de orice altceva


# --- CONFIGURAREA LOG-URILOR --------------------------------
# Din specificație (Cap. 7.1): "toate componentele vor genera log-uri
# exclusiv în format JSON (Structured Logging)"
#
# De ce JSON? Pentru că un SIEM (Wazuh, etc.) poate parsa automat
# JSON și căuta după câmpuri specifice (ex: toți event_type="FRAUD_SCORED")

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
            "service": "payment-gateway",
            "event_type": getattr(record, "event_type", "GENERAL"),
            "message": masked_message,
        }
        
        if hasattr(record, "terminal_id"):
            log_entry["terminal_id"] = record.terminal_id
        if hasattr(record, "trace_id"):
            log_entry["trace_id"] = record.trace_id
            
        return json.dumps(log_entry, ensure_ascii=False)


# Configurăm logger-ul global al aplicației
logger = logging.getLogger("gateway")
logger.setLevel(logging.INFO)

# Adăugăm un handler care scrie în consolă (stdout)
# Docker captează automat stdout și îl face accesibil cu "docker logs"
handler = logging.StreamHandler()
handler.setFormatter(MaskedJSONFormatter())

if not logger.handlers:
    logger.addHandler(handler)


# --- CREAREA APLICAȚIEI FASTAPI -----------------------------
# FastAPI() creează instanța principală a aplicației.
# Parametrii sunt opționali dar utili pentru documentația automată.
app = FastAPI(
    title="NFC Payment Gateway",
    description="Microserviciu care primește cereri de la terminalele POS",
    version="1.0.0",
)


# --- MODELELE DE DATE (Pydantic) ----------------------------
# Acestea definesc EXACT ce structură JSON așteptăm de la POS.
# Pydantic validează automat: dacă lipsește un câmp obligatoriu
# sau tipul e greșit, returnează automat HTTP 422 cu detalii.
#
# Corespunde secțiunii 2.2 din specificație: "Request Payload"

class TransactionData(BaseModel):
    """
    Datele tranzacției primite de la POS.
    Corespunde câmpului "transaction" din JSON-ul de request.
    """
    # float = număr cu zecimale (ex: 150.00)
    # Field() adaugă validări și documentație extra
    amount: float = Field(..., gt=0, description="Suma tranzacției (trebuie să fie > 0)")
    
    # str = șir de caractere
    currency: str = Field(..., min_length=3, max_length=3, description="Codul monedei (ex: RON)")
    
    # Nonce-ul generat de POS — un număr aleatoriu unic per tranzacție
    # Rol: previne Replay Attacks (din glosar: "Number used ONCE")
    pos_nonce: str = Field(..., description="Număr aleatoriu unic generat de POS")
    
    # Timestamp-ul POS-ului în format ISO 8601
    # Ex: "2026-04-10T14:30:00Z"
    terminal_timestamp: str = Field(..., description="Timestamp-ul POS (ISO 8601)")


class CryptogramData(BaseModel):
    """
    Criptograma generată de aplicația mobilă (HCE).
    Corespunde câmpului "cryptogram" din JSON-ul de request.
    """
    # MAC-ul HMAC-SHA256 calculat de telefon
    # Acesta "semnează" tranzacția — dacă cineva modifică amount,
    # MAC-ul nu mai bate și tranzacția e respinsă (AC-02)
    mac: str = Field(..., description="HMAC-SHA256 al datelor tranzacției")
    
    # ATC = Application Transaction Counter
    # Un contor care crește la fiecare tranzacție
    # Rol: previne Replay Attacks la nivel de backend (Cap. 7.6, T1)
    atc: int = Field(..., ge=0, description="Application Transaction Counter (mereu crescător)")


class PaymentRequest(BaseModel):
    """
    Request-ul complet de autorizare plată.
    Aceasta e structura ÎNTREGULUI JSON primit de la POS.
    
    Corespunde exact endpoint-ului POST /api/v1/payments/authorize
    din specificație (Cap. 2.2).
    """
    # DPAN = Device PAN (numărul virtual al cardului, specific telefonului)
    # Nu e numărul real al cardului — securitate prin tokenizare
    dpan: str = Field(..., description="Device PAN (token al cardului)")
    
    # Câmpurile imbricate folosesc modelele definite mai sus
    transaction: TransactionData
    cryptogram: CryptogramData


class PaymentResponse(BaseModel):
    """
    Răspunsul trimis înapoi la POS după procesare.
    """
    status: str = Field(..., description="APPROVED | DECLINED | CHALLENGE_REQUIRED")
    transaction_id: Optional[str] = Field(None, description="ID-ul unic al tranzacției")
    auth_code: Optional[str] = Field(None, description="Codul de autorizare")
    risk_score: Optional[int] = Field(None, description="Scorul de risc calculat (0-100)")
    processed_at: Optional[str] = Field(None, description="Timestamp procesare")


# --- EVENT HANDLERS -----------------------------------------
# FastAPI permite să rulăm cod la pornire/oprire aplicație

@app.on_event("startup")
async def startup_event():
    """
    Rulează O DATĂ când containerul pornește.
    Ideal pentru: inițializarea conexiunilor, verificări de sănătate.
    
    "async" = această funcție e asincronă (non-blocking).
    În Python async, mai multe operații pot rula "în paralel"
    fără să se blocheze reciproc (important pentru un server web).
    """
    # Suprascriem logger-ele implicite din uvicorn pentru a folosi formatul JSON
    for logger_name in ("uvicorn", "uvicorn.access", "uvicorn.error"):
        u_logger = logging.getLogger(logger_name)
        u_logger.handlers = [handler]
        u_logger.propagate = False

    logger.info(
        "Payment Gateway pornit",
        extra={"event_type": "SERVICE_STARTUP"}
    )
    logger.info(
        f"Mediu: {os.getenv('ENVIRONMENT', 'development')}",
        extra={"event_type": "SERVICE_STARTUP"}
    )


# --- ENDPOINT-URI -------------------------------------------
# Un "endpoint" = o adresă URL la care serviciul nostru răspunde
#
# Sintaxa FastAPI:
# @app.get("/cale")    = răspunde la cereri HTTP GET pe /cale
# @app.post("/cale")   = răspunde la cereri HTTP POST pe /cale
#
# "async def" = funcție asincronă (non-blocking)
# FastAPI gestionează async automat


@app.get("/health")
async def health_check():
    """
    Endpoint de sănătate — verifică dacă serviciul rulează.
    
    De ce avem nevoie de /health?
    - Docker îl poate apela periodic să verifice că serviciul trăiește
    - Un Load Balancer poate exclude containerele "bolnave"
    - Poți verifica rapid: curl http://localhost:8001/health
    
    Returnează HTTP 200 dacă totul e OK.
    """
    return {
        "status": "healthy",
        "service": "payment-gateway",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "1.0.0"
    }


@app.post("/api/v1/payments/authorize", response_model=PaymentResponse)
async def authorize_payment(
    request: Request,           # Obiectul HTTP request complet
    payment: PaymentRequest,    # Body-ul JSON, validat automat de Pydantic
    x_idempotency_key: Optional[str] = Header(None, alias="X-Idempotency-Key", description="Header obligatoriu (ex: test-trace-123)"),
    x_terminal_id: Optional[str] = Header(None, alias="X-Terminal-Id", description="Header obligatoriu (ex: POS-001)")
):
    """
    Endpoint principal de autorizare plată.
    
    Acesta e "inima" Gateway-ului. Primește cererea de la POS și
    o procesează conform fluxului din specificație.
    
    Fluxul complet (din Cap. 5.2):
    1. Validare headers (X-Idempotency-Key, X-Terminal-Id)
    2. Rate Limiting (max 2 req/sec per terminal)
    3. Verificare idempotență (Redis SETNX)
    4. Rutare către TSP → Card Network → Issuing Bank
    5. Returnare răspuns la POS
    
    DEOCAMDATĂ: implementăm doar validarea header-elor.
    Restul logicii se adaugă în pașii următori.
    """
    
    # --- PASUL 1: Validare Headers ---------------------------
    # Din spec (Cap. 2.2): headers obligatorii sunt
    # X-Idempotency-Key și X-Terminal-Id
    
    idempotency_key = request.headers.get("X-Idempotency-Key")
    terminal_id = request.headers.get("X-Terminal-Id")
    
    # Verificăm că header-ele există
    if not idempotency_key:
        logger.warning(
            "Cerere fără X-Idempotency-Key",
            extra={"event_type": "VALIDATION_ERROR", "terminal_id": terminal_id or "UNKNOWN"}
        )
        # HTTPException = returnează automat un răspuns de eroare HTTP
        # status_code=400 = Bad Request
        raise HTTPException(
            status_code=400,
            detail={
                "error_code": "MISSING_IDEMPOTENCY_KEY",
                "message": "Header-ul X-Idempotency-Key este obligatoriu",
                "retry_after_ms": 0,
                "action_required": "NONE"
            }
        )
    
    if not terminal_id:
        logger.warning(
            "Cerere fără X-Terminal-Id",
            extra={"event_type": "VALIDATION_ERROR"}
        )
        raise HTTPException(
            status_code=400,
            detail={
                "error_code": "MISSING_TERMINAL_ID",
                "message": "Header-ul X-Terminal-Id este obligatoriu",
                "retry_after_ms": 0,
                "action_required": "NONE"
            }
        )
    
    # Logăm primirea cererii (audit trail)
    logger.info(
        f"Cerere de autorizare primită de la terminal {terminal_id}",
        extra={
            "event_type": "TX_INITIATED",
            "terminal_id": terminal_id,
            "trace_id": idempotency_key,
        }
    )
    
    # --- PASUL 2: Rate Limiting (TODO) -----------------------
    # Va fi implementat în pasul următor cu Redis
    # Deocamdată lăsăm un comentariu placeholder
    # TODO: Verificare rate limiting cu Redis
    
    
    # --- PASUL 3: Idempotență (TODO) -------------------------
    # Va fi implementat cu Redis SETNX
    # TODO: Verificare idempotență cu Redis SETNX
    
    
    # --- PASUL 4: Rutare către TSP ------------------------------
    logger.info(
        "Trimitere request către TSP pentru detokenizare...",
        extra={"event_type": "TSP_REQUEST_INITIATED", "trace_id": idempotency_key, "terminal_id": terminal_id}
    )
    
    tsp_url = "http://tsp:8002/api/v1/tokens/detokenize"
    tsp_payload = {
        "dpan": payment.dpan,
        "trace_id": idempotency_key
    }
    
    # Timeout setat la 300ms pentru a menține pragul Fail-Fast de 2 secunde alocat Gateway-ului
    try:
        async with httpx.AsyncClient(timeout=0.3) as client:
            tsp_response = await client.post(tsp_url, json=tsp_payload)
            
        if tsp_response.status_code == 404:
            logger.warning(
                "TSP a returnat 404: Token negăsit",
                extra={"event_type": "TSP_TOKEN_NOT_FOUND", "trace_id": idempotency_key, "terminal_id": terminal_id}
            )
            raise HTTPException(
                status_code=400,
                detail={
                    "error_code": "INVALID_TOKEN",
                    "message": "Token-ul (DPAN) este invalid sau inexistent",
                    "retry_after_ms": 0,
                    "action_required": "USE_DIFFERENT_CARD"
                }
            )
            
        tsp_response.raise_for_status()
        
        tsp_data = tsp_response.json()
        pan = tsp_data.get("pan")
        
        logger.info(
            f"TSP a returnat PAN-ul cu succes: {pan}",
            extra={"event_type": "TSP_REQUEST_SUCCESS", "trace_id": idempotency_key, "terminal_id": terminal_id}
        )
        
    except httpx.TimeoutException:
        logger.error(
            "Timeout (300ms) la comunicarea cu TSP",
            extra={"event_type": "TSP_TIMEOUT", "trace_id": idempotency_key, "terminal_id": terminal_id}
        )
        raise HTTPException(
            status_code=503,
            detail={
                "error_code": "TSP_SERVICE_UNAVAILABLE",
                "message": "TSP nu a răspuns în timp util",
                "retry_after_ms": 1000,
                "action_required": "RETRY_LATER"
            }
        )
    except httpx.RequestError as exc:
        logger.error(
            f"Eroare rețea la comunicarea cu TSP: {exc}",
            extra={"event_type": "TSP_NETWORK_ERROR", "trace_id": idempotency_key, "terminal_id": terminal_id}
        )
        raise HTTPException(status_code=503, detail="TSP connection failed")

    # TODO: Mai departe vom adăuga rutarea către Card Network și Issuing Bank.
    
    # Deocamdată returnăm un răspuns mock cu confirmarea că s-a trecut de TSP.
    return PaymentResponse(
        status="APPROVED_TSP_MOCK",
        transaction_id=f"TXN-MOCK-{idempotency_key[:8]}",
        auth_code="MOCK01",
        risk_score=0,
        processed_at=datetime.now(timezone.utc).isoformat()
    )

# --- PORNIRE ---
if __name__ == "__main__":
    import uvicorn
    import os
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.getenv("GATEWAY_PORT", 8001)),
        reload=True
    )
