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

from fastapi import FastAPI, HTTPException, Request, Header
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import uuid
import time
import redis.asyncio as aioredis
from datetime import datetime
# Typing — pentru a specifica tipuri de date mai complexe
# Optional = un câmp care poate lipsi (e opțional)
from typing import Optional

redis_client: Optional[aioredis.Redis] = None
CA_CERT = None  # x509.Certificate încărcat la startup
CA_KEY = None   # cheie privată CA — NICIODATĂ logată

# Pydantic — pentru definirea structurii datelor așteptate
# BaseModel = clasa de bază pentru orice "model" de date
from pydantic import BaseModel, Field, field_validator


# os — pentru a citi variabilele de mediu (din .env)
import os

# logging — pentru a scrie log-uri structurate
# În producție, log-urile sunt esențiale pentru debugging și audit
import logging

# json — pentru a formata log-urile ca JSON (Structured Logging din spec)
import json
import re
import base64
import hmac
import hashlib
# pyright: ignore [reportMissingImports]
import httpx
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from jose import JWTError, jwt as jose_jwt

# datetime — pentru timestamp-uri în log-uri
from datetime import datetime, timezone, timedelta

# dotenv — citește automat fișierul .env și populează os.environ
# pyright: ignore [reportMissingImports]
from dotenv import load_dotenv
load_dotenv()  # Apelat imediat la import, înainte de orice altceva

# --- JWT CONFIG (după load_dotenv — os.getenv e valid de-abia aici) --------
JWT_SECRET = os.getenv("JWT_SECRET_KEY", "")
JWT_TTL_DAYS = int(os.getenv("JWT_TTL_DAYS", 90))
JWT_ALGORITHM = "HS256"

# --- ROUTING TABLE (replicat din card_network) ------------------------------
# IIN prefix → (bank_url, bank_id) — longest-prefix-match
BANK_ROUTING: dict[str, tuple[str, str]] = {
    "400000": ("http://issuing-bank-bt:8004",  "BT"),
    "422222": ("http://issuing-bank-bt:8004",  "BT"),
    "500000": ("http://issuing-bank-bcr:8006", "BCR"),
    "511111": ("http://issuing-bank-ing:8007", "ING"),
    "4":      ("http://issuing-bank-bt:8004",  "BT"),
    "5":      ("http://issuing-bank-bcr:8006", "BCR"),
}

def find_bank(pan: str) -> tuple[str, str] | None:
    """Returnează (bank_url, bank_id) sau None — longest-prefix-match."""
    for length in range(6, 0, -1):
        prefix = pan[:length]
        if prefix in BANK_ROUTING:
            return BANK_ROUTING[prefix]
    return None

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


# --- EVENT HANDLERS -----------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    global redis_client, CA_CERT, CA_KEY
    
    # Suprascriem logger-ele implicite din uvicorn pentru a folosi formatul JSON
    for logger_name in ("uvicorn", "uvicorn.access", "uvicorn.error"):
        u_logger = logging.getLogger(logger_name)
        u_logger.handlers = [handler]
        u_logger.propagate = False

    try:
        redis_client = aioredis.Redis(
            host=os.getenv("REDIS_HOST", "redis-master"),
            port=int(os.getenv("REDIS_PORT", 6379)),
            password=os.getenv("REDIS_PASSWORD"),
            decode_responses=True
        )
        await redis_client.ping()
        logger.info("Conexiune Redis stabilită", extra={"event_type": "REDIS_CONNECTED"})
    except Exception as e:
        logger.error(f"Redis indisponibil la startup: {e}", extra={"event_type": "REDIS_ERROR"})

    try:
        with open("/app/certs/ca.crt", "rb") as f:
            CA_CERT = x509.load_pem_x509_certificate(f.read())
        with open("/app/certs/ca.key", "rb") as f:
            CA_KEY = serialization.load_pem_private_key(f.read(), password=None)
        logger.info("CA încărcat", extra={"event_type": "CA_LOADED"})
    except Exception as e:
        logger.error(f"CA indisponibil: {e}", extra={"event_type": "CA_ERROR"})

    logger.info(
        "Payment Gateway pornit",
        extra={"event_type": "SERVICE_STARTUP"}
    )
    logger.info(
        f"Mediu: {os.getenv('ENVIRONMENT', 'development')}",
        extra={"event_type": "SERVICE_STARTUP"}
    )
    yield
    
    if redis_client:
        await redis_client.aclose()

# --- CREAREA APLICAȚIEI FASTAPI -----------------------------
app = FastAPI(
    title="NFC Payment Gateway",
    description="Microserviciu care primește cereri de la terminalele POS",
    version="1.0.0",
    lifespan=lifespan
)

from prometheus_fastapi_instrumentator import Instrumentator

Instrumentator().instrument(app).expose(app)

# --- JWT UTILITIES ------------------------------------------

def create_jwt(dpan: str) -> str:
    """Generează un JWT Bearer pentru un DPAN (Android authentication)."""
    expire = datetime.now(timezone.utc) + timedelta(days=JWT_TTL_DAYS)
    return jose_jwt.encode(
        {
            "sub": dpan,
            "exp": expire,
            "iat": datetime.now(timezone.utc)
        },
        JWT_SECRET,
        algorithm=JWT_ALGORITHM
    )


def verify_jwt(token: str) -> str:
    """Decodează și verifică un JWT. Returnează dpan sau ridică HTTPException 401."""
    try:
        payload = jose_jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        dpan = payload.get("sub")
        if not dpan:
            raise JWTError("sub lipsă")
        return dpan
    except JWTError:
        raise HTTPException(
            status_code=401,
            detail={
                "error_code": "INVALID_TOKEN",
                "message": "Token JWT invalid sau expirat."
            }
        )


def get_dpan_from_auth(authorization: Optional[str] = Header(None)) -> str:
    """FastAPI dependency — extrage dpan din header Authorization: Bearer <token>."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail={
                "error_code": "MISSING_TOKEN",
                "message": "Header Authorization: Bearer <token> lipsă."
            }
        )
    return verify_jwt(authorization.split(" ")[1])


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
    # Field() adaugă validări și documentație extra
    amount: int = Field(..., gt=0, description="Suma tranzacției in bani (trebuie să fie > 0)")
    
    # str = șir de caractere
    currency: str = Field(..., min_length=3, max_length=3, description="Codul monedei (ex: RON)")
    
    # Nonce-ul generat de POS — un număr aleatoriu unic per tranzacție
    # Rol: previne Replay Attacks (din glosar: "Number used ONCE")
    pos_nonce: str = Field(..., description="Număr aleatoriu unic generat de POS")
    
    # Timestamp-ul POS-ului în format ISO 8601
    # Ex: "2026-04-10T14:30:00Z"
    terminal_timestamp: str = Field(..., description="Timestamp-ul POS (ISO 8601)")

    @field_validator("terminal_timestamp")
    @classmethod
    def validate_timestamp(cls, v: str) -> str:
        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
            return v
        except ValueError:
            raise ValueError("terminal_timestamp trebuie să fie ISO 8601 valid")


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

class ChallengePaymentRequest(BaseModel):
    transaction_id: str
    original_dpan: str  # pentru a determina banca
    pin_block_encrypted: str

class PKIRenewRequest(BaseModel):
    csr_pem_b64: str

class EnrollRequest(BaseModel):
    pan: str = Field(..., description="PAN-ul cardului fizic")
    expiry_month: str = Field(..., min_length=1, max_length=2, description="Luna de expirare (ex: '12')")
    expiry_year: str = Field(..., min_length=2, max_length=4, description="Anul de expirare (ex: '28')")
    cvv: str = Field(..., min_length=3, max_length=4, description="CVV — verificat și aruncat, NU stocat")
    device_id: str = Field(..., description="UUID unic al telefonului Android")

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


@app.post("/api/v1/payments/challenge")
async def challenge_payment(
    request: Request,
    payload: ChallengePaymentRequest,
    x_idempotency_key: Optional[str] = Header(None, alias="X-Idempotency-Key"),
    x_terminal_id: Optional[str] = Header(None, alias="X-Terminal-Id")
):
    idempotency_key = x_idempotency_key
    terminal_id = x_terminal_id

    if not idempotency_key:
        raise HTTPException(400, {"error_code": "MISSING_IDEMPOTENCY_KEY"})
    if not terminal_id:
        raise HTTPException(400, {"error_code": "MISSING_TERMINAL_ID"})

    # Detokenizare pentru a afla banca
    try:
        async with httpx.AsyncClient(timeout=0.3) as client:
            tsp_response = await client.post(
                "http://tsp:8002/api/v1/tokens/detokenize",
                json={"dpan": payload.original_dpan, "trace_id": idempotency_key}
            )
        if tsp_response.status_code != 200:
            raise HTTPException(400, {"error_code": "INVALID_TOKEN"})
        pan = tsp_response.json().get("pan")
    except httpx.TimeoutException:
        raise HTTPException(503, {"error_code": "TSP_TIMEOUT"})

    # Rutare către banca corectă via Card Network
    try:
        async with httpx.AsyncClient(timeout=1.2) as client:
            bank_response = await client.post(
                "http://card-network:8003/api/v1/challenge/route",
                json={
                    "pan": pan,
                    "transaction_id": payload.transaction_id,
                    "idempotency_key": idempotency_key,
                    "terminal_id": terminal_id,
                    "pin_block_encrypted": payload.pin_block_encrypted
                }
            )
        # Propagăm status code-ul exact de la bancă (400 INCORRECT_PIN, 503, etc.)
        return JSONResponse(
            content=bank_response.json(),
            status_code=bank_response.status_code
        )
    except httpx.TimeoutException:
        raise HTTPException(503, {"error_code": "BANK_TIMEOUT"})

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
    
    """
    
    # --- PASUL 1: Validare Headers ---------------------------
    # Din spec (Cap. 2.2): headers obligatorii sunt
    # X-Idempotency-Key și X-Terminal-Id
    
    idempotency_key = x_idempotency_key
    terminal_id = x_terminal_id
    
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

    # Validare mTLS — CN din certificat trebuie să coincidă cu Terminal-Id
    # NGINX garantează că X-SSL-Client-CN vine din certificatul TLS, nu din request body.
    # Un POS care prezintă cert POS-BUC-001 poate activa DOAR ca terminal POS-BUC-001.
    ssl_client_dn = request.headers.get("X-SSL-Client-DN", "")
    cn_match = re.search(r"CN=([^,/]+)", ssl_client_dn)
    ssl_client_cn = cn_match.group(1).strip() if cn_match else None

    if ssl_client_cn and ssl_client_cn != terminal_id:
        logger.warning(
            f"Mismatch CN certificat vs Terminal-Id: cert={ssl_client_cn}, header={terminal_id}",
            extra={
                "event_type": "MTLS_CN_MISMATCH",
                "terminal_id": terminal_id,
                "trace_id": idempotency_key
            }
        )
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": "CERTIFICATE_MISMATCH",
                "message": "Identitatea terminalului nu corespunde certificatului.",
                "action_required": "CONTACT_SUPPORT"
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

    # --- FAIL-CLOSED: Validare Redis ---
    # Trebuie să fie ÎNAINTEA oricărei operații Redis (blacklist, rate limiting, idempotență).
    # Dacă Redis e jos, respingem cererea — este preferabil față de a procesa fără protecții.
    if not redis_client:
        logger.error("Redis indisponibil. Respingere cerere (Fail-Closed).", extra={"event_type": "FAIL_CLOSED"})
        raise HTTPException(
            status_code=503,
            detail={
                "error_code": "IDEMPOTENCY_STORE_DOWN",
                "message": "Serviciu temporar indisponibil",
                "retry_after_ms": 5000,
                "action_required": "NONE"
            }
        )
    try:
        # Blacklist Redis — revocarea operațională (complement la revocarea PKI)
        is_revoked = await redis_client.sismember("revoked_terminals", terminal_id)
        if is_revoked:
            logger.warning(
                f"Terminal revocat a încercat conexiunea: {terminal_id}",
                extra={"event_type": "REVOKED_TERMINAL_BLOCKED", "terminal_id": terminal_id}
            )
            raise HTTPException(
                status_code=403,
                detail={
                    "error_code": "TERMINAL_REVOKED",
                    "message": "Terminal dezactivat. Contactați suportul.",
                    "action_required": "CONTACT_SUPPORT"
                }
            )
        
        # --- PASUL 2: Rate Limiting (Sliding Window Log per terminal) ---
        # Sliding Window elimină problema Fixed Window (granița secundei).
        # ZADD + ZREMRANGEBYSCORE + ZCARD = atomic via pipeline.
        rate_key = f"rate:{terminal_id}"
        now_ts = time.time()
        window_start = now_ts - 1.0  # fereastră de 1 secundă

        pipe = redis_client.pipeline()
        # 1. Șterge cererile mai vechi de 1 secundă
        pipe.zremrangebyscore(rate_key, 0, window_start)
        # 2. Adaugă cererea curentă (score = timestamp, member = timestamp ca string)
        pipe.zadd(rate_key, {str(now_ts): now_ts})
        # 3. Numără cererile din fereastră
        pipe.zcard(rate_key)
        # 4. TTL de curățare
        pipe.expire(rate_key, 2)
        _, _, count, _ = await pipe.execute()

        if count > 2:
            logger.warning(
                f"Rate limit depășit pentru terminalul {terminal_id}",
                extra={
                    "event_type": "RATE_LIMIT_EXCEEDED",
                    "terminal_id": terminal_id,
                    "trace_id": idempotency_key
                }
            )
            raise HTTPException(
                status_code=429,
                detail={
                    "error_code": "RATE_LIMIT_EXCEEDED",
                    "message": "Prea multe cereri. Maxim 2 cereri pe secundă.",
                    "retry_after_ms": 1000,
                    "action_required": "RETRY_LATER"
                }
            )
        
        # --- PASUL 3: Idempotență (Redis SET atomic) -------------------------
        idemp_key = f"idemp:{idempotency_key}"
        
        # Încercăm să scriem cheia cu flag-ul NX (Not eXists) și EX atomic.
        is_new = await redis_client.set(
            idemp_key, 
            "PROCESSING",
            nx=True,      # Only set if Not eXists
            ex=30         # Expire în 30 secunde, setat atomic
        )
        if not is_new:
                # Cheia există deja. Verificăm valoarea.
                cached_val = await redis_client.get(idemp_key)
                if cached_val == "PROCESSING":
                    logger.warning(
                        "Cerere concurentă cu aceeași cheie de idempotență",
                        extra={"event_type": "CONCURRENT_REQUEST_BLOCKED", "terminal_id": terminal_id, "trace_id": idempotency_key}
                    )
                    raise HTTPException(
                        status_code=409,
                        detail={
                            "error_code": "CONCURRENT_REQUEST",
                            "message": "O cerere cu acest idempotency key este deja în procesare",
                            "retry_after_ms": 2000,
                            "action_required": "RETRY_LATER"
                        }
                    )
                elif cached_val is None:
                    # Cheia a expirat între verificare și citire — tratăm ca nouă cerere
                    logger.warning("Idempotency key expirat între set și get", extra={"event_type": "IDEMP_KEY_EXPIRED", "trace_id": idempotency_key})
                    raise HTTPException(status_code=503, detail={"error_code": "IDEMPOTENCY_STORE_DOWN", "retry_after_ms": 1000})
                
                # Altfel înseamnă că tranzacția s-a terminat anterior și avem răspunsul JSON cached.
                logger.info(
                    "Returnare răspuns din cache (idempotență)",
                    extra={"event_type": "IDEMPOTENT_RESPONSE_RETURNED", "terminal_id": terminal_id, "trace_id": idempotency_key}
                )
                return PaymentResponse(**json.loads(cached_val))

    except HTTPException:
        raise  # re-ridici excepțiile HTTP — nu le tratezi ca erori Redis

    except Exception as e:
        logger.error(
                f"Redis indisponibil: {e}",
                extra={"event_type": "REDIS_ERROR", "terminal_id": terminal_id}
        )
        raise HTTPException(
            status_code=503,
            detail={
                "error_code": "IDEMPOTENCY_STORE_DOWN",
                "message": "Serviciu temporar indisponibil.",
                "retry_after_ms": 5000,
                "action_required": "NONE"
            }
        )
    
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
            "TSP a returnat detaliile cu succes.",
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
    except httpx.HTTPStatusError as exc:
        logger.error(
            f"Eroare HTTP de la TSP: {exc.response.status_code}",
            extra={"event_type": "TSP_HTTP_ERROR", "trace_id": idempotency_key, "terminal_id": terminal_id}
        )
        raise HTTPException(
            status_code=503,
            detail={
                "error_code": "TSP_SERVICE_ERROR",
                "message": "TSP a returnat o eroare internă",
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

    # --- PASUL 5: Rutare către Card Network ------------------------------
    logger.info(
        "Trimitere request către Card Network...",
        extra={"event_type": "CARD_NETWORK_ROUTING", "trace_id": idempotency_key, "terminal_id": terminal_id}
    )
    
    card_network_url = "http://card-network:8003/api/v1/transactions/route"
    card_network_payload = {
        "pan": pan,
        "risk_level": tsp_data.get("risk_level", 0),
        "transaction": payment.transaction.model_dump(),
        "cryptogram": payment.cryptogram.model_dump(),
        "idempotency_key": idempotency_key,
        "terminal_id": terminal_id
    }
    
    # Timeout setat la 1.2s pentru a menține SLA-urile P99 (1500ms total)
    try:
        async with httpx.AsyncClient(timeout=1.2) as client:
            card_network_response = await client.post(
                card_network_url,
                json=card_network_payload
            )
            
        if card_network_response.status_code == 401:
            error_data = card_network_response.json().get("detail", {})
            logger.warning(
                "Card Network cere Step-Up Authentication.",
                extra={"event_type": "STEP_UP_REQUIRED", "trace_id": idempotency_key, "terminal_id": terminal_id}
            )
            # TODO: PoC — idemp_key rămâne "PROCESSING" cu TTL 30s.
            # Producție: salvează starea CHALLENGE_REQUIRED în Redis ca stare finală.
            raise HTTPException(status_code=401, detail=error_data)

        if card_network_response.status_code == 400:
            error_data = card_network_response.json().get("detail", {})
            logger.warning(
                f"Card Network a respins tranzacția: {error_data.get('message', 'N/A')}",
                extra={"event_type": "CARD_NETWORK_REJECTED", "trace_id": idempotency_key, "terminal_id": terminal_id}
            )
            raise HTTPException(status_code=400, detail=error_data)
            
        card_network_response.raise_for_status()
        
        bank_data = card_network_response.json()
        
    except httpx.TimeoutException:
        logger.error(
            "Timeout (1200ms) la comunicarea cu Card Network",
            extra={"event_type": "CARD_NETWORK_TIMEOUT", "trace_id": idempotency_key, "terminal_id": terminal_id}
        )
        raise HTTPException(
            status_code=503,
            detail={
                "error_code": "CARD_NETWORK_SERVICE_UNAVAILABLE",
                "message": "Card Network nu a răspuns în timp util",
                "retry_after_ms": 1000,
                "action_required": "RETRY_LATER"
            }
        )
    except httpx.HTTPStatusError as exc:
        logger.error(
            f"Eroare HTTP de la Card Network: {exc.response.status_code}",
            extra={"event_type": "CARD_NETWORK_HTTP_ERROR", "trace_id": idempotency_key, "terminal_id": terminal_id}
        )
        raise HTTPException(
            status_code=503,
            detail={
                "error_code": "CARD_NETWORK_SERVICE_ERROR",
                "message": "Card Network a returnat o eroare internă",
                "retry_after_ms": 1000,
                "action_required": "RETRY_LATER"
            }
        )
    except httpx.RequestError as exc:
        logger.error(
            f"Eroare rețea la comunicarea cu Card Network: {exc}",
            extra={"event_type": "CARD_NETWORK_NETWORK_ERROR", "trace_id": idempotency_key, "terminal_id": terminal_id}
        )
        raise HTTPException(status_code=503, detail="Card Network connection failed")

    # --- INSPECȚIE BODY (HTTP 200 nu implică APPROVED) ---
    # DECLINED și APPROVED sunt ambele HTTP 200 — trebuie inspectat câmpul status din body.
    bank_status = bank_data.get("status", "DECLINED")

    if bank_status == "DECLINED":
        logger.warning(
            f"Tranzacție RESPINSĂ de bancă. Risk score: {bank_data.get('risk_score', 'N/A')}",
            extra={"event_type": "TX_DECLINED", "trace_id": idempotency_key, "terminal_id": terminal_id}
        )
    else:
        logger.info(
            "Tranzacție APROBATĂ de bancă.",
            extra={"event_type": "CARD_NETWORK_TRANSACTION_APPROVED", "trace_id": idempotency_key, "terminal_id": terminal_id}
        )

    final_response = PaymentResponse(
        status=bank_status,
        transaction_id=bank_data.get("transaction_id", f"TXN-{uuid.uuid4().hex[:12].upper()}"),
        auth_code=bank_data.get("auth_code"),
        risk_score=bank_data.get("risk_score", 0),
        processed_at=bank_data.get("processed_at", datetime.now(timezone.utc).isoformat())
    )

    # DECLINED se cachează 30 min (nu 24h) — permite retry după Risk Decay
    # APPROVED se cachează 24h pentru idempotență completă
    cache_ttl = 1800 if bank_status == "DECLINED" else 86400
    
    # --- FAIL-CLOSED: Validare Redis ---
    # Dacă Redis e jos, respingem raspunsul final
    try:
        await redis_client.setex(idemp_key, cache_ttl, final_response.model_dump_json())
    except Exception as e:
        logger.error(
            f"Redis indisponibil: {e}",
            extra={"event_type": "REDIS_ERROR", "terminal_id": terminal_id}
        )
        raise HTTPException(
            status_code=503,
            detail={
                "error_code": "IDEMPOTENCY_STORE_DOWN",
                "message": "Serviciu temporar indisponibil.",
                "retry_after_ms": 5000,
                "action_required": "NONE"
            }
        )
    return final_response

@app.post("/api/v1/enroll")
async def enroll_card(payload: EnrollRequest):
    """
    Înrolează un card fizic și generează DPAN + HMAC key + JWT pentru Android.
    Accesibil EXCLUSIV prin NGINX port 8443 (TLS, fără mTLS).

    SECURITATE CRITICĂ:
      - CVV NU apare în log-uri, NU se stochează, NU se transmite plain text
      - K_user NU apare în log-uri
      - PAN-ul complet este mascat în log-uri (doar primele 6 cifre / IIN)
    """
    iin = payload.pan[:6]
    logger.info(
        f"Cerere enroll primită (IIN: {iin})",
        extra={"event_type": "ENROLL_REQUEST"}
    )

    # 1. Determină banca din prefix PAN
    bank = find_bank(payload.pan)
    if not bank:
        logger.warning(
            f"Bancă necunoscută pentru IIN: {iin}",
            extra={"event_type": "ENROLL_FAILED", "reason": "UNSUPPORTED_BANK"}
        )
        raise HTTPException(status_code=400, detail={"error_code": "UNSUPPORTED_BANK"})
    bank_url, bank_id = bank

    # 2. Calculează cvv_hash = SHA256(pan + cvv) — CVV-ul plain text NU circulă pe rețea
    cvv_hash = hashlib.sha256((payload.pan + payload.cvv).encode()).hexdigest()

    # 3. Verifică cardul în Issuing Bank (cu cvv_hash, nu CVV plain text)
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            verify_resp = await client.post(
                f"{bank_url}/api/v1/admin/verify-card",
                json={
                    "pan": payload.pan,
                    "expiry_month": payload.expiry_month,
                    "expiry_year": payload.expiry_year,
                    "cvv_hash": cvv_hash
                }
            )
        if verify_resp.status_code != 200:
            logger.warning(
                "Verificare card eșuată la Issuing Bank",
                extra={"event_type": "ENROLL_FAILED", "reason": "INVALID_CARD_DATA"}
            )
            raise HTTPException(status_code=400, detail={"error_code": "INVALID_CARD_DATA"})
    except httpx.TimeoutException:
        logger.error(
            "Timeout la verificarea cardului",
            extra={"event_type": "ENROLL_FAILED", "reason": "BANK_TIMEOUT"}
        )
        raise HTTPException(status_code=503, detail={"error_code": "BANK_TIMEOUT"})

    # 4. Generează DPAN
    dpan = f"TKN-{uuid.uuid4().hex[:16].upper()}"

    # 5. Derivă K_user din HMAC(K_master, device_id)
    #    Același utilizator pe telefoane diferite → chei diferite (bound to device)
    k_master_hex = os.getenv(f"BANK_{bank_id}_HMAC_KEY", "")
    if not k_master_hex:
        logger.error(
            f"BANK_{bank_id}_HMAC_KEY lipsă din configurație",
            extra={"event_type": "ENROLL_FAILED", "reason": "CONFIG_ERROR"}
        )
        raise HTTPException(status_code=503, detail={"error_code": "SERVICE_UNAVAILABLE"})

    try:
        k_master = bytes.fromhex(k_master_hex)
        k_user = hmac.new(k_master, payload.device_id.encode("utf-8"), hashlib.sha256).hexdigest()
    except ValueError:
        logger.error(
            f"BANK_{bank_id}_HMAC_KEY invalid (format hex incorect)",
            extra={"event_type": "ENROLL_FAILED", "reason": "CONFIG_ERROR"}
        )
        raise HTTPException(status_code=503, detail={"error_code": "SERVICE_UNAVAILABLE"})

    # 6. Înregistrează DPAN în TSP
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            tsp_resp = await client.post(
                "http://tsp:8002/api/v1/tokens/register",
                json={"dpan": dpan, "pan": payload.pan, "risk_level": 0}
            )
        if tsp_resp.status_code != 200:
            logger.error(
                "Înregistrare token în TSP eșuată",
                extra={"event_type": "ENROLL_FAILED", "reason": "TSP_ERROR"}
            )
            raise HTTPException(status_code=503, detail={"error_code": "TSP_ERROR"})
    except httpx.TimeoutException:
        logger.error(
            "Timeout la înregistrarea token-ului în TSP",
            extra={"event_type": "ENROLL_FAILED", "reason": "TSP_TIMEOUT"}
        )
        raise HTTPException(status_code=503, detail={"error_code": "TSP_TIMEOUT"})

    # 7. Citește cheia publică RSA a băncii (distribuită la Android)
    bank_pub_key_path = f"/app/certs/bank_{bank_id.lower()}_public.pem"
    try:
        with open(bank_pub_key_path, "rb") as f:
            bank_pub_key_pem = f.read()
    except FileNotFoundError:
        logger.error(
            f"Cheie publică bancă lipsă: {bank_pub_key_path}",
            extra={"event_type": "ENROLL_FAILED", "reason": "MISSING_BANK_KEY"}
        )
        raise HTTPException(status_code=503, detail={"error_code": "SERVICE_UNAVAILABLE"})

    # 8. Generează JWT + stochează în Redis pentru invalidare viitoare
    jwt_token = create_jwt(dpan)
    jwt_expire = datetime.now(timezone.utc) + timedelta(days=JWT_TTL_DAYS)

    if redis_client:
        try:
            await redis_client.setex(f"jwt:{dpan}", JWT_TTL_DAYS * 86400, "active")
        except Exception as e:
            logger.warning(
                f"Nu s-a putut stoca JWT în Redis: {e}",
                extra={"event_type": "ENROLL_REDIS_WARN"}
            )

    logger.info(
        f"Enroll reușit pentru DPAN={dpan}, bank={bank_id}, device={payload.device_id}",
        extra={"event_type": "ENROLL_SUCCESS"}
    )

    return {
        "dpan": dpan,
        "hmac_key_hex": k_user,         # K_user — NU se logează niciodată
        "jwt_token": jwt_token,
        "jwt_expires_at": jwt_expire.isoformat(),
        "biometric_threshold_ron": 10000,
        "bank_public_key_pem_b64": base64.b64encode(bank_pub_key_pem).decode()
    }


@app.get("/api/v1/accounts/balance")
async def get_account_balance(authorization: Optional[str] = Header(None)):
    """
    Returnează soldul contului Android.
    Autentificare: Authorization: Bearer <jwt_token>
    Accesibil EXCLUSIV prin NGINX port 8443.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail={"error_code": "MISSING_TOKEN", "message": "Header Authorization: Bearer <token> lipsă."}
        )
    token = authorization.split(" ")[1]
    dpan = verify_jwt(token)

    # Verifică dacă JWT expiră în < 30 zile (pentru refresh automat)
    decoded = jose_jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    exp = datetime.fromtimestamp(decoded["exp"], tz=timezone.utc)
    days_remaining = (exp - datetime.now(timezone.utc)).days

    # Detokenizare DPAN → PAN via TSP
    try:
        async with httpx.AsyncClient(timeout=0.3) as client:
            tsp_resp = await client.post(
                "http://tsp:8002/api/v1/tokens/detokenize",
                json={"dpan": dpan}
            )
        if tsp_resp.status_code != 200:
            raise HTTPException(status_code=400, detail={"error_code": "INVALID_TOKEN"})
        pan = tsp_resp.json()["pan"]
    except httpx.TimeoutException:
        raise HTTPException(status_code=503, detail={"error_code": "TSP_TIMEOUT"})

    # Determină banca
    bank = find_bank(pan)
    if not bank:
        raise HTTPException(status_code=400, detail={"error_code": "UNSUPPORTED_BANK"})
    bank_url, bank_id = bank

    # Preia soldul de la Issuing Bank
    try:
        async with httpx.AsyncClient(timeout=0.5) as client:
            bal_resp = await client.get(
                f"{bank_url}/api/v1/admin/balance",
                params={"pan": pan}
            )
        if bal_resp.status_code != 200:
            raise HTTPException(status_code=503, detail={"error_code": "BALANCE_UNAVAILABLE"})
        bal_data = bal_resp.json()
    except httpx.TimeoutException:
        raise HTTPException(status_code=503, detail={"error_code": "BANK_TIMEOUT"})

    # Refresh JWT automat dacă mai sunt < 30 zile
    new_token = None
    jwt_refreshed = False
    if days_remaining < 30:
        new_token = create_jwt(dpan)
        jwt_refreshed = True
        if redis_client:
            try:
                await redis_client.setex(f"jwt:{dpan}", JWT_TTL_DAYS * 86400, "active")
            except Exception:
                pass

    return {
        "balance_ron": bal_data["balance_ron"],
        "dpan_masked": f"TKN-****{dpan[-4:]}",
        "bank_id": bank_id,
        "jwt_refreshed": jwt_refreshed,
        "new_jwt_token": new_token
    }


@app.get("/api/v1/transactions/history")
async def get_transaction_history(authorization: Optional[str] = Header(None)):
    """
    Returnează istoricul tranzacțiilor pentru Android.
    Autentificare: Authorization: Bearer <jwt_token>
    Accesibil EXCLUSIV prin NGINX port 8443.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail={"error_code": "MISSING_TOKEN", "message": "Header Authorization: Bearer <token> lipsă."}
        )
    token = authorization.split(" ")[1]
    dpan = verify_jwt(token)

    # Detokenizare DPAN → PAN via TSP
    try:
        async with httpx.AsyncClient(timeout=0.3) as client:
            tsp_resp = await client.post(
                "http://tsp:8002/api/v1/tokens/detokenize",
                json={"dpan": dpan}
            )
        if tsp_resp.status_code != 200:
            raise HTTPException(status_code=400, detail={"error_code": "INVALID_TOKEN"})
        pan = tsp_resp.json()["pan"]
    except httpx.TimeoutException:
        raise HTTPException(status_code=503, detail={"error_code": "TSP_TIMEOUT"})

    # Determină banca
    bank = find_bank(pan)
    if not bank:
        raise HTTPException(status_code=400, detail={"error_code": "UNSUPPORTED_BANK"})
    bank_url, bank_id = bank

    # Preia tranzacțiile de la Issuing Bank (filtrate după PAN)
    try:
        async with httpx.AsyncClient(timeout=0.5) as client:
            txn_resp = await client.get(
                f"{bank_url}/api/v1/admin/transactions",
                params={"pan": pan}
            )
        if txn_resp.status_code != 200:
            raise HTTPException(status_code=503, detail={"error_code": "TRANSACTIONS_UNAVAILABLE"})
        txn_data = txn_resp.json()
    except httpx.TimeoutException:
        raise HTTPException(status_code=503, detail={"error_code": "BANK_TIMEOUT"})

    return {
        "transactions": [
            {
                "transaction_id": t["transaction_id"],
                "amount_ron": t.get("amount", 0) / 100,
                "currency": t.get("currency", "RON"),
                "status": t.get("status", "UNKNOWN"),
                "risk_score": t.get("risk_score", 0),
                "terminal_id": t.get("terminal_id", "UNKNOWN"),
                "timestamp": t.get("timestamp", "")
            }
            for t in txn_data.get("transactions", [])
        ]
    }


@app.post("/api/pki/renew")
async def renew_certificate(
    request: Request,
    payload: PKIRenewRequest,
    x_terminal_id: Optional[str] = Header(None, alias="X-Terminal-Id")
):
    """
    Reînnoiește certificatul mTLS al unui terminal POS.
    Accesat EXCLUSIV prin NGINX (mTLS obligatoriu — ssl_verify_client on).
    PoC: nu verificăm data expirării certificatului curent.
    """
    terminal_id = x_terminal_id or "UNKNOWN"

    logger.info(
        f"Cerere reînnoire certificat de la terminal {terminal_id}",
        extra={"event_type": "PKI_RENEWAL_REQUEST", "terminal_id": terminal_id}
    )

    if CA_CERT is None or CA_KEY is None:
        logger.error(
            "CA indisponibil — nu se poate semna certificatul",
            extra={"event_type": "PKI_RENEWAL_FAILED", "terminal_id": terminal_id, "reason": "CA_UNAVAILABLE"}
        )
        raise HTTPException(status_code=503, detail={"error_code": "CA_UNAVAILABLE"})

    # 1. Decodare și parsare CSR
    try:
        csr_bytes = base64.b64decode(payload.csr_pem_b64)
        csr = x509.load_pem_x509_csr(csr_bytes)
    except Exception:
        logger.warning(
            "CSR invalid (decodare sau parsare eșuată)",
            extra={"event_type": "PKI_RENEWAL_FAILED", "terminal_id": terminal_id, "reason": "INVALID_CSR"}
        )
        raise HTTPException(status_code=400, detail={"error_code": "INVALID_CSR"})

    # 2. Extragere CN din CSR
    try:
        csr_cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except (IndexError, Exception):
        logger.warning(
            "CSR fără câmp CN",
            extra={"event_type": "PKI_RENEWAL_FAILED", "terminal_id": terminal_id, "reason": "MISSING_CN"}
        )
        raise HTTPException(status_code=400, detail={"error_code": "INVALID_CSR", "detail": "CN lipsă din CSR"})

    # 3. Validare CN: un terminal nu poate reînnoi certificatul altui terminal
    ssl_dn = request.headers.get("X-SSL-Client-DN", "")
    cn_match = re.search(r"CN=([^,/]+)", ssl_dn)
    mtls_cn = cn_match.group(1).strip() if cn_match else None

    if mtls_cn and csr_cn != mtls_cn:
        logger.warning(
            f"CN mismatch: CSR CN={csr_cn}, mTLS CN={mtls_cn}",
            extra={"event_type": "PKI_RENEWAL_FAILED", "terminal_id": terminal_id, "reason": "CN_MISMATCH"}
        )
        raise HTTPException(status_code=403, detail={"error_code": "CN_MISMATCH"})

    # 4. Semnare CSR cu CA-ul intern
    try:
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(CA_CERT.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=30))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True
            )
            .sign(CA_KEY, hashes.SHA256())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        ca_pem = CA_CERT.public_bytes(serialization.Encoding.PEM)

    except Exception as e:
        logger.error(
            f"Eroare la semnarea CSR: {e}",
            extra={"event_type": "PKI_RENEWAL_FAILED", "terminal_id": terminal_id, "reason": "SIGNING_ERROR"}
        )
        raise HTTPException(status_code=500, detail={"error_code": "SIGNING_ERROR"})

    logger.info(
        f"Certificat nou emis pentru terminal {terminal_id} (CN={csr_cn})",
        extra={"event_type": "PKI_RENEWAL_SUCCESS", "terminal_id": terminal_id}
    )

    return {
        "certificate_pem_b64": base64.b64encode(cert_pem).decode(),
        "ca_certificate_pem_b64": base64.b64encode(ca_pem).decode(),
        "valid_days": 30,
        "issued_at": now.isoformat()
    }


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
