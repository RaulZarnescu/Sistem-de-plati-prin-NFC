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
from contextlib import asynccontextmanager
import uuid
import time
import redis.asyncio as aioredis
from datetime import datetime
# Typing — pentru a specifica tipuri de date mai complexe
# Optional = un câmp care poate lipsi (e opțional)
from typing import Optional

redis_client: Optional[aioredis.Redis] = None

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
# pyright: ignore [reportMissingImports]
import httpx

# datetime — pentru timestamp-uri în log-uri
from datetime import datetime, timezone

# dotenv — citește automat fișierul .env și populează os.environ
# pyright: ignore [reportMissingImports]
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
    global redis_client
    
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
