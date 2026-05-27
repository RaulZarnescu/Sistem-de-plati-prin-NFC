#!/usr/bin/env python3
"""
============================================================
wifi_direct_test.py — Test Flux WiFi Direct
ESP32 Simulat + Telefon Simulat + Backend Real
============================================================

Arhitectura testată:

  [Simulator ESP32]          [Simulator Telefon]
       │                            │
       │ 1. pornește server HTTP    │
       │    pe port 8088            │
       │                            │
       │ 2. inițiază tranzacție     │
       │    (amount, nonce, ts)     │
       │                            │
       │ ←── GET /payment-request ──│
       │ ──── date tranzacție ─────►│
       │                            │ 3. calculează MAC
       │ ←── POST /payment-response─│
       │      { dpan, atc, mac }    │
       │                            │
       │ 4. construiește payload    │
       │ 5. POST /authorize ───────►[Gateway]
       │ ←── răspuns ──────────────│

Teste acoperite:
  T-01  Server ESP32 pornește corect
  T-02  GET /payment-request returnează date corecte
  T-03  POST /payment-response acceptat corect
  T-04  POST /payment-response respins când IDLE
  T-05  Flux WiFi Direct complet — APPROVED
  T-06  Formula MAC identică cu backend
  T-07  Flux WiFi Direct — CHALLENGE_REQUIRED + PIN
  T-08  Timeout telefon — ESP32 anulează tranzacția
============================================================
"""

import base64
import hmac as hmac_lib
import hashlib
import json
import os
import sys
import threading
import time
import uuid

# Forțăm UTF-8 pe stdout/stderr (necesar pe Windows cu terminal cp1252)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional

import httpx

# Încarcă automat variabilele din .env (același mecanism ca gateway/main.py)
try:
    from dotenv import load_dotenv
    load_dotenv(
        dotenv_path=os.path.join(os.path.dirname(__file__), "..", ".env"),
        override=False,   # nu suprascrie variabile deja setate în shell
    )
except ImportError:
    pass  # python-dotenv opțional — variabilele pot fi setate manual în shell

# Importăm shared/crypto_utils dacă e accesibil — nu duplicăm logica MAC
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from shared.crypto_utils import compute_mac as _shared_compute_mac
    _HAS_SHARED_CRYPTO = True
except ImportError:
    _HAS_SHARED_CRYPTO = False


# ============================================================
# CONFIGURARE
# ============================================================

GATEWAY_URL      = os.getenv("TEST_GATEWAY_URL", "http://localhost:8001")
ESP32_SERVER_PORT = 8088      # Port ales deliberat (≠ 8080) pentru a evita conflicte Docker
TERMINAL_ID      = "POS-WIFI-TEST-001"

# Cheile HMAC din .env
_hex_bt      = os.getenv("BANK_BT_HMAC_KEY", "")
HMAC_KEY_BT  = bytes.fromhex(_hex_bt) if _hex_bt else b""

# DPAN-uri seed (db/init/tsp/01_schema.sql)
DPAN_BT_APPROVED = "4000000000000001"   # PAN 4000001111111111, BT, risk_level=0
DPAN_STEP_UP_BT  = "TEST-STEP-UP-BT"   # PAN 4000001111111111, BT, risk_level=55
PAN_STEP_UP_BT   = "4000001111111111"   # PAN asociat DPAN_STEP_UP_BT (pentru reset Redis)

INTER_TEST_SLEEP = 0.6  # s — evită rate limit 2 req/s per terminal


# ============================================================
# UTILITARE
# ============================================================

def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _new_nonce() -> str:
    """Nonce hex 8 caractere uppercase."""
    return uuid.uuid4().hex[:8].upper()


def _reset_fraud_state(pan: str) -> None:
    """
    Șterge cheile Redis de fraudă (velocity, risk, amounts) pentru un PAN.

    Necesar deoarece toate DPAN-urile BT din seed mapează la același PAN
    (4000001111111111) — velocity acumulat din teste anterioare ridică
    risk_score, transformând APPROVED în CHALLENGE_REQUIRED sau DECLINED.

    Strategii încercate în ordine:
      1. docker exec nfc-redis-master redis-cli DEL ... (funcționează de pe laptop)
      2. Conexiune Python directă la Redis          (funcționează din container Docker)
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
        subprocess.run(cmd, capture_output=True, timeout=5, check=True)
        return
    except Exception:
        pass

    # Strategie 2: conexiune Python directă (din interiorul containerului Docker)
    try:
        import redis as redis_sync
        r = redis_sync.Redis(
            host=os.getenv("REDIS_HOST", "redis-master"),
            port=int(os.getenv("REDIS_PORT", "6379")),
            password=redis_pw,
            decode_responses=True,
        )
        r.delete(*keys)
        r.close()
    except Exception:
        pass  # dacă ambele metode eșuează, testul continuă (va eșua dacă velocity e prea mare)


# ============================================================
# ESP32 SIMULATOR
# ============================================================

class ESP32Simulator:
    """
    Simulează serverul HTTP local al POS-ului ESP32.

    Mașina de stări:
      IDLE ──initiate_transaction()──► WAITING_FOR_PHONE
                                            │
                                   POST /payment-response
                                            │
                                       PROCESSING
                                            │
                                  send_to_gateway()
                                   ┌────────┴──────────────┐
                                   ▼                       ▼
                                RESULT            CHALLENGE_REQUIRED
                               (200 OK)               (401)
      wait_for_phone() timeout ──► IDLE (reset)

    Endpoints HTTP (ascultate pe port ESP32_SERVER_PORT):
      GET  /payment-request   — returnează starea și datele tranzacției
      POST /payment-response  — primește { dpan, atc, mac } de la telefon
    """

    def __init__(self, port: int = ESP32_SERVER_PORT):
        self.port = port

        # Stare mașină de stări (str pentru lizibilitate în assert-uri)
        self.state: str = "IDLE"

        # Date tranzacție curentă (setate de initiate_transaction)
        self.current_txn: Optional[dict] = None

        # Răspunsul primit de la telefon (setat de handler POST)
        self.phone_response: Optional[dict] = None

        # Rezultatul de la Gateway (setat de send_to_gateway)
        self.gateway_result: Optional[dict] = None

        # Server HTTP și thread-ul său
        self.server: Optional[HTTPServer] = None
        self.thread: Optional[threading.Thread] = None

        # Lock pentru acces concurrent din handler și din test
        self._lock = threading.Lock()

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Pornește serverul HTTP într-un daemon thread."""
        handler_cls = _make_handler(self)

        class _ReuseServer(HTTPServer):
            allow_reuse_address = True  # SO_REUSEADDR — port eliberat rapid între teste

        self.server = _ReuseServer(("", self.port), handler_cls)
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            daemon=True,
            name=f"ESP32Sim-{self.port}",
        )
        self.thread.start()

    def stop(self) -> None:
        """Oprește serverul HTTP și eliberează portul."""
        if self.server:
            self.server.shutdown()    # blochează până serve_forever() termină
            self.server.server_close()
            self.server = None

    # ── Operații tranzacție ───────────────────────────────────────────────────

    def initiate_transaction(self, amount_cents: int, currency: str = "RON") -> dict:
        """
        Inițiază o tranzacție nouă:
          - generează nonce (hex 8 chars uppercase)
          - generează timestamp ISO 8601 UTC
          - generează idempotency_key (UUIDv4)
          - setează state = WAITING_FOR_PHONE
        Returnează dict-ul tranzacției.
        """
        txn = {
            "amount":             amount_cents,
            "currency":           currency,
            "pos_nonce":          _new_nonce(),
            "terminal_timestamp": _now_iso(),
            "terminal_id":        TERMINAL_ID,
            "idempotency_key":    str(uuid.uuid4()),
        }
        with self._lock:
            self.current_txn    = txn
            self.phone_response = None
            self.gateway_result = None
            self.state          = "WAITING_FOR_PHONE"
        return txn

    def wait_for_phone(self, timeout: float = 10.0) -> bool:
        """
        Polling până telefonul trimite datele de plată (phone_response setat).
        Returnează True dacă a primit răspuns, False la timeout.
        La timeout, resetează starea la IDLE (tranzacția e anulată implicit).
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                if self.phone_response is not None:
                    return True
            time.sleep(0.1)
        # Timeout — revine în IDLE, tranzacția e anulată
        with self._lock:
            self.state = "IDLE"
        return False

    def send_to_gateway(self) -> dict:
        """
        Construiește payload-ul complet și îl POST-ează la Gateway.
        Gestionează:
          - 200: APPROVED / DECLINED → state = RESULT
          - 401: CHALLENGE_REQUIRED  → state = CHALLENGE_REQUIRED, stochează transaction_id
          - altele: eroare            → state = RESULT

        Returnează dict cu: status_code, body, și câmpuri auxiliare
        (status, transaction_id, original_dpan, error_code).
        """
        with self._lock:
            txn = self.current_txn
            pr  = self.phone_response

        # Payload conform specificației Gateway (PaymentRequest Pydantic model)
        payload = {
            "dpan": pr["dpan"],
            "transaction": {
                "amount":             txn["amount"],      # int cenți — NU float
                "currency":           txn["currency"],
                "pos_nonce":          txn["pos_nonce"],
                "terminal_timestamp": txn["terminal_timestamp"],
            },
            "cryptogram": {
                "mac": pr["mac"],
                "atc": pr["atc"],
            },
        }

        headers = {
            "X-Idempotency-Key": txn["idempotency_key"],
            "X-Terminal-Id":     TERMINAL_ID,
        }

        try:
            with httpx.Client(timeout=10.0) as client:
                resp = client.post(
                    f"{GATEWAY_URL}/api/v1/payments/authorize",
                    headers=headers,
                    json=payload,
                )

            data   = resp.json()
            result = {"status_code": resp.status_code, "body": data}

            if resp.status_code == 200:
                result["status"] = data.get("status", "")
                with self._lock:
                    self.state = "RESULT"

            elif resp.status_code == 401:
                # FastAPI wraps HTTPException: {"detail": {"error_code": ..., "transaction_id": ...}}
                detail = data.get("detail", {})
                if not isinstance(detail, dict):
                    detail = {}
                result["transaction_id"] = detail.get("transaction_id", "")
                result["original_dpan"]  = detail.get("original_dpan", pr["dpan"])
                with self._lock:
                    self.state = "CHALLENGE_REQUIRED"

            else:
                detail = data.get("detail", {})
                if isinstance(detail, dict):
                    result["error_code"] = detail.get("error_code", "UNKNOWN")
                with self._lock:
                    self.state = "RESULT"

            with self._lock:
                self.gateway_result = result
            return result

        except Exception as exc:
            err = {"status_code": -1, "error": str(exc)}
            with self._lock:
                self.gateway_result = err
                self.state = "RESULT"
            return err


# ── HTTP Request Handler ───────────────────────────────────────────────────────

def _make_handler(sim: ESP32Simulator):
    """
    Fabrică un handler HTTP legat de instanța ESP32Simulator.
    Pattern closure — permite instanțe multiple fără variabile globale.
    """

    class _Handler(BaseHTTPRequestHandler):
        _sim = sim   # referință la instanța simulatorului

        def log_message(self, fmt, *args):
            pass  # suprimăm log-urile HTTP (reduce noise în output teste)

        def _send_json(self, status: int, data: dict) -> None:
            body = json.dumps(data).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802
            if self.path == "/payment-request":
                with self._sim._lock:
                    state  = self._sim.state
                    txn    = self._sim.current_txn
                    result = self._sim.gateway_result

                if state == "WAITING_FOR_PHONE" and txn:
                    self._send_json(200, {
                        "status":             "PENDING",
                        "amount":             txn["amount"],
                        "currency":           txn["currency"],
                        "pos_nonce":          txn["pos_nonce"],
                        "terminal_timestamp": txn["terminal_timestamp"],
                        "terminal_id":        txn["terminal_id"],
                    })
                elif state == "PROCESSING":
                    self._send_json(200, {"status": "PROCESSING"})
                elif state == "CHALLENGE_REQUIRED":
                    self._send_json(200, {"status": "CHALLENGE_REQUIRED"})
                elif state == "RESULT" and result:
                    self._send_json(200, {"status": "RESULT", "result": result})
                else:
                    self._send_json(200, {"status": "IDLE"})

            elif self.path == "/transaction-result":
                with self._sim._lock:
                    result = self._sim.gateway_result
                    state  = self._sim.state

                if result is not None:
                    self._send_json(200, {**result, "esp32_state": state})
                else:
                    self._send_json(200, {"status": "no_result"})

            else:
                self._send_json(404, {"error": "Not Found"})

        def do_POST(self):  # noqa: N802
            if self.path == "/initiate-transaction":
                with self._sim._lock:
                    if self._sim.state != "IDLE":
                        self._send_json(409, {
                            "error":  "Conflict",
                            "detail": f"Tranzacție deja în curs (state={self._sim.state!r})",
                        })
                        return

                length = int(self.headers.get("Content-Length", 0))
                raw    = self.rfile.read(length)
                try:
                    body = json.loads(raw.decode("utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    self._send_json(400, {"error": "Invalid JSON"})
                    return

                amount_cents = body.get("amount_cents")
                if amount_cents is None or not isinstance(amount_cents, int):
                    self._send_json(422, {"error": "amount_cents (int) obligatoriu"})
                    return

                txn = self._sim.initiate_transaction(amount_cents)
                self._send_json(200, {
                    "status":             "initiated",
                    "amount_cents":       amount_cents,
                    "pos_nonce":          txn["pos_nonce"],
                    "terminal_timestamp": txn["terminal_timestamp"],
                })

            elif self.path == "/payment-response":
                # Verificăm starea înainte de a citi body-ul
                with self._sim._lock:
                    if self._sim.state != "WAITING_FOR_PHONE":
                        self._send_json(409, {
                            "error":  "Conflict",
                            "detail": (
                                f"POS state is '{self._sim.state}', "
                                "expected WAITING_FOR_PHONE"
                            ),
                        })
                        return

                length = int(self.headers.get("Content-Length", 0))
                raw    = self.rfile.read(length)
                try:
                    payload = json.loads(raw.decode("utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    self._send_json(400, {"error": "Invalid JSON"})
                    return

                dpan = payload.get("dpan", "")
                atc  = payload.get("atc")
                mac  = payload.get("mac", "")

                if not dpan or atc is None or not mac:
                    self._send_json(422, {
                        "error":  "Unprocessable Entity",
                        "detail": "Câmpuri obligatorii: dpan, atc, mac",
                    })
                    return

                with self._sim._lock:
                    self._sim.phone_response = {
                        "dpan": dpan,
                        "atc":  int(atc),
                        "mac":  mac,
                    }
                    self._sim.state = "PROCESSING"

                self._send_json(200, {"status": "OK"})

            else:
                self._send_json(404, {"error": "Not Found"})

    return _Handler


# ============================================================
# PHONE SIMULATOR
# ============================================================

class PhoneSimulator:
    """
    Simulează aplicația Android în arhitectura WiFi Direct.

    Telefonul:
      1. Interoghează POS-ul via GET /payment-request (polling)
      2. Calculează MAC cu formula exactă a backend-ului (two-step HMAC)
      3. Trimite datele de plată via POST /payment-response
      4. Incrementează ATC după fiecare tranzacție reușită

    Atribute:
      dpan       : DPAN-ul cardului tokenizat
      k_user_hex : Cheia HMAC hex-encoded (K_user al telefonului)
      atc        : Application Transaction Counter (inițiat la ms Unix timestamp)
    """

    def __init__(self, dpan: str, k_user_hex: str):
        self.dpan      = dpan
        self.k_user    = bytes.fromhex(k_user_hex) if k_user_hex else b""
        self.atc: int  = int(time.time() * 1000)   # ms — garantat > orice ATC stocat anterior

    def get_payment_request(self, esp32_url: str) -> Optional[dict]:
        """
        GET {esp32_url}/payment-request.
        Returnează dict-ul JSON sau None la eroare.
        """
        try:
            with httpx.Client(timeout=5.0) as client:
                resp = client.get(f"{esp32_url}/payment-request")
            return resp.json() if resp.status_code == 200 else None
        except Exception:
            return None

    def calculate_mac(
        self,
        amount_cents: int,
        currency: str,
        nonce: str,
        timestamp: str,
        atc: int,
    ) -> str:
        """
        Formula EXACTĂ — identică cu verify_mac() din issuing-bank-bt/main.py:

          session_key = k_user   (cheia master, FĂRĂ derivare per-ATC)
          mac_input   = f"{amount_cents}|{currency}|{nonce}|{timestamp}|{atc}"
          mac         = HMAC-SHA256(session_key, mac_input.encode("utf-8")).hexdigest()

        Confirmat din codul băncii (linia ~491):
          verify_mac(session_key=HMAC_KEY, amount_cents=..., atc=..., ...)
        unde HMAC_KEY este cheia master nemodificată.

        Dacă shared/crypto_utils.py e disponibil, calculul e delegat acestuia
        (nu duplicăm logica — DRY principle). session_key = k_user direct.
        """
        if _HAS_SHARED_CRYPTO:
            # shared/crypto_utils.compute_mac(session_key, ...) — session_key = k_user
            return _shared_compute_mac(self.k_user, amount_cents, currency,
                                       nonce, timestamp, atc)

        # Fallback — implementare locală identică cu shared/crypto_utils.py
        mac_input = f"{amount_cents}|{currency}|{nonce}|{timestamp}|{atc}"
        return hmac_lib.new(
            self.k_user,
            mac_input.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def send_payment_response(self, esp32_url: str, mac: str) -> bool:
        """
        POST {esp32_url}/payment-response cu { dpan, atc, mac }.
        Incrementează self.atc după trimitere reușită (pregătire pentru tranzacția următoare).
        Returnează True dacă HTTP 200.
        """
        try:
            with httpx.Client(timeout=5.0) as client:
                resp = client.post(
                    f"{esp32_url}/payment-response",
                    json={"dpan": self.dpan, "atc": self.atc, "mac": mac},
                )
            success = resp.status_code == 200
            if success:
                self.atc += 1
            return success
        except Exception:
            return False

    def process_transaction(self, esp32_url: str) -> dict:
        """
        Flux complet al telefonului:
          1. Polling GET /payment-request (maxim 5 încercări la 0.5s interval)
          2. Calculează MAC cu datele primite
          3. POST /payment-response

        Returnează { dpan, atc, mac } la succes, {} la eșec (timeout polling).
        Poate rula în thread separat față de ESP32Simulator (thread-safe).
        """
        txn_data = None
        for _ in range(5):
            data = self.get_payment_request(esp32_url)
            if data and data.get("status") == "PENDING":
                txn_data = data
                break
            time.sleep(0.5)

        if not txn_data:
            return {}   # Timeout polling

        current_atc = self.atc
        mac = self.calculate_mac(
            txn_data["amount"],
            txn_data["currency"],
            txn_data["pos_nonce"],
            txn_data["terminal_timestamp"],
            current_atc,
        )
        self.send_payment_response(esp32_url, mac)
        return {"dpan": self.dpan, "atc": current_atc, "mac": mac}


# ============================================================
# TEST RUNNER
# ============================================================

def run_test(name: str, fn) -> bool:
    """
    Execută fn() și înregistrează rezultatul.
    fn() nu returnează nimic — ridică o excepție cu mesaj descriptiv la eșec.
    run_test() prinde TOATE excepțiile și le afișează fără a bloca suite-ul.
    """
    try:
        fn()
        print(f"  ✅ {name}")
        return True
    except Exception as exc:
        print(f"  ❌ {name}  ← {exc}")
        return False


# ── URL de bază al simulatorului ESP32 ────────────────────────────────────────
_ESP32_URL = f"http://localhost:{ESP32_SERVER_PORT}"


# ============================================================
# T-01: Server ESP32 pornește corect
# ============================================================

def test_01():
    """T-01: Serverul HTTP pornește pe portul 8088 și răspunde la GET /payment-request."""
    sim = ESP32Simulator(ESP32_SERVER_PORT)
    try:
        sim.start()
        time.sleep(0.05)   # așteptăm bind-ul socket-ului

        with httpx.Client(timeout=3.0) as client:
            resp = client.get(f"{_ESP32_URL}/payment-request")

        assert resp.status_code == 200, f"HTTP {resp.status_code} (așteptat 200)"
        data = resp.json()
        assert data.get("status") == "IDLE", \
            f"status={data.get('status')!r} (așteptat 'IDLE')"
    finally:
        sim.stop()


# ============================================================
# T-02: GET /payment-request returnează date corecte
# ============================================================

def test_02():
    """T-02: GET /payment-request returnează PENDING și câmpurile validate."""
    sim = ESP32Simulator(ESP32_SERVER_PORT)
    try:
        sim.start()
        time.sleep(0.05)
        sim.initiate_transaction(15000, "RON")   # 150 RON

        with httpx.Client(timeout=3.0) as client:
            resp = client.get(f"{_ESP32_URL}/payment-request")

        assert resp.status_code == 200, f"HTTP {resp.status_code}"
        data = resp.json()

        assert data.get("status")   == "PENDING", \
            f"status={data.get('status')!r} (așteptat 'PENDING')"
        assert data.get("amount")   == 15000, \
            f"amount={data.get('amount')!r} (așteptat 15000 int)"
        assert data.get("currency") == "RON", \
            f"currency={data.get('currency')!r}"
        nonce = data.get("pos_nonce", "")
        assert len(nonce) == 8 and nonce == nonce.upper() and nonce.isalnum(), \
            f"pos_nonce invalid: {nonce!r} (așteptat hex 8 chars uppercase)"
        ts = data.get("terminal_timestamp", "")
        assert "T" in ts and ts.endswith("Z"), \
            f"terminal_timestamp nu e ISO 8601 UTC: {ts!r}"
        assert data.get("terminal_id"), \
            "terminal_id lipsă sau gol"
    finally:
        sim.stop()


# ============================================================
# T-03: POST /payment-response acceptat corect
# ============================================================

def test_03():
    """T-03: POST /payment-response returnează 200 și stochează datele corect."""
    sim = ESP32Simulator(ESP32_SERVER_PORT)
    try:
        sim.start()
        time.sleep(0.05)
        sim.initiate_transaction(5000, "RON")

        dummy_atc = 42
        dummy_mac = "ab" * 32   # 64 chars hex-like, sintetic

        with httpx.Client(timeout=3.0) as client:
            resp = client.post(
                f"{_ESP32_URL}/payment-response",
                json={"dpan": "TEST-DPAN", "atc": dummy_atc, "mac": dummy_mac},
            )

        assert resp.status_code == 200, f"HTTP {resp.status_code}: {resp.text}"

        with sim._lock:
            pr = sim.phone_response
        assert pr is not None, "phone_response nu a fost setat de handler"
        assert pr["dpan"] == "TEST-DPAN",  f"dpan stocat: {pr['dpan']!r}"
        assert pr["atc"]  == dummy_atc,    f"atc stocat: {pr['atc']!r}"
        assert pr["mac"]  == dummy_mac,    f"mac stocat: {pr['mac']!r}"
    finally:
        sim.stop()


# ============================================================
# T-04: POST /payment-response respins când IDLE
# ============================================================

def test_04():
    """T-04: POST /payment-response returnează 409 Conflict când ESP32 e în stare IDLE."""
    sim = ESP32Simulator(ESP32_SERVER_PORT)
    try:
        sim.start()
        time.sleep(0.05)
        # NU apelăm initiate_transaction() — starea rămâne IDLE

        with httpx.Client(timeout=3.0) as client:
            resp = client.post(
                f"{_ESP32_URL}/payment-response",
                json={"dpan": DPAN_BT_APPROVED, "atc": 1, "mac": "ab" * 32},
            )

        assert resp.status_code == 409, \
            f"HTTP {resp.status_code} (așteptat 409 Conflict)"
    finally:
        sim.stop()


# ============================================================
# T-05: Flux WiFi Direct complet — APPROVED
# ============================================================

def test_05():
    """T-05: Flux end-to-end complet: Telefon → ESP32 → Gateway → APPROVED."""
    if not HMAC_KEY_BT:
        raise RuntimeError("BANK_BT_HMAC_KEY nu este setată în mediu")

    # K_user: TEST_HMAC_KEY dacă e definit, altfel BANK_BT_HMAC_KEY
    k_user_hex = os.getenv("TEST_HMAC_KEY") or os.getenv("BANK_BT_HMAC_KEY", "")

    sim   = ESP32Simulator(ESP32_SERVER_PORT)
    phone = PhoneSimulator(dpan=DPAN_BT_APPROVED, k_user_hex=k_user_hex)

    try:
        sim.start()
        time.sleep(0.05)

        txn = sim.initiate_transaction(10000, "RON")   # 100 RON

        # Telefonul procesează tranzacția în fundal (simulează comportamentul async)
        t = threading.Thread(
            target=phone.process_transaction,
            args=(_ESP32_URL,),
            daemon=True,
        )
        t.start()

        received = sim.wait_for_phone(timeout=10.0)
        assert received, "Telefonul nu a trimis date în 10 secunde"
        t.join(timeout=3.0)

        # Reset velocity/risk pentru PAN-ul folosit (toate DPAN-urile BT mapează
        # la același PAN — velocity acumulat din T-05 ar face T-06/T-07 să eșueze)
        _reset_fraud_state("4000001111111111")

        result = sim.send_to_gateway()

        # Verificare HTTP 200 APPROVED
        assert result["status_code"] == 200, \
            f"HTTP {result['status_code']}: {result.get('body')}"
        assert result.get("status") == "APPROVED", \
            f"status={result.get('status')!r} (așteptat APPROVED)"

        # Verificări suplimentare — consistența internă a payload-ului
        with sim._lock:
            pr = sim.phone_response
        assert isinstance(txn["amount"], int), \
            f"amount trebuie să fie int cenți, nu {type(txn['amount'])}"
        assert isinstance(pr["atc"], int), \
            f"atc din cryptogram trebuie să fie int, nu {type(pr['atc'])}"
        # pos_nonce și terminal_timestamp din MAC_input = din payload (validat implicit prin APPROVED)
        # Dacă MAC-ul calculat cu aceste valori a trecut, înseamnă că sunt consistente.
    finally:
        sim.stop()


# ============================================================
# T-06: Formula MAC identică cu backend
# ============================================================

def test_06():
    """
    T-06: Verifică că formula MAC din PhoneSimulator produce un MAC acceptat de Gateway.

    Strategia în două etape:
      1. Verificare locală cu valori fixe — confirmă reproductibilitatea formulei.
         Valorile fixe nu ajung la Gateway (evită ATC replay după T-05).
      2. Verificare live — trimite la Gateway cu ATC proaspăt (ms timestamp).
         Confirmă că backend-ul și PhoneSimulator agreează aceeași formulă.
    """
    if not HMAC_KEY_BT:
        raise RuntimeError("BANK_BT_HMAC_KEY nu este setată în mediu")

    k_user_hex = os.getenv("TEST_HMAC_KEY") or os.getenv("BANK_BT_HMAC_KEY", "")
    phone = PhoneSimulator(dpan=DPAN_BT_APPROVED, k_user_hex=k_user_hex)

    # ── Etapa 1: verificare locală cu valori fixe ──────────────────────────
    # Valorile fixe garantează că aceeași intrare → același MAC, indiferent de rulare.
    fixed_amount    = 8750
    fixed_currency  = "RON"
    fixed_nonce     = "WIFI0001"
    fixed_timestamp = "2026-06-01T10:00:00Z"
    fixed_atc       = 9001

    mac_fixed = phone.calculate_mac(fixed_amount, fixed_currency,
                                    fixed_nonce, fixed_timestamp, fixed_atc)
    assert mac_fixed and len(mac_fixed) == 64, \
        f"MAC cu valori fixe invalid (așteptat 64 chars hex): {mac_fixed!r}"

    # Recalculare independentă — confirmă că formula e deterministă
    mac_input_ref = f"{fixed_amount}|{fixed_currency}|{fixed_nonce}|{fixed_timestamp}|{fixed_atc}"
    mac_ref = hmac_lib.new(
        HMAC_KEY_BT, mac_input_ref.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    assert mac_fixed == mac_ref, \
        f"Formula MAC inconsistentă!\n  phone:   {mac_fixed}\n  ref:     {mac_ref}"

    # ── Etapa 2: verificare live cu ATC proaspăt ───────────────────────────
    # ATC = ms timestamp: garantat > orice ATC stocat anterior (evită ATC replay).
    live_nonce = _new_nonce()
    live_ts    = _now_iso()
    live_atc   = phone.atc     # int(time.time() * 1000) setat la construirea PhoneSimulator
    live_mac   = phone.calculate_mac(fixed_amount, fixed_currency,
                                     live_nonce, live_ts, live_atc)

    # Reset velocity/risk înainte de apelul live (T-05 a folosit același PAN)
    _reset_fraud_state("4000001111111111")

    idemp = f"T06-LIVE-{uuid.uuid4().hex[:8].upper()}"
    with httpx.Client(timeout=10.0) as client:
        resp = client.post(
            f"{GATEWAY_URL}/api/v1/payments/authorize",
            headers={
                "X-Idempotency-Key": idemp,
                "X-Terminal-Id":     TERMINAL_ID,
            },
            json={
                "dpan": DPAN_BT_APPROVED,
                "transaction": {
                    "amount":             fixed_amount,
                    "currency":           fixed_currency,
                    "pos_nonce":          live_nonce,
                    "terminal_timestamp": live_ts,
                },
                "cryptogram": {"mac": live_mac, "atc": live_atc},
            },
        )

    data = resp.json()
    assert resp.status_code == 200, \
        f"Gateway a respins MAC-ul — formulă incompatibilă: HTTP {resp.status_code}: {data}"
    assert data.get("status") == "APPROVED", \
        f"status={data.get('status')!r} — MAC valid, dar tranzacție refuzată din alt motiv"


# ============================================================
# T-07: Flux WiFi Direct — CHALLENGE_REQUIRED + PIN
# ============================================================

def test_07():
    """
    T-07: DPAN cu risk_level=55 → 401 CHALLENGE_REQUIRED → PIN corect → 200 APPROVED.

    Flux:
      1. ESP32 inițiază tranzacție cu DPAN_STEP_UP_BT
      2. Telefon calculează MAC și trimite
      3. ESP32 primește 401 CHALLENGE_REQUIRED + transaction_id
      4. ESP32 construiește PIN Block: "{transaction_id}:1234"
      5. Criptează RSA-OAEP SHA256 cu cheia publică BT
      6. POST /api/v1/payments/challenge → 200 APPROVED
    """
    if not HMAC_KEY_BT:
        raise RuntimeError("BANK_BT_HMAC_KEY nu este setată în mediu")

    # Reset stare fraudă — T-06 a folosit același PAN, velocity trebuie curat
    _reset_fraud_state(PAN_STEP_UP_BT)

    # Căutăm cheia publică RSA BT
    pub_key_paths = [
        "certs/bank_bt_public.pem",
        os.path.join(os.path.dirname(__file__), "..", "certs", "bank_bt_public.pem"),
        "/tmp/bank_bt_public.pem",
    ]
    pub_key = None
    for path in pub_key_paths:
        if os.path.exists(path):
            try:
                from cryptography.hazmat.primitives import serialization
                with open(path, "rb") as f:
                    pub_key = serialization.load_pem_public_key(f.read())
                break
            except Exception:
                continue

    if pub_key is None:
        raise RuntimeError(
            "Cheia publică RSA BT nu a fost găsită în:\n"
            + "\n".join(f"  {p}" for p in pub_key_paths)
            + "\nGenerare:\n"
            "  docker exec nfc-issuing-bank-bt "
            "cat /app/keys/bank_bt_public.pem > /tmp/bank_bt_public.pem"
        )

    k_user_hex = os.getenv("TEST_HMAC_KEY") or os.getenv("BANK_BT_HMAC_KEY", "")
    sim   = ESP32Simulator(ESP32_SERVER_PORT)
    phone = PhoneSimulator(dpan=DPAN_STEP_UP_BT, k_user_hex=k_user_hex)

    try:
        sim.start()
        time.sleep(0.05)
        sim.initiate_transaction(10000, "RON")

        t = threading.Thread(
            target=phone.process_transaction,
            args=(_ESP32_URL,),
            daemon=True,
        )
        t.start()

        received = sim.wait_for_phone(timeout=10.0)
        assert received, "Telefonul nu a trimis date în 10 secunde"
        t.join(timeout=3.0)

        result = sim.send_to_gateway()
        assert result["status_code"] == 401, (
            f"Așteptat 401 CHALLENGE_REQUIRED pentru DPAN {DPAN_STEP_UP_BT!r}, "
            f"primit HTTP {result['status_code']}: {result.get('body')}"
        )

        transaction_id = result.get("transaction_id", "")
        original_dpan  = result.get("original_dpan", DPAN_STEP_UP_BT)
        assert transaction_id, \
            f"transaction_id lipsă din răspunsul 401: {result.get('body')}"

        # Construim și criptăm PIN Block
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes

        pin_block = f"{transaction_id}:1234"
        encrypted = pub_key.encrypt(
            pin_block.encode("utf-8"),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        pin_block_b64 = base64.b64encode(encrypted).decode("utf-8")

        # Idempotency key pentru challenge (separat de cel al autorizării)
        with sim._lock:
            base_idemp = sim.current_txn["idempotency_key"]
        challenge_idemp = f"{base_idemp[:18]}-CHALL"

        with httpx.Client(timeout=10.0) as client:
            resp = client.post(
                f"{GATEWAY_URL}/api/v1/payments/challenge",
                headers={
                    "X-Idempotency-Key": challenge_idemp,
                    "X-Terminal-Id":     TERMINAL_ID,
                },
                json={
                    "transaction_id":      transaction_id,
                    "original_dpan":       original_dpan,
                    "pin_block_encrypted": pin_block_b64,
                },
            )

        data = resp.json()
        assert resp.status_code == 200, \
            f"Challenge eșuat: HTTP {resp.status_code}: {data}"
        assert data.get("status") == "APPROVED", \
            f"status={data.get('status')!r} (așteptat APPROVED)"

    finally:
        sim.stop()


# ============================================================
# T-08: Timeout telefon — ESP32 anulează tranzacția
# ============================================================

def test_08():
    """
    T-08: Telefonul nu trimite niciun răspuns în 3s.
    wait_for_phone(timeout=3.0) trebuie să returneze False și să reseteze
    starea la IDLE. O nouă tranzacție poate fi inițiată imediat după.
    """
    sim = ESP32Simulator(ESP32_SERVER_PORT)
    try:
        sim.start()
        time.sleep(0.05)
        sim.initiate_transaction(5000, "RON")

        with sim._lock:
            state_before = sim.state
        assert state_before == "WAITING_FOR_PHONE", \
            f"Stare inițială așteptată WAITING_FOR_PHONE, primit {state_before!r}"

        # Niciun telefon nu trimite date — așteptăm timeout de 3s
        t0       = time.monotonic()
        received = sim.wait_for_phone(timeout=3.0)
        elapsed  = time.monotonic() - t0

        assert not received, \
            "wait_for_phone() a returnat True deși niciun telefon nu a trimis date"
        assert elapsed >= 2.8, \
            f"Timeout prea scurt: {elapsed:.2f}s (așteptat ≥2.8s)"

        # Verificăm că starea a revenit la IDLE
        with sim._lock:
            state_after = sim.state
        assert state_after == "IDLE", \
            f"Stare după timeout așteptată IDLE, primit {state_after!r}"

        # Verificăm că o nouă tranzacție poate fi inițiată imediat
        txn2 = sim.initiate_transaction(2500, "RON")
        assert txn2["amount"] == 2500, \
            f"Noua tranzacție are amount={txn2['amount']!r} (așteptat 2500)"
        with sim._lock:
            state_new = sim.state
        assert state_new == "WAITING_FOR_PHONE", \
            f"Stare după re-inițiere așteptată WAITING_FOR_PHONE, primit {state_new!r}"

    finally:
        sim.stop()


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    print("\n📡 Test Suite WiFi Direct — ESP32 Simulator")
    print("=" * 55)
    print(f"Gateway: {GATEWAY_URL}")
    print(f"ESP32 Simulator: http://localhost:{ESP32_SERVER_PORT}")
    print("=" * 55)

    results = []

    results.append(run_test("T-01 Server ESP32 pornește",   test_01))
    results.append(run_test("T-02 GET /payment-request",    test_02))
    results.append(run_test("T-03 POST /payment-response",  test_03))
    results.append(run_test("T-04 POST respins când IDLE",  test_04))
    time.sleep(INTER_TEST_SLEEP)   # evită rate limit înainte de T-05
    results.append(run_test("T-05 Flux complet APPROVED",   test_05))
    time.sleep(INTER_TEST_SLEEP)
    results.append(run_test("T-06 Formula MAC identică",    test_06))
    time.sleep(INTER_TEST_SLEEP)
    results.append(run_test("T-07 Challenge + PIN",         test_07))
    results.append(run_test("T-08 Timeout telefon",         test_08))

    passed = sum(results)
    total  = len(results)
    print(f"\n{'=' * 55}")
    print(f"Rezultat: {passed}/{total} teste trecute")

    if passed == total:
        print("✅ Fluxul WiFi Direct e compatibil cu backend-ul!")
        print("   ESP32 poate fi flashat cu încredere.")
    else:
        print("❌ Există probleme — verifică erorile de mai sus")
        print("   înainte de a flasha ESP32.")

    sys.exit(0 if passed == total else 1)


# ============================================================
# INSTRUCȚIUNI DE RULARE
# ============================================================
# Rulare locală (pe laptop, sistemul Docker pornit):
# pip install httpx cryptography
# python tests/wifi_direct_test.py
#
# Rulare în container Gateway:
# docker cp tests/wifi_direct_test.py nfc-gateway:/tmp/
# docker cp certs/bank_bt_public.pem nfc-gateway:/tmp/bank_bt_public.pem
# docker exec nfc-gateway python /tmp/wifi_direct_test.py
#
# Dacă T-06 eșuează cu INVALID_CRYPTOGRAM și ATC=9001:
#   → ATC replay: rulează pe Docker fresh sau schimbă manual atc în test_06
#
# Dacă T-07 eșuează cu FileNotFoundError:
#   → docker exec nfc-issuing-bank-bt cat /app/keys/bank_bt_public.pem \
#       > certs/bank_bt_public.pem
