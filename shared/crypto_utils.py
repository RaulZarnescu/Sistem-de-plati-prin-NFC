# ============================================================
# shared/crypto_utils.py — Utilitare criptografice comune
#
# De ce "shared"?
# Funcția de calcul HMAC trebuie să producă ACELAȘI rezultat
# pe telefon (Android), pe POS (ESP32) și în backend (Python).
# Dacă fiecare serviciu implementează propria versiune, riscăm
# inconsistențe subtile (ex: encoding diferit, ordine câmpuri).
#
# Soluție: O SINGURĂ implementare, importată de toate serviciile.
# Aceasta e regula "DRY" — Don't Repeat Yourself.
# ============================================================

import hmac
import hashlib
from datetime import datetime, timezone


def derive_session_key(master_key: bytes, atc: int) -> bytes:
    """
    Pasul 1 din formula 2-step HMAC (aliniat cu Android CryptoUtils.kt):
      Session_Key = HMAC-SHA256(master_key, str(atc))

    Această derivare leagă cheia de sesiune de tranzacția specifică (ATC),
    prevenind reutilizarea cheii între tranzacții.

    Parametri:
        master_key : Cheia master HMAC a băncii emitente (bytes, 32 bytes)
        atc        : Application Transaction Counter (int)

    Returnează:
        Session key ca bytes (32 bytes pentru SHA256)
    """
    return hmac.new(
        key=master_key,
        msg=str(atc).encode("utf-8"),
        digestmod=hashlib.sha256
    ).digest()


def compute_mac(
    session_key: bytes,
    amount_cents: int,
    currency: str,
    pos_nonce: str,
    terminal_timestamp: str,
    atc: int
) -> str:
    """
    Calculează MAC-ul HMAC-SHA256 pentru o tranzacție.

    Aceasta implementează EXACT formula din specificație (Cap. 3.1):
    INPUT = UTF8(Amount_as_string) | UTF8(Currency) | UTF8(Nonce) |
            UTF8(Terminal_Timestamp_ISO8601) | UTF8(ATC_decimal)

    Parametri:
        session_key     : Cheia de sesiune derivată (bytes)
        amount_cents    : Suma în cenți/bani (ex: 15000 pentru 150.00 RON)
        currency        : Codul monedei (ex: "RON")
        pos_nonce       : Nonce-ul generat de POS (ex: "A7F90B1C")
        terminal_timestamp : Timestamp ISO 8601 (ex: "2026-04-10T14:30:00Z")
        atc             : Application Transaction Counter (ex: 42)

    Returnează:
        String hex al MAC-ului (64 caractere pentru SHA256)

    Exemplu din spec:
        amount_cents=15000, currency="RON", pos_nonce="A7F90B1C",
        terminal_timestamp="2026-04-10T14:30:00Z", atc=42
        → INPUT = "15000|RON|A7F90B1C|2026-04-10T14:30:00Z|42"
        → MAC = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    """

    # Construim inputul EXACT ca în specificație
    # str(amount_cents) = "15000" (suma în bani/cenți, fără punct zecimal)
    # "|" = separatorul dintre câmpuri
    mac_input = "|".join([
        str(amount_cents),
        currency,
        pos_nonce,
        terminal_timestamp,
        str(atc)
    ])

    # Convertim la bytes UTF-8 (obligatoriu pentru HMAC)
    # encode("utf-8") = convertește string Python → bytes
    mac_input_bytes = mac_input.encode("utf-8")

    # Calculăm HMAC-SHA256
    # hmac.new(key, message, digestmod) = crează un obiect HMAC
    # hashlib.sha256 = specificăm algoritmul SHA256
    mac_object = hmac.new(
        key=session_key,
        msg=mac_input_bytes,
        digestmod=hashlib.sha256
    )

    # hexdigest() returnează MAC-ul ca string hexadecimal (64 chars)
    return mac_object.hexdigest()


def verify_mac(
    session_key: bytes,
    amount_cents: int,
    currency: str,
    pos_nonce: str,
    terminal_timestamp: str,
    atc: int,
    received_mac: str
) -> bool:
    """
    Verifică dacă un MAC primit este valid.

    De ce nu comparăm pur și simplu cu "=="?
    Comparația simplă cu "==" e vulnerabilă la "Timing Attack":
    un atacator poate măsura timpul de răspuns și deduce câte
    caractere din MAC sunt corecte.

    hmac.compare_digest() face comparație în timp CONSTANT,
    indiferent de câte caractere se potrivesc.

    Returnează True dacă MAC-ul e valid, False altfel.
    """

    # Calculăm MAC-ul așteptat cu aceleași date
    expected_mac = compute_mac(
        session_key=session_key,
        amount_cents=amount_cents,
        currency=currency,
        pos_nonce=pos_nonce,
        terminal_timestamp=terminal_timestamp,
        atc=atc
    )

    # Comparație în timp constant (protecție Timing Attack)
    return hmac.compare_digest(expected_mac, received_mac)


def hash_pin(pin: str, pan: str) -> str:
    """
    Calculează hash-ul PIN-ului folosind SHA256(pan + pin).

    De ce pan ca salt?
    Fără salt, hash-uri identice pentru același PIN pe conturi diferite
    ar permite atacuri de tip rainbow table. Folosirea PAN-ului ca salt
    garantează că hash-urile sunt unice per cont.

    PoC: SHA256 simplu — vulnerabil la brute-force pe 10.000 combinații PIN.
    Producție OBLIGATORIU: PBKDF2-HMAC-SHA256 cu 100.000 iterații și
    salt random per cont stocat separat.

    Parametri:
        pin  : PIN-ul în clar (ex: "1234") — NICIODATĂ logat
        pan  : PAN-ul cardului — folosit ca salt implicit

    Returnează:
        String hex SHA256 (64 caractere)
    """
    combined = (pan + pin).encode("utf-8")
    return hashlib.sha256(combined).hexdigest()


def verify_pin(received_pin: str, pan: str, stored_hash: str) -> bool:
    """
    Verifică PIN-ul folosind comparație timing-safe (HMAC-safe).

    De ce hmac.compare_digest și NU "=="?
    Operatorul == returnează False la primul caracter diferit → timing attack:
    un atacator poate deduce câte caractere sunt corecte măsurând timpul de răspuns.
    hmac.compare_digest() compară TOATE caracterele în timp constant.

    REGULĂ DE SECURITATE: received_pin NU apare niciodată în log-uri.
    Corect:   logger.info("PIN verificat cu succes")
    GREȘIT:   logger.info(f"PIN primit: {received_pin}")  ← interzis

    Parametri:
        received_pin  : PIN-ul primit de la utilizator (ex: "1234")
        pan           : PAN-ul cardului (salt pentru hash)
        stored_hash   : Hash-ul stocat în DB (din coloana pin_hash)

    Returnează:
        True dacă PIN-ul e corect, False altfel
    """
    if not stored_hash:
        return False
    computed = hash_pin(received_pin, pan)
    # hmac.compare_digest — OBLIGATORIU. Operatorul == e interzis aici.
    return hmac.compare_digest(computed, stored_hash)
