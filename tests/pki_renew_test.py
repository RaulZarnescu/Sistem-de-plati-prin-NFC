"""
Test pentru endpoint-ul /api/pki/renew.
Simulează comportamentul ESP32 la reînnoirea certificatului mTLS.
"""
import base64
import os
from datetime import datetime, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import httpx

GATEWAY_URL = os.getenv("TEST_GATEWAY_URL", "http://localhost:8001")
TERMINAL_CN = "POS-BUC-001"


def generate_csr(cn: str) -> tuple[bytes, bytes]:
    """Generează cheie privată nouă și CSR — simulează ESP32."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FictiveBank"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "RO"),
        ]))
        .sign(private_key, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    key_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    )
    return csr_pem, key_pem


def main():
    print("\n🔑 Test PKI Certificate Renewal")
    print("=" * 50)

    # Test 1 — Reînnoire legitimă
    print("\n[1/3] Reînnoire legitimă (CN coincide cu mTLS)...")
    csr_pem, new_key_pem = generate_csr(TERMINAL_CN)
    csr_b64 = base64.b64encode(csr_pem).decode()

    with httpx.Client(timeout=10.0) as client:
        resp = client.post(
            f"{GATEWAY_URL}/api/pki/renew",
            headers={
                "Content-Type": "application/json",
                "X-Terminal-Id": TERMINAL_CN,
                # Simulăm header-ul NGINX (în producție vine din cert mTLS)
                "X-SSL-Client-DN": f"CN={TERMINAL_CN},O=FictiveBank,C=RO"
            },
            json={"csr_pem_b64": csr_b64}
        )

    if resp.status_code == 200:
        data = resp.json()
        # Verificăm că certificatul returnat e valid
        cert_pem = base64.b64decode(data["certificate_pem_b64"])
        cert = x509.load_pem_x509_certificate(cert_pem)
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        days_valid = (cert.not_valid_after_utc - cert.not_valid_before_utc).days
        print(f"  ✅ Certificat emis pentru CN={cn}, valabil {days_valid} zile")
        print(f"     Serial: {cert.serial_number}")
        print(f"     Expiră: {cert.not_valid_after_utc.strftime('%Y-%m-%d')}")
    else:
        print(f"  ❌ HTTP {resp.status_code}: {resp.json()}")

    # Test 2 — CN mismatch (terminal încearcă să reînnoiască cert pentru alt terminal)
    print("\n[2/3] CN mismatch — trebuie 403...")
    csr_rogue, _ = generate_csr("POS-ROGUE-999")
    csr_rogue_b64 = base64.b64encode(csr_rogue).decode()

    with httpx.Client(timeout=10.0) as client:
        resp = client.post(
            f"{GATEWAY_URL}/api/pki/renew",
            headers={
                "X-Terminal-Id": TERMINAL_CN,
                "X-SSL-Client-DN": f"CN={TERMINAL_CN},O=FictiveBank,C=RO"
            },
            json={"csr_pem_b64": csr_rogue_b64}
        )

    if resp.status_code == 403:
        print(f"  ✅ 403 CN_MISMATCH — reînnoire blocată corect")
    else:
        print(f"  ❌ Așteptat 403, primit {resp.status_code}: {resp.json()}")

    # Test 3 — CSR invalid
    print("\n[3/3] CSR malformat — trebuie 400...")
    with httpx.Client(timeout=10.0) as client:
        resp = client.post(
            f"{GATEWAY_URL}/api/pki/renew",
            headers={
                "X-Terminal-Id": TERMINAL_CN,
                "X-SSL-Client-DN": f"CN={TERMINAL_CN},O=FictiveBank,C=RO"
            },
            json={"csr_pem_b64": "bm90LWEtY3Ny"}  # "not-a-csr" base64
        )

    if resp.status_code == 400:
        print(f"  ✅ 400 INVALID_CSR — CSR malformat respins corect")
    else:
        print(f"  ❌ Așteptat 400, primit {resp.status_code}: {resp.json()}")

    print("\n" + "=" * 50)


if __name__ == "__main__":
    main()