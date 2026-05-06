# NFC Payment PoC — Sistem de Plăți Closed-Loop

> Proof of Concept pentru un sistem de plăți NFC cu autentificare criptografică,
> implementat ca 5 microservicii Docker cu securitate bazată pe HMAC-SHA256 și mTLS v1.3 (cu certificate ECC).

---

## Arhitectura pe scurt

```
[Telefon Android HCE] 
        │  NFC (APDU)
        ▼
[ESP32 + PN532 POS Terminal]
        │  HTTPS / mTLS
        ▼
[1. Payment Gateway]  ──────────────────────────────  Redis (Idempotență + Rate Limiting)
        │  (HTTP / Circuit Breaker / Strict Timeouts)
        ▼
[2. Token Service Provider]   (DPAN → PAN lookup) ──  PostgreSQL (Token Vault DB)
        │
        ▼
[3. Card Network Router]      (rutare către banca corectă)
        │
        ▼
[4. Issuing Bank]             (validare HMAC + Fraud Engine + decizie finală) ── PostgreSQL (Core Banking DB)
        │
        ▼
[5. Dashboard]                (monitorizare în timp real)
```

---

## Cerințe preliminare

Înainte să pornești proiectul, asigură-te că ai instalat:

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (include Docker + Docker Compose)
- [Git](https://git-scm.com/)
- [Python 3.11+](https://www.python.org/) (pentru rulare locală fără Docker, opțional)
- [VS Code](https://code.visualstudio.com/) (recomandat) cu extensiile Python și Docker

Verifică instalarea:
```bash
docker --version        # Docker version 24.x sau mai nou
docker compose version  # Docker Compose version 2.x sau mai nou
python3 --version       # Python 3.11 sau mai nou
```

---

## Pornirea proiectului

### 1. Clonează repository-ul
```bash
git clone https://github.com/username/nfc-payment-poc.git
cd nfc-payment-poc
```

### 2. Configurează variabilele de mediu
```bash
# Copiază template-ul
cp .env.example .env

# Deschide .env și completează valorile (mai ales cheile secrete!)
# NICIODATĂ nu urca .env pe GitHub
```

### 3. Generează certificatele mTLS
```bash
# Script care va fi adăugat în curând
# bash scripts/generate-certs.sh
```

### 4. Pornește toate serviciile
```bash
docker compose up --build
```

### 5. Verifică că totul rulează
```bash
# Ar trebui să vezi toate containerele pornite
docker compose ps

# Testează Gateway-ul
curl http://localhost:8001/health
```

---

## Structura proiectului

```
nfc-payment-poc/
├── docker-compose.yml          # Orchestratorul principal
├── .env.example                # Template variabile de mediu (fără secrete)
├── .gitignore                  # Ce ignoră Git
│
├── certs/                      # Certificate mTLS (generate local, ignorate de Git)
│
├── services/
│   ├── gateway/                # Serviciul 1: Payment Gateway
│   ├── tsp/                    # Serviciul 2: Token Service Provider
│   ├── card_network/           # Serviciul 3: Card Network Router
│   ├── issuing_bank/           # Serviciul 4: Issuing Bank
│   └── dashboard/              # Serviciul 5: Dashboard
│
└── shared/                     # Cod comun (ex: funcția HMAC)
    └── crypto_utils.py
```

---

## Microserviciile

| Serviciu | Port | Responsabilitate |
|---|---|---|
| Payment Gateway | 8001 | Primește cereri POS, rate limiting, idempotență bazată pe State Machine (salvare răspuns final) |
| TSP | 8002 | Mapare DPAN → PAN (Token Vault stocat într-o bază de date relațională, ex: PostgreSQL) |
| Card Network | 8003 | Rutare către banca corectă |
| Issuing Bank | 8004 | Bază de date relațională (ACID) pe conturi, validare criptografică (tranziție spre asimetrică/ECDSA), Fraud Engine |
| Dashboard | 8005 | Monitorizare în timp real |

---

## Criterii de acceptanță (din Specificația Tehnică)

- [ ] **AC-01** — Idempotency Test: 5 cereri concurente → o singură deducere
- [ ] **AC-02** — Cryptographic Rejection: MAC invalid → HTTP 400
- [ ] **AC-03** — Rate Limiting: a 3-a cerere/secundă → HTTP 429
- [ ] **AC-04** — Step-Up Flow: Risk Score 55 → HTTP 401 CHALLENGE_REQUIRED
- [ ] **AC-05** — Redis Failover: crash Redis → HTTP 503, recovery < 30s
- [ ] **AC-06** — mTLS Rejection: certificat expirat → TLS Handshake Failure
- [ ] **AC-07** — PII/PCI Masking: Niciun număr de card (PAN) expus în loguri

---

## Echipa

- Zărnescu Raul — Autor specificație tehnică

---

## Resurse utile

- [Documentația FastAPI](https://fastapi.tiangolo.com/)
- [Documentația Docker Compose](https://docs.docker.com/compose/)
- [Înțelegerea mTLS](https://www.cloudflare.com/learning/access-management/what-is-mutual-tls/)
- [HMAC explicat simplu](https://en.wikipedia.org/wiki/HMAC)

---

## Registru TO-DO (Production Readiness)

Următoarele aspecte critice trebuie rezolvate pentru a aduce arhitectura la standarde de producție, conform reviziei tehnice inițiale:

1. [ ] **Circuit Breaker & Timeouts (Gateway):** De adăugat limitări stricte de timp (ex: max 500ms per request în rețeaua internă) pentru a evita Cascading Failures în cazul în care Issuing Bank răspunde greu.
2. [ ] **Idempotency State Machine:** Lock-ul din Redis (`SETNX`) trebuie extins pentru a salva statusul tranzacției (`PENDING`, `COMPLETED`, `FAILED`) și răspunsul final. Retries-urile POS-ului trebuie să primească răspunsul stocat, fără a declanșa o re-rutare.
3. [ ] **Integrare Baze de Date Relaționale:** Adăugarea de containere PostgreSQL:
   - Pentru `Issuing Bank`: pentru persistența ACID a conturilor și balanțelor.
   - Pentru `TSP`: pentru o mapare stabilă și sigură DPAN -> PAN.
4. [ ] **Criptografie Asimetrică (ECDSA):** Înlocuirea validării pe bază de `HMAC-SHA256` (cheie simetrică distribuită) cu ECDSA, unde dispozitivul (HCE) semnează cu cheie privată, iar banca verifică cu cheia publică.
5. [ ] **Mascarea Datelor Sensibile (PCI-DSS):** Implementarea unui filtru Regex la nivelul clasei `JSONFormatter` pentru mascarea PAN-urilor (ex. `1234********5678`) înainte de logare.
