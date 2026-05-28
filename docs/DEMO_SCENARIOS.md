# Scenarii Demo — NFC Payment PoC
**Versiune:** 2.0 | **Data:** Mai 2026 | **Autor:** Echipă PoC

---

> **NOTĂ MAC-URI:** Comenzile curl din acest document conțin `MAC_PLACEHOLDER`.
> Înainte de prezentare, rulează scriptul de mai jos și înlocuiește placeholder-ele cu valorile reale:
>
> ```powershell
> docker cp scripts/generate_demo_macs.py nfc-gateway:/tmp/
> docker exec nfc-gateway python /tmp/generate_demo_macs.py | python -m json.tool
> ```
>
> MAC-urile sunt **reproductibile** (nonce și timestamp fixe) — același output la fiecare rulare atâta timp cât cheile HMAC din `.env` nu s-au schimbat.

---

## Setup Rapid (înainte de prezentare)

### Pornire sistem

```powershell
# Din directorul proiectului
docker compose up -d
docker compose ps   # verifică că toate serviciile sunt healthy
```

**Toate serviciile trebuie să fie în starea `healthy` înainte de demo.**
Dacă un serviciu arată `starting`, așteaptă 15-30 secunde și rulează `docker compose ps` din nou.

### Verificare funcționalitate

```powershell
# Copiere test E2E în container și rulare
docker cp tests/wifi_direct_test.py nfc-gateway:/tmp/
docker cp certs/bank_bt_public.pem nfc-gateway:/tmp/bank_bt_public.pem
docker exec nfc-gateway python /tmp/wifi_direct_test.py
```

**Rezultat așteptat:** `8/8 teste trecute` — fluxul WiFi Direct e compatibil cu backend-ul.

### URL-uri utile

| Serviciu | URL | Observație |
|---|---|---|
| Casa de Marcat | http://localhost:8005/pos | Calea principală demo |
| Dashboard | http://localhost:8005 | Pagina de start |
| Grafana | http://localhost:3000 | Metrici și grafice fraud |
| pgAdmin | http://localhost:5050 | Vizualizare baze de date |
| Prometheus | http://localhost:9090/targets | Stare monitorizare |
| Gateway API (Swagger) | http://localhost:8001/docs | Documentație API interactivă |

### Credențiale

| Serviciu | User | Parolă |
|---|---|---|
| Grafana | `admin` | `admin` |
| pgAdmin | `admin@nfc.local` | `admin` |
| pgAdmin → Server Banks | — | Host: `postgres-bank:5432` |
| pgAdmin → Server TSP | — | Host: `postgres-tsp:5432` |

### Pre-calculare MAC-uri (o singură dată, înainte de prezentare)

```powershell
docker cp scripts/generate_demo_macs.py nfc-gateway:/tmp/
docker exec nfc-gateway python /tmp/generate_demo_macs.py
# Inserează output-ul JSON în secțiunea "MAC-uri pre-calculate" de la sfârșitul documentului
```

---

## Scenariul 1 — Happy Path Normal

**Demonstrează:** Autorizarea completă a unei tranzacții fără fraudă, folosind arhitectura ESP32 → Gateway → Card Network → Banca emitentă. Scor de risc sub 40 → APPROVED imediat.

### Date de test

| Câmp | Valoare |
|---|---|
| Bancă emitentă | BT (Banca Transilvania) |
| PAN | `4000001111111111` |
| DPAN (token TSP) | `4000000000000001` |
| CVV | `123` |
| PIN | `1234` |
| Expirare | `12/28` |
| Sumă | `87.50 RON` (8750 cenți) |
| Sold disponibil | > 10.000 RON |
| Risk level token | 0 (fără step-up) |

### Calea principală — Casa de Marcat

1. Deschide http://localhost:8005/pos în browser
2. Adaugă produse din listă (ex: Cafea Espresso × 1 + Sandwich Pui × 2 + Croissant × 1 = 58 RON)
   - Sau orice combinație până la suma dorită
3. Apasă butonul verde **💳 ÎNCASEAZĂ**
4. Interfața afișează "Apropiați telefonul de terminal..."
5. ESP32 afișează suma și așteaptă telefonul
6. Telefonul Android se apropie de terminal (sau folosim scriptul de test)
7. Interfața afișează **✅ APROBAT** cu codul de autorizare

### Backup curl (dacă ESP32 nu este disponibil)

```powershell
# RULEAZĂ generate_demo_macs.py și înlocuiește MAC_PLACEHOLDER cu valorile reale
# nonce=DEMO0001 | timestamp=2026-06-01T10:00:00Z | atc=9001 | DPAN=4000000000000001

curl.exe -s -X POST http://localhost:8001/api/v1/payments/authorize `
  -H "Content-Type: application/json" `
  -H "X-Idempotency-Key: DEMO-SC1-HAPPY-001" `
  -H "X-Terminal-Id: POS-DEMO-BUC-001" `
  -d '{
    "dpan": "4000000000000001",
    "transaction": {
      "amount": 8750,
      "currency": "RON",
      "pos_nonce": "DEMO0001",
      "terminal_timestamp": "2026-06-01T10:00:00Z"
    },
    "cryptogram": {
      "mac": "MAC_PLACEHOLDER",
      "atc": 9001
    }
  }'
```

### Rezultat așteptat

```json
HTTP 200
{
  "status": "APPROVED",
  "auth_code": "AUTH-XXXXXX",
  "risk_score": 0,
  "bank": "BT"
}
```

- **ESP32 display:** ecran verde „APROBAT" + suma
- **Grafana:** tranzacție nouă apare în panoul „Transactions/minute", risk_score = 0
- **pgAdmin (bank_bt):** `SELECT pan, status, risk_score FROM transactions ORDER BY created_at DESC LIMIT 1;`

### Ce să explici juriului

1. **Arhitectura 5-servicii:** ESP32 → Gateway → Card Network → Banca emitentă. Fiecare serviciu are o singură responsabilitate (Separation of Concerns).
2. **Formula MAC 2-step HMAC:**
   - `Session_Key = HMAC-SHA256(master_key, ATC_ca_string)`
   - `MAC_input = f"{amount}|{currency}|{nonce}|{timestamp}|{atc}"`
   - `MAC = HMAC-SHA256(session_key, MAC_input.encode('utf-8')).hexdigest()`
   - ATC-ul legat de sesiune previne reutilizarea cheii între tranzacții.
3. **Tokenizarea:** Telefonul trimite DPAN (Digital PAN), nu PAN-ul real. Dacă terminalul e compromis, DPAN-ul nu e utilizabil singur — banca îl poate invalida instant.

### Întrebări probabile

- **Q: De ce suma e în cenți, nu RON cu zecimale?**
  A: Aritmetica floating-point (0.1 + 0.2 ≠ 0.3 în IEEE 754). Suma în cenți (integer) elimină erorile de rotunjire în calcule financiare.

- **Q: Ce este ATC?**
  A: Application Transaction Counter — un contor crescător stocat pe card. La fiecare tranzacție crește cu 1. Backend-ul respinge orice ATC mai mic sau egal cu ultimul văzut (protecție replay attack).

---

## Scenariul 2 — Velocity Fraud Detection

**Demonstrează:** Fraud Engine-ul detectează tranzacții prea frecvente de la același card și escaladează automat: APPROVED → CHALLENGE_REQUIRED → DECLINED. Scorul de risc crește de la 0 la 91+ în 14 tranzacții.

### Date de test

| Câmp | Valoare |
|---|---|
| Bancă emitentă | BCR |
| PAN (istoric pgAdmin) | `5105105105105100` |
| DPAN (seeded TSP, funcționează live) | `5000000000000002` |
| CVV | `111` |
| Sumă per tranzacție | `50 RON` (5000 cenți) |
| Nr. tranzacții | 8 |
| Interval realist | 90s (≈ 14 minute) |
| Interval rapid demo | 2s (Redis nu decays în 2s) |

> **Context pgAdmin:** Baza de date `bank_bcr` conține deja 8 tranzacții istorice pentru PAN `5105105105105100` (de acum 5 zile) cu risk scores 0→6→12→45→57→78→85→91 — ideal pentru a arăta escaladarea vizuală juriului **înainte** de a rula demo-ul live.

### Pas 0 — Arată contextul istoric în pgAdmin

```sql
-- În pgAdmin → bank_bcr → Query Tool:
SELECT transaction_id, amount/100.0 AS amount_ron, status, risk_score,
       TO_CHAR(created_at, 'HH24:MI:SS') AS ora
FROM transactions
WHERE pan = '5105105105105100'
ORDER BY created_at ASC;
```

**Output așteptat:** 8 rânduri, risk_score crescând 0→91, status schimbând APPROVED→CHALLENGE_REQUIRED→DECLINED.

### Rulare demo live

```powershell
# Demo rapid (2s interval — arată escaladarea imediată):
python tests/velocity_fraud_demo.py

# Demo realist (90s interval ≈ 14 minute):
$env:DEMO_INTERVAL = "90"
python tests/velocity_fraud_demo.py
```

Scriptul:
1. Resetează automat cheile Redis `velocity:`, `risk:`, `amounts:` pentru PAN-ul configurat
2. Trimite 8 tranzacții cu ATC = `int(time.time() * 1000) + index` (crescător, anti-replay)
3. Afișează în timp real: HTTP status, decizie, risk_score
4. Sumarizează rezultatele la final

### Resetare Redis între rulări

```powershell
# PowerShell — șterge starea de fraudă fără să atingi DB-ul:
$pw = "Ion_Filotti_Cantacuzino"
$pan = "5000002222222222"
docker exec nfc-redis-master redis-cli `
  -a $pw --no-auth-warning `
  DEL "velocity:$pan" "risk:$pan" "amounts:$pan"
```

### Rezultat așteptat

```
Nr   ATC                 HTTP  Decizie                Risk
--   ------------------  ----  ---------------------  ----
 1   1748000000001001   200   ✅ APPROVED              0
 2   1748000000001002   200   ✅ APPROVED              6
 3   1748000000001003   200   ✅ APPROVED             12
 4   1748000000001004   401   🔐 CHALLENGE_REQUIRED   45
 5   1748000000001005   401   🔐 CHALLENGE_REQUIRED   57
 6   1748000000001006   200   ❌ DECLINED             78
 7   1748000000001007   200   ❌ DECLINED             85
 8   1748000000001008   200   ❌ DECLINED             91
```

- **Grafana:** graficul „Fraud Score per PAN" arată creșterea exponențială
- **pgAdmin:** `SELECT status, risk_score FROM transactions WHERE pan='5000002222222222' ORDER BY created_at DESC LIMIT 8;`

### Ce să explici juriului

1. **Formula scoring velocity:** Fraud Engine numără tranzacțiile în fereastră de 10 minute. Fiecare tranzacție adaugă ~15 puncte la scor (W_velocity = 30, normalizat).
2. **Degradare exponențială (decay):** Scorul se „uită" cu `lambda = 0.173`, rezultând un half-life de 4 ore: `score_actual = score_inițial × e^(-λt)`. Un card inactiv 4 ore pierde jumătate din scorul de risc.
3. **Praguri adaptive:** Sub 40 → APPROVED. Între 40 și 75 → STEP-UP (PIN challenge). Peste 75 → DECLINED automat. Valorile sunt configurabile în `.env` (`FRAUD_SCORE_ALLOW_THRESHOLD`, `FRAUD_SCORE_STEP_UP_THRESHOLD`).

### Întrebări probabile

- **Q: De ce nu blocați de la prima tranzacție repetitivă?**
  A: Un client legitim poate face mai multe plăți consecutiv (ex: salariaților în numerar sau cumpărături multiple). Pragul de 3 tranzacții normale (risk < 40) înainte de step-up echilibrează securitatea cu experiența utilizatorului.

- **Q: Ce se întâmplă dacă Fraud Engine e oprit?**
  A: Fail-Closed. Gateway-ul respinge TOATE tranzacțiile cu `503 IDEMPOTENCY_STORE_DOWN` dacă Redis nu răspunde. Nicio tranzacție nu poate ocoli rate limiting-ul sau scoring-ul.

---

## Scenariul 3 — Amount Deviation

**Demonstrează:** Fraud Engine detectează o tranzacție de 4500 RON față de o medie istorică de ~44 RON. Ratio ~100x produce un scor sigmoid N2 ≈ 0.98 → contribuție 39 puncte → CHALLENGE_REQUIRED.

### Date de test

| Câmp | Valoare |
|---|---|
| Bancă emitentă | ING |
| PAN (istoric pgAdmin) | `5200828282828210` |
| DPAN (seeded TSP, funcționează live) | `5000000000000003` |
| CVV | `444` |
| Sumă anomalie | `4500 RON` (450000 cenți) |
| Media istorică în Redis | `~4417 cenți` (~44 RON) |
| Ratio | ~102× media |
| N2 sigmoid | ≈ 0.98 |
| Contribuție amount | ≈ 39.2 puncte (W=40 × 0.98) |
| Decizie așteptată | CHALLENGE_REQUIRED (risk ≈ 58) |

> **IMPORTANT:** NU reseta Redis `amounts:` pentru ING înainte de acest scenariu. Baseline-ul de 6 tranzacții normale (32-89 RON) trebuie să fie în Redis pentru ca deviația să fie calculată corect.

### Pas 0 — Arată contextul istoric în pgAdmin

```sql
-- În pgAdmin → bank_ing → Query Tool:
SELECT amount/100.0 AS amount_ron, status, risk_score,
       TO_CHAR(created_at, 'DD Mon') AS data
FROM transactions
WHERE pan = '5200828282828210'
ORDER BY created_at ASC;
```

**Output așteptat:** 6 tranzacții normale (32-89 RON, risk 0-3), ultima de 4500 RON cu CHALLENGE_REQUIRED.

### Pas 1 — Pre-warm Redis (6 tranzacții normale)

**Dacă Redis e gol** (sistem proaspăt sau după resetare completă), trebuie să construiești baseline-ul înainte de tranzacția anomalie:

```powershell
# Rulează generate_demo_macs.py și folosește comenzile din scenario_3_prewarm_6_normal_txns
# Trimite cele 6 tranzacții normale înainte de tranzacția de 4500 RON
docker exec nfc-gateway python /tmp/generate_demo_macs.py
# Copiază comenzile curl din "scenario_3_prewarm_6_normal_txns" și rulează-le în ordine
```

### Pas 2 — Tranzacția anomalie

```powershell
# RULEAZĂ generate_demo_macs.py și înlocuiește MAC_PLACEHOLDER
# nonce=DEMO0003 | timestamp=2026-06-01T10:00:00Z | atc=3007 | DPAN=5000000000000003

curl.exe -s -X POST http://localhost:8001/api/v1/payments/authorize `
  -H "Content-Type: application/json" `
  -H "X-Idempotency-Key: DEMO-SC3-AMT-007" `
  -H "X-Terminal-Id: POS-DEMO-ING-001" `
  -d '{
    "dpan": "5000000000000003",
    "transaction": {
      "amount": 450000,
      "currency": "RON",
      "pos_nonce": "DEMO0003",
      "terminal_timestamp": "2026-06-01T10:00:00Z"
    },
    "cryptogram": {
      "mac": "MAC_PLACEHOLDER",
      "atc": 3007
    }
  }'
```

### Rezultat așteptat

```json
HTTP 401
{
  "detail": {
    "error_code": "CHALLENGE_REQUIRED",
    "transaction_id": "TXN-XXXXXXXX",
    "original_dpan": "5000000000000003"
  }
}
```

### Formula amount deviation (pentru explicat juriului)

```
media_istorica = mean(ultimele N sume din Redis)  ≈ 4417 cenți
ratio = amount_curent / media_istorica = 450000 / 4417 ≈ 101.9

# Funcție sigmoid pentru normalizare:
N2 = 1 / (1 + e^(-0.1 × (ratio - 10)))
N2 = 1 / (1 + e^(-0.1 × (101.9 - 10)))
N2 = 1 / (1 + e^(-9.19))
N2 ≈ 0.9999 → arrondit la 0.98 în practică

# Contribuție la scor:
amount_contribution = W_amount × N2 = 40 × 0.98 ≈ 39.2 puncte

# Scor total (fără velocity, fără TSP risk):
risk_score ≈ 39 → sub 40 → APPROVED dacă nu era nimic altceva
# Cu TSP risk_level > 0 sau velocity minor, trece de 40 → CHALLENGE_REQUIRED
```

### Ce să explici juriului

1. **Sigmoid normalizează orice ratio la [0, 1]:** Un ratio de 2× produce N2 ≈ 0.50 (20 puncte), un ratio de 10× produce N2 ≈ 0.73 (29 puncte), un ratio de 100× produce N2 ≈ 0.98 (39 puncte). Funcția e continuă și diferențiabilă — nu are praguri abrupte.
2. **Sliding window în Redis:** `amounts:{PAN}` e o listă Redis LPUSH/LTRIM cu ultimele 100 tranzacții. Media se recalculează la fiecare tranzacție nouă — nu depinde de DB.
3. **Cel mai puternic semnal:** Weight = 40 (cel mai mare din cei 3 factori: velocity W=30, amount W=40, TSP W=30). O anomalie de 100× garantează step-up chiar dacă velocity e zero.

---

## Scenariul 4 — Sold Insuficient

**Demonstrează:** Banca emitentă respinge tranzacția cu `INSUFFICIENT_FUNDS` când soldul contului nu acoperă suma. Soldul nu se modifică după tentativă (atomicitate ACID). Tranzacția e înregistrată în DB ca DECLINED.

### Date de test

| Câmp | Valoare |
|---|---|
| Bancă emitentă | BT (Banca Transilvania) |
| PAN | `4000002222222224` |
| CVV | `456` |
| Sold disponibil | `50 RON` (5000 cenți) |
| Sumă request | `100 RON` (10000 cenți) |
| Rezultat așteptat | `DECLINED — INSUFFICIENT_FUNDS` |

> **NOTĂ DPAN:** PAN `4000002222222224` necesită enrollment în TSP pentru a genera un DPAN valid. Calea cea mai sigură pentru demo este via **pgAdmin** (verificare sold) combinată cu **Casa de Marcat** (dacă cardul fizic e disponibil).

### Pas 1 — Verificare sold înainte în pgAdmin

```sql
-- În pgAdmin → bank_bt → Query Tool:
SELECT pan, balance, balance/100.0 AS balance_ron
FROM accounts
WHERE pan = '4000002222222224';
```

**Rezultat așteptat:** `balance = 5000` (50.00 RON)

### Pas 2 — Tentativă plată 100 RON

Via Casa de Marcat (dacă cardul e disponibil):
1. Adaugă produse de cel puțin 100 RON (ex: Salată Caesar × 5 = 110 RON)
2. Apasă **ÎNCASEAZĂ**
3. Prezintă cardul cu PAN `4000002222222224`
4. Terminalul afișează **❌ REFUZAT**

Via curl (necesită DPAN enrolled):
```powershell
# Necesită DPAN_BT_INS obținut după enrollment al PAN-ului 4000002222222224
# Înlocuiește <<DPAN_BT_INS>> cu DPAN-ul real

curl.exe -s -X POST http://localhost:8001/api/v1/payments/authorize `
  -H "Content-Type: application/json" `
  -H "X-Idempotency-Key: DEMO-SC4-INS-001" `
  -H "X-Terminal-Id: POS-DEMO-ATM-001" `
  -d '{
    "dpan": "<<DPAN_BT_INS>>",
    "transaction": {
      "amount": 10000,
      "currency": "RON",
      "pos_nonce": "DEMO0004",
      "terminal_timestamp": "2026-06-01T10:00:00Z"
    },
    "cryptogram": {
      "mac": "MAC_PLACEHOLDER",
      "atc": 4001
    }
  }'
```

### Rezultat așteptat

```json
HTTP 200
{
  "status": "DECLINED",
  "error_code": "INSUFFICIENT_FUNDS",
  "bank": "BT"
}
```

### Pas 3 — Verificare sold neschimbat după tentativă

```sql
-- Soldul trebuie să rămână 5000 (neschimbat):
SELECT pan, balance, balance/100.0 AS balance_ron
FROM accounts
WHERE pan = '4000002222222224';
```

**Output așteptat:** `balance = 5000` — identic cu înainte de tentativă.

Verificare în tabelul de tranzacții:
```sql
SELECT transaction_id, amount/100.0, status, risk_score, created_at
FROM transactions
WHERE pan = '4000002222222224'
ORDER BY created_at DESC LIMIT 5;
```

### Ce să explici juriului

1. **SELECT FOR UPDATE:** Banca emitentă blochează rândul contului cu `SELECT FOR UPDATE` înainte de orice verificare. O a doua cerere concurentă pentru același cont AȘTEAPTĂ primul COMMIT înainte să citească soldul — elimină race condition pentru double spending.
2. **Atomicitate ACID:** UPDATE balance și INSERT transaction sunt în aceeași tranzacție SQL. Dacă oricare din ele eșuează (ex: sold insuficient), ROLLBACK automat — soldul nu se modifică niciodată parțial.
3. **Tranzacția e înregistrată:** DECLINED nu înseamnă că nu există înregistrare. Banca stochează toate tentativele (inclusiv DECLINED) pentru audit și fraud detection ulterioară.

---

## Scenariul 5 — Step-Up PIN Challenge (bonus)

**Demonstrează:** Fluxul complet de Step-Up Authentication: Gateway primește un card cu `risk_level=55` din TSP → emite `401 CHALLENGE_REQUIRED` → ESP32 afișează „INTRODU PIN" → utilizatorul introduce PIN-ul pe tastatura fizică → PIN Block RSA-OAEP decriptat de bancă → APPROVED.

### Date de test

| Câmp | Valoare |
|---|---|
| Bancă emitentă | BT |
| PAN | `4000001111111111` |
| DPAN (seeded TSP, risk_level=55) | `TEST-STEP-UP-BT` |
| PIN | `1234` + `#` pentru confirmare |
| Sumă | `12.50 RON` (1250 cenți) |
| Risk level token | 55 (forțează CHALLENGE_REQUIRED) |

### Rulare via script automat (recomandat)

```powershell
# Încarcă variabilele din .env:
Get-Content .env | ForEach-Object {
    if ($_ -match '^([^#=][^=]*)=(.*)$') {
        [System.Environment]::SetEnvironmentVariable($matches[1].Trim(), $matches[2].Trim())
    }
}

# Rulează testul de Step-Up pe ESP32 fizic:
python tests/live_manual_stepup.py
```

### Rulare via Casa de Marcat (dacă ESP32 are DPAN TEST-STEP-UP-BT)

1. Deschide http://localhost:8005/pos
2. Adaugă produse pentru 12.50 RON (Cafea Espresso × 1)
3. Apasă **ÎNCASEAZĂ**
4. Prezintă cardul cu DPAN `TEST-STEP-UP-BT`
5. Interfața afișează **🔐 Introduceți PIN pe terminal...**
6. Pe tastatura ESP32: `1 2 3 4 #`
7. Interfața afișează **✅ APROBAT**

### Fluxul tehnic complet

```
1. POST /authorize cu DPAN TEST-STEP-UP-BT
   → TSP returnează risk_level=55
   → Gateway calculează risk_score = 55 (TSP W=30 × 55/100 × ... ≈ 55)
   → 40 ≤ 55 < 75 → CHALLENGE_REQUIRED

2. Gateway returnează:
   HTTP 401
   { "error_code": "CHALLENGE_REQUIRED",
     "transaction_id": "TXN-XXXXXXXX" }

3. ESP32 afișează pe ecran galben: "INTRODU PIN"

4. Utilizator introduce: 1, 2, 3, 4, # pe tastatura fizică

5. ESP32 construiește PIN Block: f"{transaction_id}:1234"
   Criptează cu RSA-OAEP SHA256 (cheia publică BT):
   pin_block_encrypted = RSA_OAEP.encrypt(pin_block.encode('utf-8'))
   pin_block_b64 = base64.b64encode(encrypted).decode('utf-8')

6. POST /challenge
   { "transaction_id": "TXN-XXXXXXXX",
     "original_dpan": "TEST-STEP-UP-BT",
     "pin_block_encrypted": "<base64>" }

7. Gateway → Banca BT decriptează RSA-OAEP cu cheia privată
   Extrage PIN din format: "{transaction_id}:{pin}"
   Verifică: SHA256(PAN + pin) == stored_pin_hash (timing-safe)
   → HTTP 200 APPROVED
```

### Rezultat așteptat

```json
HTTP 200
{
  "status": "APPROVED",
  "auth_code": "AUTH-XXXXXX",
  "bank": "BT"
}
```

### Ce să explici juriului

1. **RSA-OAEP pentru PIN Block:** PIN-ul nu circulă în clar pe rețea niciodată. ESP32 îl criptează cu cheia publică a băncii — numai banca, cu cheia privată, poate decripta. Un interceptor vede doar text cifrat aleatoriu.
2. **PIN Block include transaction_id:** Format `{transaction_id}:{pin}`. Dacă un atacator interceptează PIN Block-ul criptat, nu îl poate reutiliza pentru o altă tranzacție (transaction_id e diferit).
3. **Verificare timing-safe:** `hmac.compare_digest(computed_hash, stored_hash)` — nu `==`. Operatorul `==` returnează False la primul caracter diferit (timing attack: atacatorul măsoară microsecunde). `compare_digest` compară TOATE caracterele în timp constant.

---

## Resetare între demonstrații

### Redis (fraud state) — fără să pierzi tranzacțiile din DB

```powershell
# PowerShell — resetare selectivă per PAN:
$pw = "Ion_Filotti_Cantacuzino"

# BT (SC1, SC5):
docker exec nfc-redis-master redis-cli -a $pw --no-auth-warning `
  DEL "velocity:4000001111111111" "risk:4000001111111111" "amounts:4000001111111111"

# BCR (SC2 — seeded DPAN):
docker exec nfc-redis-master redis-cli -a $pw --no-auth-warning `
  DEL "velocity:5000002222222222" "risk:5000002222222222" "amounts:5000002222222222"

# ING (SC3 — ATENȚIE: NU șterge amounts: dacă vrei să menții baseline-ul pentru SC3!):
docker exec nfc-redis-master redis-cli -a $pw --no-auth-warning `
  DEL "velocity:5111113333333333" "risk:5111113333333333"
# amounts:5111113333333333 NU se șterge dacă SC3 urmează imediat după

# Resetare completă toate cheile (orice PAN):
foreach ($pattern in @("velocity:*", "risk:*", "amounts:*")) {
    $keys = docker exec nfc-redis-master redis-cli -a $pw --no-auth-warning --scan --pattern $pattern
    if ($keys) {
        $keys | ForEach-Object {
            docker exec nfc-redis-master redis-cli -a $pw --no-auth-warning DEL $_
        }
    }
}
```

### Resetare completă (inclusiv DB — repornire din zero)

```powershell
# ATENȚIE: șterge toate datele din DB și Redis!
docker compose down -v postgres-bank postgres-tsp redis-master
docker compose up -d postgres-bank postgres-tsp redis-master
docker compose restart issuing-bank-bt issuing-bank-bcr issuing-bank-ing tsp card-network gateway
```

### Rebuild dashboard (după modificări de cod)

```powershell
docker compose up --build dashboard
```

---

## Comenzi Rapide (Cheat Sheet)

| Acțiune | Comandă |
|---|---|
| Verificare stare sistem | `docker compose ps` |
| Teste E2E WiFi Direct | `docker cp tests/wifi_direct_test.py nfc-gateway:/tmp/ && docker exec nfc-gateway python /tmp/wifi_direct_test.py` |
| Teste E2E în container | `docker exec nfc-gateway python /tmp/e2e_test.py` |
| Logs Gateway | `docker logs nfc-gateway --tail 20 -f` |
| Logs Bancă BT | `docker logs nfc-issuing-bank-bt --tail 20 -f` |
| Logs Card Network | `docker logs nfc-card-network --tail 20 -f` |
| Sold cont BT (toate) | `docker exec postgres-bank psql -U bank_bt -d bank_bt -c "SELECT pan, balance/100.0 AS ron FROM accounts ORDER BY pan;"` |
| Sold cont BT specific | `docker exec postgres-bank psql -U bank_bt -d bank_bt -c "SELECT pan, balance FROM accounts WHERE pan='4000002222222224';"` |
| Tranzacții recente BT | `docker exec postgres-bank psql -U bank_bt -d bank_bt -c "SELECT transaction_id, amount/100.0, status, risk_score FROM transactions ORDER BY created_at DESC LIMIT 5;"` |
| Tranzacții recente BCR | `docker exec postgres-bank psql -U bank_bcr -d bank_bcr -c "SELECT transaction_id, amount/100.0, status, risk_score FROM transactions ORDER BY created_at DESC LIMIT 5;"` |
| Token TSP DPAN | `docker exec postgres-tsp psql -U tsp_user -d tsp_db -c "SELECT dpan, pan, risk_level, status FROM tokens;"` |
| Blacklist terminal | `curl.exe -s -X POST http://localhost:8001/api/v1/admin/terminals/blacklist -H "Content-Type: application/json" -d "{\"terminal_id\":\"POS-BUC-001\",\"action\":\"ADD\"}"` |
| Reset Redis SC2 (rapid) | `docker exec nfc-redis-master redis-cli -a Ion_Filotti_Cantacuzino --no-auth-warning DEL velocity:5000002222222222 risk:5000002222222222 amounts:5000002222222222` |
| Regenerare MAC-uri | `docker exec nfc-gateway python /tmp/generate_demo_macs.py` |
| Restart serviciu | `docker compose restart <nume-serviciu>` |
| Health check | `curl.exe -s http://localhost:8001/health \| python -m json.tool` |

---

## MAC-uri Pre-calculate

> **INSTRUCȚIUNI:**
> 1. Rulează comenzile de mai jos înainte de prezentare
> 2. Inserează output-ul JSON în această secțiune
> 3. Folosește comenzile `curl_command` din JSON direct în terminal
>
> ```powershell
> docker cp scripts/generate_demo_macs.py nfc-gateway:/tmp/
> docker exec nfc-gateway python /tmp/generate_demo_macs.py
> ```

```json
// RULEAZĂ generate_demo_macs.py și înlocuiește acest bloc cu output-ul real
// Exemplu structură output:
{
  "scenario_1_happy_path": {
    "mac": "MAC_PLACEHOLDER",
    "atc": 1001,
    "pos_nonce": "DEMO0001",
    "terminal_timestamp": "2026-06-01T10:00:00Z",
    "curl_command": "curl.exe -s -X POST ..."
  },
  "scenario_4_insufficient_funds": {
    "mac": "MAC_PLACEHOLDER",
    "atc": 4001,
    "curl_command": "curl.exe -s -X POST ..."
  }
}
```

---

## Întrebări Probabile Juriu + Răspunsuri

### Q: De ce WiFi în loc de NFC?
**A:** Modulul NFC s-a defectat cu 2 zile înainte de prezentare. Am migrat comunicarea pe WiFi în 2 ore — backend-ul a rămas complet neschimbat deoarece arhitectura era deja separată corect. Demonstrează că Separation of Concerns funcționează: stratul de transport (NFC vs WiFi) e izolat de logica de business.

---

### Q: Ce se întâmplă dacă Redis cade?
**A:** Fail-Closed. Gateway-ul respinge TOATE tranzacțiile cu `503 IDEMPOTENCY_STORE_DOWN`. Nicio tranzacție nu poate ocoli rate limiting-ul sau idempotența. Decizia de design: prefer să refuz tranzacții legitime decât să permit double-spending sau bypass de fraud scoring.

---

### Q: Cum preveniți double spending?
**A:** Trei mecanisme suprapuse:
1. `SELECT FOR UPDATE` blochează rândul contului pe toată durata tranzacției SQL
2. `UPDATE balance` și `INSERT transaction` sunt în aceeași tranzacție ACID — rollback automat dacă oricare eșuează
3. Idempotency key în Redis: al doilea request identic primește același răspuns fără să re-execute logica

---

### Q: PIN-ul e stocat în baza de date?
**A:** Nu în clear. Implementarea PoC stochează `SHA256(PAN + PIN)` — PAN-ul servește ca salt implicit, prevenind rainbow table attacks per cont. Producția ar necesita PBKDF2-HMAC-SHA256 cu 100.000 iterații și salt random per cont (recomandat PCI-DSS). Verificarea e timing-safe cu `hmac.compare_digest` — nu cu `==` (care ar fi vulnerabil la timing attack).

---

### Q: Ce este mTLS și de ce îl folosiți?
**A:** Mutual TLS — ambele părți își verifică certificatele. ESP32 prezintă un certificat semnat de CA-ul nostru intern. NGINX verifică certificatul înainte de orice conexiune TCP. Un terminal fără certificat valid nu poate trimite niciodată o cerere la Gateway — chiar dacă cunoaște IP-ul și portul.

---

### Q: Cum funcționează rutarea multi-bancă?
**A:** BIN lookup — primele 6 cifre ale PAN-ului identifică banca emitentă. Card Network menține un tabel de routing de la cel mai specific (6 cifre) la cel mai generic (1 cifră). BT, BCR și ING sunt instanțe separate ale aceleiași imagini Docker, parametrizate cu `BANK_ID` și `POSTGRES_DB` diferite — zero cod duplicat.

---

### Q: Ce face Fraud Engine-ul exact?
**A:** Scoring ponderat din 3 componente:
- **Velocity (W=30):** frecvența tranzacțiilor în fereastra de 10 minute
- **Amount Deviation (W=40):** deviația față de media istorică prin funcție sigmoid: `N2 = 1/(1+e^(-0.1×(ratio-10)))`
- **TSP Risk (W=30):** `risk_level` per token din Token Vault

Scorul total se degradează exponențial cu `lambda=0.173` (half-life 4 ore). Sub 40 → APPROVED, 40-75 → STEP-UP PIN, peste 75 → DECLINED.

---

### Q: Cum asigurați că nu există replay attack pe MAC?
**A:** Trei apărări:
1. **ATC crescător:** Backend-ul stochează ultimul ATC văzut per DPAN în DB. Un ATC ≤ ultimul stocat → `INVALID_ATC_REPLAY`. ATC-ul e un contor care crește cu fiecare tranzacție.
2. **Nonce unic per tranzacție:** Generat de ESP32 ca UUID hex 8 caractere. Chiar dacă ATC-ul ar fi acceptat, MAC-ul calculat cu un nonce diferit ar eșua validarea.
3. **Session Key per ATC:** `Session_Key = HMAC-SHA256(master_key, str(atc))`. Re-utilizarea aceluiași ATC produce același session key → același MAC → detectat ca replay.

---

### Q: De ce folosiți tokenizare (DPAN) și nu PAN direct?
**A:** Dacă terminalul POS e compromis (malware, skimmer), atacatorul obține DPAN-ul — nu PAN-ul real. DPAN-ul:
- E valid doar pentru un singur device (device binding)
- Poate fi revocat instant din TSP fără să afecteze cardul fizic
- Nu e utilizabil la alt terminal decât cel enrolled
- PAN-ul real rămâne numai în baza de date a băncii emitente, niciodată pe terminal

---

### Q: Ce se întâmplă cu idempotența dacă același request e trimis de 2 ori?
**A:** `X-Idempotency-Key` e stocat în Redis cu un TTL de 24 ore. Al doilea request cu aceeași cheie primește exact același răspuns ca primul — fără re-executarea logicii de autorizare. Asta previne:
- Dubla debitare la timeout de rețea și retry
- Race conditions când clientul trimite simultan din cauza unui bug

---

### Q: Cum gestionați cazul în care Gateway-ul primește un request în timp ce procesează un altul pentru același terminal?
**A:** Rate limiting per terminal: `GATEWAY_RATE_LIMIT_PER_TERMINAL=2` req/sec (din spec). La depășire, Gateway returnează `429 Too Many Requests`. Rate limit-ul e implementat în Redis cu sliding window — funcționează și în deployments multi-instanță. Un terminal fizic normal nu face mai mult de 1 req/10 secunde — 2 req/sec e pentru teste automatizate.

---

### Q: Cum ați testa în producție? Ce lipsește față de un sistem real?
**A:** Ce lipsește (cu bună știință pentru PoC):
1. **HSM (Hardware Security Module)** pentru stocarea cheilor HMAC — în PoC sunt în `.env`
2. **Certificat de producție** (Let's Encrypt sau DigiCert) în loc de CA self-signed
3. **Audit log imutabil** (append-only, semnat digital) pentru PCI-DSS compliance
4. **PBKDF2 pentru PIN** în loc de SHA256 simplu
5. **Kubernetes + HPA** pentru autoscaling la load mare

Ce există și e production-grade: ACID transactions, SELECT FOR UPDATE, mTLS, timing-safe comparisons, idempotency, exponential decay fraud scoring.
