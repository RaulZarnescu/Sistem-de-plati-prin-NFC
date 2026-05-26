# Scenarii Demo — NFC Payment PoC
**Versiune:** 1.1 | **Data:** Mai 2026 | **Autor:** Echipă PoC

---

## Pregătire înainte de prezentare

### Pornire sistem
```powershell
cd "D:\Apps\Sistem de plati NFC\Sistem-de-plati-prin-NFC"
docker compose up -d
docker compose ps   # verifici că toate containerele sunt "healthy"
```

### Verificare stare baze de date
```powershell
# Conturi seed (trebuie să apară 13 rânduri per bancă)
docker exec sistem-de-plati-prin-nfc-postgres-bank-1 `
  psql -U bank_bt -d bank_bt -c "SELECT pan, balance, exp_month, exp_year, cvv_hash IS NOT NULL as has_cvv FROM accounts;"

# Tranzacții demo BT (trebuie 13 rânduri: 10 SC1 + 3 SC4)
docker exec sistem-de-plati-prin-nfc-postgres-bank-1 `
  psql -U bank_bt -d bank_bt -c "SELECT transaction_id, amount, status, terminal_id, created_at FROM transactions ORDER BY created_at;"
```

### Generare MAC-uri demo
```powershell
# Copiezi scriptul în container și îl rulezi
docker cp scripts\generate_demo_macs.py nfc-gateway:/tmp/
docker exec nfc-gateway python /tmp/generate_demo_macs.py > demo_macs.json

# Verifici că s-au generat 4 scenarii + velocity + prewarm
type demo_macs.json | findstr "scenario_"
```

### URL-uri utile
| Serviciu | URL | Credențiale |
|---|---|---|
| Dashboard servicii | http://localhost:8005 | — |
| Grafana RED metrics | http://localhost:3000 | admin / `GRAFANA_PASSWORD` din .env |
| pgAdmin baze de date | http://localhost:5050 | admin@nfc.dev / admin |
| Prometheus targets | http://localhost:9090/targets | — |
| Gateway Swagger | http://localhost:8001/docs | — |
| Gateway health | http://localhost:8001/health | — |

### Credențiale pgAdmin
- **Email:** `admin@nfc.dev`
- **Parolă:** `admin`
- **Server Banks:** `postgres-bank:5432` · user `postgres` · db `postgres`
  - Baze de date: `bank_bt`, `bank_bcr`, `bank_ing`
- **Server TSP:** `postgres-tsp:5432` · user `tsp_user` · db `tsp_db`

### Resetare Redis între demonstrații
```powershell
# Citești parola Redis din .env
$REDIS_PASS = (Get-Content .env | Select-String "^REDIS_PASSWORD=").Line.Split("=")[1]

# Ștergi profilele de risc acumulate
docker exec nfc-redis-master redis-cli -a $REDIS_PASS --scan --pattern "risk:*" |
  ForEach-Object { docker exec nfc-redis-master redis-cli -a $REDIS_PASS DEL $_ }

# Ștergi historicul velocity (fereastră 10 minute)
docker exec nfc-redis-master redis-cli -a $REDIS_PASS --scan --pattern "velocity:*" |
  ForEach-Object { docker exec nfc-redis-master redis-cli -a $REDIS_PASS DEL $_ }

# Ștergi istoricul sume (Amount Deviation)
docker exec nfc-redis-master redis-cli -a $REDIS_PASS --scan --pattern "amounts:*" |
  ForEach-Object { docker exec nfc-redis-master redis-cli -a $REDIS_PASS DEL $_ }
```

### Resetare completă (volume inclusiv)
```powershell
docker compose down -v postgres-bank postgres-tsp
docker compose up -d postgres-bank postgres-tsp
# Aștepți ~15s pentru healthcheck
docker compose restart issuing-bank-bt issuing-bank-bcr issuing-bank-ing tsp
```

---

## Carduri de test

> **SECURITATE:** CVV-urile de test apar EXCLUSIV în acest document.
> Nu apar în SQL, în codul sursă, sau în log-uri (PCI-DSS Art. 3.3).

### Banca BT (prefix 400000)

| PAN | CVV | Sold inițial | Exp. | Scenariu |
|---|---|---|---|---|
| `4000001111111118` | **123** | 1.500 RON | 12/28 | SC1 — Happy Path |
| `4000002222222224` | **456** | 50 RON | 06/27 | SC4 — Sold Insuficient |
| `4000003333333306` | **789** | 5.000 RON | 03/29 | Rezervă BT |

### Banca BCR (prefix 510510)

| PAN | CVV | Sold inițial | Exp. | Scenariu |
|---|---|---|---|---|
| `5105105105105100` | **111** | 2.000 RON | 12/28 | SC2 — Velocity Fraud |
| `5105105105105118` | **222** | 3.000 RON | 09/27 | Rezervă BCR 1 |
| `5105105105105126` | **333** | 1.000 RON | 04/29 | Rezervă BCR 2 |

### Banca ING (prefix 520082)

| PAN | CVV | Sold inițial | Exp. | Scenariu |
|---|---|---|---|---|
| `5200828282828210` | **444** | 2.500 RON | 12/28 | SC3 — Amount Deviation |
| `5200828282828228` | **555** | 1.500 RON | 08/27 | Rezervă ING 1 |
| `5200828282828236` | **666** | 500 RON | 05/29 | Rezervă ING 2 |

> **Notă Luhn:** Toate PANs demo v2 trec algoritmul Luhn.
> PANs legacy (`4000001111111111` etc.) sunt fixture anterioare — nu Luhn-valide.

---

## Scenariul 1 — Happy Path Normal

### Ce demonstrează
Fluxul complet de plată NFC fără fricțiuni:
**Telefon → POS → Gateway → TSP → Card Network → Issuing Bank BT → APPROVED**
în < 500ms. Demonstrează arhitectura microservicii, logging JSON structurat și
latența conformă NFR-02 (P95 < 800ms).

Istoric în baza de date: 10 tranzacții anterioare APPROVED pe 30 zile.

### Date de test
| Câmp | Valoare |
|---|---|
| PAN | `4000001111111118` |
| CVV | `123` |
| Bancă | BT |
| Exp. | 12/28 |
| Sold disponibil | 1.500 RON (150.000 cenți) |
| Sumă demo | 87,50 RON (8.750 cenți) |
| DPAN | completați după `POST /api/v1/enroll` |

### Pași de reproducere

**Pas 1: Enroll card (o dată per sesiune)**
```powershell
# Înrolează cardul BT și obții JWT + DPAN + hmac_key
curl.exe -s -X POST https://localhost:8443/api/v1/enroll `
  -H "Content-Type: application/json" `
  -d '{
    "pan": "4000001111111118",
    "expiry_month": "12",
    "expiry_year": "28",
    "cvv": "123",
    "device_id": "DEMO-DEVICE-BT-001"
  }' | python -m json.tool

# Salvezi dpan și jwt_token din răspuns
$DPAN_BT  = "<dpan din raspuns>"
$JWT_BT   = "<jwt_token din raspuns>"
```

**Pas 2: Plată (MAC pre-calculat, ATC fix pentru demo)**
```powershell
# MAC pre-calculat pentru nonce=DEMO0001, ts=2026-06-01T10:00:00Z, atc=1001
# Reproductibil dacă BANK_BT_HMAC_KEY nu s-a schimbat
curl.exe -s -X POST http://localhost:8001/api/v1/payments/authorize `
  -H "Content-Type: application/json" `
  -H "X-Idempotency-Key: DEMO-SC1-IKEA-001" `
  -H "X-Terminal-Id: POS-DEMO-BUC-001" `
  -d "{
    \"dpan\": \"$DPAN_BT\",
    \"transaction\": {
      \"amount\": 8750,
      \"currency\": \"RON\",
      \"pos_nonce\": \"DEMO0001\",
      \"terminal_timestamp\": \"2026-06-01T10:00:00Z\"
    },
    \"cryptogram\": {
      \"mac\": \"098a3ca75f45d016624b8849ec58625bab85e5f44b5fb864c255b2b352dbf5c2\",
      \"atc\": 1001
    }
  }"
```

> **Dacă ATC 1001 a mai fost folosit:** incrementați atc și generați MAC nou:
> ```powershell
> docker exec nfc-gateway python /tmp/generate_demo_macs.py
> ```

### Rezultat așteptat
```json
{
  "status": "APPROVED",
  "transaction_id": "TXN-XXXXXXXXXXXXXX",
  "auth_code": "XXXXXXXX",
  "risk_score": 5,
  "processed_at": "2026-..."
}
```

### Verificare în pgAdmin
```sql
-- Verifici că tranzacția apare și soldul a scăzut
SELECT balance FROM accounts WHERE pan = '4000001111111118';
-- Așteptat: 150000 - 8750 = 141250

SELECT transaction_id, amount, status, risk_score
FROM transactions WHERE pan = '4000001111111118'
ORDER BY created_at DESC LIMIT 5;
```

### Ce arăți în Grafana
- Gateway TPS: spike la 1 tranzacție
- P95 latency: sub 200ms (sistem local)
- Error Rate: 0%

### Întrebări probabile juriu
**Q: De ce tranzacția durează < 500ms?**
R: Toate serviciile rulează pe aceeași mașină (PoC). Bugetul real de timeout:
TSP 300ms + Issuing Bank 1.200ms. Spec-ul alocă 2.000ms total pentru rețea 4G.

**Q: Ce se întâmplă dacă TSP-ul nu răspunde?**
R: Gateway-ul are timeout de 300ms pe TSP. Depășit → 503 TSP_SERVICE_UNAVAILABLE.
Demonstrabil: `docker stop nfc-tsp` → trimiteți o cerere → `docker start nfc-tsp`.

---

## Scenariul 2 — Velocity Fraud Detection

### Ce demonstrează
Fraud Engine detectează tranzacții prea frecvente (Velocity Factor, W1=30).
Același utilizator care face 6+ tranzacții în 10 minute escaladează automat:
**APPROVED → CHALLENGE_REQUIRED → DECLINED**.

### Date de test
| Câmp | Valoare |
|---|---|
| PAN | `5105105105105100` |
| CVV | `111` |
| Bancă | BCR |
| Exp. | 12/28 |
| Sold disponibil | 2.000 RON |
| Sumă per tranzacție | 50 RON (5.000 cenți) |

### Pași de reproducere

**Pas 0: Resetare Redis** (mandatory — altfel istoricul anterior afectează rezultatul)
```powershell
$REDIS_PASS = (Get-Content .env | Select-String "^REDIS_PASSWORD=").Line.Split("=")[1]
docker exec nfc-redis-master redis-cli -a $REDIS_PASS DEL "velocity:5105105105105100"
docker exec nfc-redis-master redis-cli -a $REDIS_PASS DEL "risk:5105105105105100"
```

**Pas 1: Enroll card BCR**
```powershell
curl.exe -s -X POST https://localhost:8443/api/v1/enroll `
  -H "Content-Type: application/json" `
  -d '{
    "pan": "5105105105105100",
    "expiry_month": "12",
    "expiry_year": "28",
    "cvv": "111",
    "device_id": "DEMO-DEVICE-BCR-001"
  }' | python -m json.tool
$DPAN_BCR = "<dpan din raspuns>"
```

**Pas 2: 8 tranzacții rapide** — copiați și executați rapid în PowerShell:
```powershell
# Tranzacția 1 — APPROVED (risk 0)
curl.exe -s -X POST http://localhost:8001/api/v1/payments/authorize -H "Content-Type: application/json" -H "X-Idempotency-Key: DEMO-SC2-VEL-001" -H "X-Terminal-Id: POS-DEMO-ONLINE-001" -d "{\"dpan\":\"$DPAN_BCR\",\"transaction\":{\"amount\":5000,\"currency\":\"RON\",\"pos_nonce\":\"DEMO2001\",\"terminal_timestamp\":\"2026-06-01T10:00:00Z\"},\"cryptogram\":{\"mac\":\"c04452901a7d149090fa7c0fb0f790791a312a3221d015920f81d6dcd657e83f\",\"atc\":2001}}"

# Tranzacția 2 — APPROVED (risk ~6)
curl.exe -s -X POST http://localhost:8001/api/v1/payments/authorize -H "Content-Type: application/json" -H "X-Idempotency-Key: DEMO-SC2-VEL-002" -H "X-Terminal-Id: POS-DEMO-ONLINE-001" -d "{\"dpan\":\"$DPAN_BCR\",\"transaction\":{\"amount\":5000,\"currency\":\"RON\",\"pos_nonce\":\"DEMO2002\",\"terminal_timestamp\":\"2026-06-01T10:00:00Z\"},\"cryptogram\":{\"mac\":\"902486078e4965edf133bcb31ec77c4005fc6c9c2424444f16c237edb97a1e79\",\"atc\":2002}}"

# Tranzacția 3 — APPROVED (risk ~12)
curl.exe -s -X POST http://localhost:8001/api/v1/payments/authorize -H "Content-Type: application/json" -H "X-Idempotency-Key: DEMO-SC2-VEL-003" -H "X-Terminal-Id: POS-DEMO-ONLINE-001" -d "{\"dpan\":\"$DPAN_BCR\",\"transaction\":{\"amount\":5000,\"currency\":\"RON\",\"pos_nonce\":\"DEMO2003\",\"terminal_timestamp\":\"2026-06-01T10:00:00Z\"},\"cryptogram\":{\"mac\":\"7d92a6e864c5c29229939c097315bdd1e7be39a9c8bb21dec9a6404cd26fa961\",\"atc\":2003}}"

# Tranzacția 4 — CHALLENGE_REQUIRED (risk ~45)
curl.exe -s -X POST http://localhost:8001/api/v1/payments/authorize -H "Content-Type: application/json" -H "X-Idempotency-Key: DEMO-SC2-VEL-004" -H "X-Terminal-Id: POS-DEMO-ONLINE-001" -d "{\"dpan\":\"$DPAN_BCR\",\"transaction\":{\"amount\":5000,\"currency\":\"RON\",\"pos_nonce\":\"DEMO2004\",\"terminal_timestamp\":\"2026-06-01T10:00:00Z\"},\"cryptogram\":{\"mac\":\"26470d470a86501dfaa155b57a2e70fb178be29bb5dc5f2273ab67133f1f7c1e\",\"atc\":2004}}"

# Tranzacția 5 — CHALLENGE_REQUIRED (risk ~57)
curl.exe -s -X POST http://localhost:8001/api/v1/payments/authorize -H "Content-Type: application/json" -H "X-Idempotency-Key: DEMO-SC2-VEL-005" -H "X-Terminal-Id: POS-DEMO-ONLINE-001" -d "{\"dpan\":\"$DPAN_BCR\",\"transaction\":{\"amount\":5000,\"currency\":\"RON\",\"pos_nonce\":\"DEMO2005\",\"terminal_timestamp\":\"2026-06-01T10:00:00Z\"},\"cryptogram\":{\"mac\":\"404e3307616df9084d92d265868c6dcd6bf7151dfcf635b03900ba13c9570eb1\",\"atc\":2005}}"

# Tranzacția 6 — DECLINED (risk ~78)
curl.exe -s -X POST http://localhost:8001/api/v1/payments/authorize -H "Content-Type: application/json" -H "X-Idempotency-Key: DEMO-SC2-VEL-006" -H "X-Terminal-Id: POS-DEMO-ONLINE-001" -d "{\"dpan\":\"$DPAN_BCR\",\"transaction\":{\"amount\":5000,\"currency\":\"RON\",\"pos_nonce\":\"DEMO2006\",\"terminal_timestamp\":\"2026-06-01T10:00:00Z\"},\"cryptogram\":{\"mac\":\"38f5f3c22b2dd0ccca127af6497b68a8bd88814a950026dcc9b7b2aac6cf7089\",\"atc\":2006}}"

# Tranzacția 7 — DECLINED (risk ~85)
curl.exe -s -X POST http://localhost:8001/api/v1/payments/authorize -H "Content-Type: application/json" -H "X-Idempotency-Key: DEMO-SC2-VEL-007" -H "X-Terminal-Id: POS-DEMO-ONLINE-001" -d "{\"dpan\":\"$DPAN_BCR\",\"transaction\":{\"amount\":5000,\"currency\":\"RON\",\"pos_nonce\":\"DEMO2007\",\"terminal_timestamp\":\"2026-06-01T10:00:00Z\"},\"cryptogram\":{\"mac\":\"530bd8850b223e420710042048778a7ca7d84b7344b06ea2bab3d6c35523c818\",\"atc\":2007}}"

# Tranzacția 8 — DECLINED (risk ~91)
curl.exe -s -X POST http://localhost:8001/api/v1/payments/authorize -H "Content-Type: application/json" -H "X-Idempotency-Key: DEMO-SC2-VEL-008" -H "X-Terminal-Id: POS-DEMO-ONLINE-001" -d "{\"dpan\":\"$DPAN_BCR\",\"transaction\":{\"amount\":5000,\"currency\":\"RON\",\"pos_nonce\":\"DEMO2008\",\"terminal_timestamp\":\"2026-06-01T10:00:00Z\"},\"cryptogram\":{\"mac\":\"2ed99b2c63fc73611e99301eda70360530de5d3716a5840cb0346fa6bd9af7df\",\"atc\":2008}}"
```

### Rezultat așteptat (în ordine)
```
1: {"status":"APPROVED","risk_score":0,...}
2: {"status":"APPROVED","risk_score":~6,...}
3: {"status":"APPROVED","risk_score":~12,...}
4: HTTP 401 {"error_code":"CHALLENGE_REQUIRED","risk_score":~45,...}
5: HTTP 401 {"error_code":"CHALLENGE_REQUIRED","risk_score":~57,...}
6: {"status":"DECLINED","risk_score":~78,...}
7: {"status":"DECLINED","risk_score":~85,...}
8: {"status":"DECLINED","risk_score":~91,...}
```

### Formula vizibilă în log-uri
```
docker logs nfc-issuing-bank-bcr --tail 30 | findstr "Fraud"
```
Output:
```
"Fraud scored. Decay base: 0.0, Velocity: +0.0 (T=0), ..."   ← txn 1
"Fraud scored. Decay base: 6.0, Velocity: +6.0 (T=1), ..."   ← txn 2
"Fraud scored. Decay base: 12.0, Velocity: +12.0 (T=2), ..."  ← txn 3
...
"Fraud scored. ..., Velocity: +30.0 (T=5), ..., Final: 91/100"
```

### Întrebări probabile juriu
**Q: Cum funcționează Velocity Factor matematic?**
R: N1 = min(T/5, 1.0) unde T = număr tranzacții în ultimele 10 minute.
Contribuție = W1 × N1 = 30 × N1. La T≥5: N1=1.0, contribuție maximă = 30 puncte.

**Q: De ce fereastră de 10 minute?**
R: Standard EMV 3DS. Implementat cu Redis Sorted Set: ZADD/ZRANGEBYSCORE atomic,
TTL 20 minute, curățare automată tranzacții expirate.

---

## Scenariul 3 — Amount Deviation

### Ce demonstrează
Fraud Engine detectează o sumă anormală față de media istorică (Amount Deviation
Factor, W2=40). Un utilizator care cheltuie obișnuit 30-90 RON face brusc o
tranzacție de 4.500 RON → CHALLENGE_REQUIRED automat.

### Date de test
| Câmp | Valoare |
|---|---|
| PAN | `5200828282828210` |
| CVV | `444` |
| Bancă | ING |
| Exp. | 12/28 |
| Sold disponibil | 2.500 RON |
| Media istorică | ~44 RON (44.17 cenți × 6 tranzacții) |
| Sumă anomalie | 4.500 RON (450.000 cenți) ≈ 101× media |

> ⚠️ **ATENȚIE:** Fraud Engine-ul folosește Redis pentru istoricul sumelor.
> Trebuie să trimiteți mai întâi 6 tranzacții normale via curl pentru a
> construi baseline-ul Redis. Tranzacțiile din DB (seed) sunt doar vizuale.

### Pași de reproducere

**Pas 0: Resetare Redis**
```powershell
$REDIS_PASS = (Get-Content .env | Select-String "^REDIS_PASSWORD=").Line.Split("=")[1]
docker exec nfc-redis-master redis-cli -a $REDIS_PASS DEL "amounts:5200828282828210"
docker exec nfc-redis-master redis-cli -a $REDIS_PASS DEL "velocity:5200828282828210"
docker exec nfc-redis-master redis-cli -a $REDIS_PASS DEL "risk:5200828282828210"
```

**Pas 1: Enroll card ING**
```powershell
curl.exe -s -X POST https://localhost:8443/api/v1/enroll `
  -H "Content-Type: application/json" `
  -d '{
    "pan": "5200828282828210",
    "expiry_month": "12",
    "expiry_year": "28",
    "cvv": "444",
    "device_id": "DEMO-DEVICE-ING-001"
  }' | python -m json.tool
$DPAN_ING = "<dpan din raspuns>"
```

**Pas 2: 6 tranzacții "normale" (pre-warm Redis)**
```powershell
# Trimiteți toate 6 rapid — construiesc baseline-ul de sume
curl.exe -s -X POST http://localhost:8001/api/v1/payments/authorize -H "Content-Type: application/json" -H "X-Idempotency-Key: DEMO-SC3-PRE-001" -H "X-Terminal-Id: POS-DEMO-ING-001" -d "{\"dpan\":\"$DPAN_ING\",\"transaction\":{\"amount\":3200,\"currency\":\"RON\",\"pos_nonce\":\"DEMO3001\",\"terminal_timestamp\":\"2026-06-01T10:00:00Z\"},\"cryptogram\":{\"mac\":\"1bbbbac59ba7603300dbdb03be054d791b1dd10f99b3ab17b96b27178a1afbbb\",\"atc\":3001}}"
curl.exe -s -X POST http://localhost:8001/api/v1/payments/authorize -H "Content-Type: application/json" -H "X-Idempotency-Key: DEMO-SC3-PRE-002" -H "X-Terminal-Id: POS-DEMO-ING-001" -d "{\"dpan\":\"$DPAN_ING\",\"transaction\":{\"amount\":4100,\"currency\":\"RON\",\"pos_nonce\":\"DEMO3002\",\"terminal_timestamp\":\"2026-06-01T10:00:00Z\"},\"cryptogram\":{\"mac\":\"3b2bfc0751d8942d27e84b49b25a23322df8f8b9190bd300cd9af43833181528\",\"atc\":3002}}"
curl.exe -s -X POST http://localhost:8001/api/v1/payments/authorize -H "Content-Type: application/json" -H "X-Idempotency-Key: DEMO-SC3-PRE-003" -H "X-Terminal-Id: POS-DEMO-ING-001" -d "{\"dpan\":\"$DPAN_ING\",\"transaction\":{\"amount\":2800,\"currency\":\"RON\",\"pos_nonce\":\"DEMO3003\",\"terminal_timestamp\":\"2026-06-01T10:00:00Z\"},\"cryptogram\":{\"mac\":\"a0f1deb16ad1f5548a3cf719bb0710919a07328d85d69abf28b45aaf7da3e973\",\"atc\":3003}}"
curl.exe -s -X POST http://localhost:8001/api/v1/payments/authorize -H "Content-Type: application/json" -H "X-Idempotency-Key: DEMO-SC3-PRE-004" -H "X-Terminal-Id: POS-DEMO-ING-001" -d "{\"dpan\":\"$DPAN_ING\",\"transaction\":{\"amount\":8900,\"currency\":\"RON\",\"pos_nonce\":\"DEMO3004\",\"terminal_timestamp\":\"2026-06-01T10:00:00Z\"},\"cryptogram\":{\"mac\":\"a418a994da52cb2b3b5f3778af5a22bd6eb22b0fec3710e87e9bc64bc7b96442\",\"atc\":3004}}"
curl.exe -s -X POST http://localhost:8001/api/v1/payments/authorize -H "Content-Type: application/json" -H "X-Idempotency-Key: DEMO-SC3-PRE-005" -H "X-Terminal-Id: POS-DEMO-ING-001" -d "{\"dpan\":\"$DPAN_ING\",\"transaction\":{\"amount\":5600,\"currency\":\"RON\",\"pos_nonce\":\"DEMO3005\",\"terminal_timestamp\":\"2026-06-01T10:00:00Z\"},\"cryptogram\":{\"mac\":\"1a053426aec3707b44f8217e46a96ba01bd297ed59fcb904b3660f7663fd268d\",\"atc\":3005}}"
curl.exe -s -X POST http://localhost:8001/api/v1/payments/authorize -H "Content-Type: application/json" -H "X-Idempotency-Key: DEMO-SC3-PRE-006" -H "X-Terminal-Id: POS-DEMO-ING-001" -d "{\"dpan\":\"$DPAN_ING\",\"transaction\":{\"amount\":1900,\"currency\":\"RON\",\"pos_nonce\":\"DEMO3006\",\"terminal_timestamp\":\"2026-06-01T10:00:00Z\"},\"cryptogram\":{\"mac\":\"70c70dc19772e74e427088d743d463374bccede285b18e54f97144d8a6922096\",\"atc\":3006}}"
```

**Pas 3: Tranzacția anomalie — 4.500 RON**
```powershell
curl.exe -s -X POST http://localhost:8001/api/v1/payments/authorize `
  -H "Content-Type: application/json" `
  -H "X-Idempotency-Key: DEMO-SC3-AMT-007" `
  -H "X-Terminal-Id: POS-DEMO-ING-001" `
  -d "{
    \"dpan\": \"$DPAN_ING\",
    \"transaction\": {
      \"amount\": 450000,
      \"currency\": \"RON\",
      \"pos_nonce\": \"DEMO0003\",
      \"terminal_timestamp\": \"2026-06-01T10:00:00Z\"
    },
    \"cryptogram\": {
      \"mac\": \"84f362d891c112d3dcac2ca54bbfba8c7000bf775f4096eb5f7f64018b6b93a7\",
      \"atc\": 3007
    }
  }"
```

### Rezultat așteptat
```json
HTTP 401
{
  "error_code": "CHALLENGE_REQUIRED",
  "risk_score": 58
}
```

### Formula vizibilă în log-uri
```
docker logs nfc-issuing-bank-ing --tail 5
```
Output:
```
"Amount Dev: +39.1 (N2=0.98) — ratio≈101x față de medie (4417 cenți)"
"Fraud scored. ..., Amount Dev: +39.1, ..., Final: 58/100"
```

### Întrebări probabile juriu
**Q: Cum calculați "normal" pentru un utilizator nou?**
R: Prima tranzacție → N2=0 (nicio deviație detectabilă fără baseline).
Baseline se construiește din istoricul Redis List (ultimele 100 tranzacții).

**Q: De ce sigmoid și nu threshold simplu?**
R: Sigmoid oferă penalizare proporțională. 2× media e suspect (N2≈0.5),
10× media e foarte suspect (N2≈0.9), 100× e aproape certitudine (N2≈0.98).
Threshold fix ar genera false positives la variații legitime (ex: cumpărare anuală mare).

---

## Scenariul 4 — Sold Insuficient

### Ce demonstrează
Validarea soldului în PostgreSQL cu `SELECT FOR UPDATE` previne double-spending.
O tranzacție care depășește soldul disponibil e respinsă cu INSUFFICIENT_FUNDS
înainte de orice altă procesare (fraud engine nu mai rulează).

### Date de test
| Câmp | Valoare |
|---|---|
| PAN | `4000002222222224` |
| CVV | `456` |
| Bancă | BT |
| Exp. | 06/27 |
| Sold disponibil | 50 RON (5.000 cenți) |
| Sumă request | 100 RON (10.000 cenți) |

### Pași de reproducere

**Pas 1: Verifici soldul (50 RON)**
```powershell
# Enroll card BT sold mic
curl.exe -s -X POST https://localhost:8443/api/v1/enroll `
  -H "Content-Type: application/json" `
  -d '{
    "pan": "4000002222222224",
    "expiry_month": "06",
    "expiry_year": "27",
    "cvv": "456",
    "device_id": "DEMO-DEVICE-BT-LOW-001"
  }' | python -m json.tool
$DPAN_BT_LOW = "<dpan din raspuns>"
$JWT_BT_LOW  = "<jwt_token din raspuns>"

# Verifici soldul via Android endpoint
curl.exe -s http://localhost:8001/api/v1/accounts/balance `
  -H "Authorization: Bearer $JWT_BT_LOW"
# Așteptat: {"balance_ron": 50.0, "balance_cents": 5000}
```

**Pas 2: Încerci plată de 100 RON (> 50 RON disponibil)**
```powershell
curl.exe -s -X POST http://localhost:8001/api/v1/payments/authorize `
  -H "Content-Type: application/json" `
  -H "X-Idempotency-Key: DEMO-SC4-INS-001" `
  -H "X-Terminal-Id: POS-DEMO-ATM-001" `
  -d "{
    \"dpan\": \"$DPAN_BT_LOW\",
    \"transaction\": {
      \"amount\": 10000,
      \"currency\": \"RON\",
      \"pos_nonce\": \"DEMO0004\",
      \"terminal_timestamp\": \"2026-06-01T10:00:00Z\"
    },
    \"cryptogram\": {
      \"mac\": \"5687bc662dce0b95fc469a13a0324ef5467d32f58bb0de28496433de67b8b803\",
      \"atc\": 4001
    }
  }"
```

### Rezultat așteptat
```json
HTTP 400
{
  "error_code": "INSUFFICIENT_FUNDS",
  "message": "Sold insuficient.",
  "action_required": "DECLINE_TRANSACTION"
}
```

### Verificare în pgAdmin
```sql
-- Soldul rămâne neschimbat (5000 cenți)
SELECT balance FROM accounts WHERE pan = '4000002222222224';

-- Tranzacțiile DECLINED apar în ledger (imutabil)
SELECT transaction_id, amount, status FROM transactions
WHERE pan = '4000002222222224' ORDER BY created_at;
```

### Întrebări probabile juriu
**Q: Cum preveniți double-spending la cereri concurente?**
R: `SELECT ... FOR UPDATE` blochează rândul contului pe durata tranzacției SQL.
Un al doilea request concurrent pentru același cont e pus în așteptare până
primul face COMMIT. Implementat în `issuing_bank/main.py` cu asyncpg transaction.

**Q: De ce se stochează și tranzacțiile DECLINED?**
R: Ledger pattern (imutabilitate totală) — compliance și audit trail.
Trigger `make_transactions_immutable` previne DELETE și UPDATE pe tabelul
transactions (verificabil în pgAdmin: Schema → Triggers).

---

## Notă despre MAC-uri

MAC-urile din comenzile curl de mai sus sunt pre-calculate cu nonce și
timestamp **FIXE** pentru reproductibilitate demo.

**În producție:** ESP32 generează nonce aleatoriu și timestamp curent la
fiecare tranzacție → MAC diferit de fiecare dată.

**Regenerare MAC-uri** (dacă cheile HMAC din .env s-au schimbat):
```powershell
docker cp scripts\generate_demo_macs.py nfc-gateway:/tmp/
docker exec nfc-gateway python /tmp/generate_demo_macs.py > demo_macs_new.json
```

**Formula referință (`shared/crypto_utils.py`):**
```python
mac_input   = f"{amount_cents}|{currency}|{pos_nonce}|{terminal_timestamp}|{atc}"
session_key = bytes.fromhex(BANK_HMAC_KEY)   # cheia master a băncii, direct
mac         = HMAC-SHA256(session_key, mac_input.encode("utf-8")).hexdigest()
```

**Pentru test cu hardware fizic (Android + ESP32):**
Colegul Android calculează MAC-ul cu aceeași formulă.
Primul test de validare cross-platform: verificați că același set de date
produce același MAC în Android (Kotlin/Java) și în backend (Python).

---

## Arhitectura sistemului (pentru juriu)

```
Telefon Android (HCE)
        │ NFC APDU
        ▼
ESP32 + PN532 (POS Terminal)
        │ HTTPS mTLS :443 (POS) / TLS :8443 (Android)
        ▼
NGINX (TLS Terminator)
        │ HTTP intern
        ▼
Payment Gateway :8001 ──→ TSP :8002 (Token Vault PostgreSQL)
        │
        ▼
Card Network Router :8003 (BIN routing longest-prefix-match)
        │
        ├──→ Issuing Bank BT  :8004 ──→ PostgreSQL bank_bt
        ├──→ Issuing Bank BCR :8006 ──→ PostgreSQL bank_bcr
        └──→ Issuing Bank ING :8007 ──→ PostgreSQL bank_ing

Infrastructură transversală:
  Redis    — Rate Limiting, Idempotență, Fraud Engine (velocity/amount/risk)
  Prometheus + Grafana — Metrici RED (Rate/Errors/Duration), Alerte
  pgAdmin  — Administrare baze de date (vizualizare tranzacții, conturi)
```

### Rutare BIN (Card Network Router)
| Prefix IIN | Bancă | Port |
|---|---|---|
| `400000` | BT | :8004 |
| `422222` | BT | :8004 |
| `510510` | BCR | :8006 |
| `520082` | ING | :8007 |
| `4` (fallback) | BT | :8004 |
| `5` (fallback) | BCR | :8006 |

### Praguri Fraud Engine
| Scor | Decizie |
|---|---|
| 0 – 39 | APPROVED |
| 40 – 75 | CHALLENGE_REQUIRED (Step-Up Auth) |
| > 75 | DECLINED |

---

*Document generat pentru NFC Payment PoC — uz intern echipă.*
*Nu distribuiți în afara echipei — conține CVV-uri și date de test.*
