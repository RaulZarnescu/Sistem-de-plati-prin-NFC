# Arhitectura Timpului și Bugetarea Timeout-urilor

Acest document fundamentează cerințele non-funcționale (NFR) și SLA-urile sistemului de plăți NFC. Obiectivul arhitectural este de a atinge o finalitate a tranzacției în aproximativ **1.5 - 2 secunde**, menținând un prag maximal absolut de **5 secunde** doar ca plasă de siguranță pentru degradarea controlată.

---

## 1. Constrângeri Hardware și Rețea (ESP32)

- **Ciclu complet NFC-APDU (NFR-05):** < 400 ms. 
  Acoperă trezirea device-ului mobil, trimiterea comenzilor (ex: GET PROCESSING OPTIONS cu timeout de 300ms) și primirea criptogramei.
- **Network Connect Timeout (Handshake mTLS):** 2000 ms.
  Limită justificată de constrângerile de procesare hardware ale microcontrolerului ESP32 la negocierea criptografică. 
  > *Decizie Arhitecturală:* S-a adoptat utilizarea certificatelor cu curbe eliptice (ECC - Elliptic Curve Cryptography) în defavoarea RSA, reducând astfel timpul de procesare mTLS pe ESP32 sub 1000 ms.
- **HTTP Read/Response Timeout:** 2000 ms.
  Conform principiului *"Fail-Fast"*, Gateway-ul trebuie să livreze un răspuns în maxim 2 secunde. Așteptarea prelungită pe rețele financiare blochează firele de execuție backend (thread starvation) și sabotează UX-ul la punctul de vânzare.

## 2. Nivel Backend: Performanță și Limite (Hard Limits)

Având un buget maxim de citire HTTP impus la **2000 ms**, backend-ul trebuie să aplice timeout-uri interne stricte ce nu pot depăși, însumate, **~1500 ms**, păstrând un tampon de **500 ms** pentru latența rețelei publice 4G/WiFi a terminalului.

| Componentă Backend | SLA Așteptat | Hard Timeout | Justificare |
|---|---|---|---|
| **Gateway ↔ Redis** | 5 - 10 ms | **50 ms** | Rate limit / Idempotență. Operațiune critică In-Memory. |
| **Gateway ↔ TSP** | 20 - 50 ms | **300 ms** | Detokenizare via PostgreSQL. Orice latență mare indică congestia bazei de date. |
| **Gateway ↔ Issuing Bank** | 50 - 150 ms | **1200 ms** | Fraud Engine + Scriere Relațională (ACID). Limita absolută a băncii pentru a nu depăși "Fail-Fast-ul" POS-ului. |
| **Issuing Bank (Crypto)**| **< 15 ms** | N/A | NFR-04: Latență criptografică pentru validarea HMAC. |

> SLA General de Tranzacție (NFR-02):
> - **Latență P95:** < 800 ms
> - **Latență P99:** < 1500 ms

## 3. Politici de Retrying și Failover

- **Idempotent Retry (Algoritm Jitter pe ESP32):** Dacă ESP32 primește timeout-ul HTTP de 2000ms sau status 503/504 de la Gateway, va închide socket-ul și va reîncerca asincron folosind **Exponential Backoff Jitter**, având o bază de *1000 ms* și un cap maxim de *10000 ms*.
- **Recovery Time Objective (RTO) Redis:** 30 secunde maxim (AC-05) pentru promovarea unei replici via Sentinel la căderea masterului.

## 4. Sistemul de Alerte și Observabilitate

Sistemul va monitoriza direct KPI-urile financiare, generând escaladări P1 automat:

1. **Alerte Latență:**
   - **Warning:** P95 > 1500 ms (susținut pe 3 minute).
   - **Critical (P1):** P99 > 2000 ms.
2. **Alerte Securitate și Erori:**
   - **Critical:** Rata erorilor de sistem (5xx) depășește 1% per 5 minute.
   - **Security / Fraud:** Peste 10 MAC-uri/criptograme respinse cumulat într-un minut de pe terminale diferite.
