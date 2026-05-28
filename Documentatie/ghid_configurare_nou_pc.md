# Ghid Complet de Configurare și Rulare pe un PC Nou
Acest document descrie toți pașii necesari pentru a pune în funcțiune sistemul complet de plăți prin NFC (Zonă Centrală + Terminal ESP32) după un `git pull` sau o clonare proaspătă a repozitorului pe un alt calculator.

---

## 📋 1. Cerințe Preliminare (Host System)
Înainte de a începe, asigură-te că noul calculator are instalate următoarele utilitare:
1. **Python 3.8+**: Asigură-te că este adăugat în variabila de mediu `PATH`.
2. **Docker Desktop**: Pornit și configurat să ruleze containere de Linux.
3. **PlatformIO CLI / Core**: Integrat în VSCode sau instalat ca utilitar standalone (implicit instalat în directorul utilizatorului sub `C:\Users\<Nume_Utilizator>\.platformio`).
4. **Drivere USB pentru ESP32**: În funcție de modelul plăcii de dezvoltare ESP32, poate fi necesară instalarea manuală a driverelor de port COM virtual:
   * **Silicon Labs CP210x USB to UART Bridge**
   * **WCH CH340 / CH341**
   * Verifică recunoașterea portului în *Device Manager* sub secțiunea **Ports (COM & LPT)** (de exemplu: `COM3`).

---

## 🏗️ 2. Pregătirea Automată a Mediului Central (`setup.py`)
> [!WARNING]
> **NU rula `docker compose up` în mod direct pe un PC curat!**
> Deoarece Docker montează fișierele de certificate în containere, dacă acestea nu există pe disc, Docker le va crea ca *foldere goale*, corupând pornirea serviciilor. Este absolut necesară inițializarea prealabilă a certificatelor folosind scriptul central de setup.

În rădăcina proiectului, rulează scriptul de configurare automată:
```powershell
python setup.py
```

### Ce face automat `setup.py` pentru tine?
1. **Configurare `.env`**: Copiază automat fișierul `.env.EXAMPLE` în `.env` (dacă nu există deja).
2. **Curățare certificate invalide**: Detectează și șterge directoarele goale invalide generate accidental de Docker în `./certs/`.
3. **Conversie End-of-Line (LF)**: Convertește sfârșiturile de rând din format Windows (`CRLF`) în format Unix (`LF`) pentru toate scripturile bash/SQL (`.sh`, `.sql.template`) care vor rula în interiorul containerelor.
4. **Generare Certificate mTLS (PKI)**: Lansează asincron un container temporar de Alpine Linux care instalează OpenSSL și execută scriptul `certs/scripts/generate_certs.sh`. Acesta generează automat întreaga structură PKI:
   * Autoritatea de Certificare (`ca.crt`, `ca.key`)
   * Certificatele mTLS pentru Gateway, TSP, Bănci și Terminal (`pos-buc-001.crt`, `pos-buc-001.key`, etc.)
5. **Curățare Containere Orfane**: Oprește și curăță eventualele containere reziduale sau volume vechi afectate de structuri de tabele învechite (execută un `docker compose down -v` implicit).

---

## 🐳 3. Lansarea Mediilor Centrale (Docker Backend)
Odată ce certificatele și fișierele de mediu au fost generate cu succes de `setup.py`, poți porni serviciile centrale:

1. **Lansarea containerelor**:
   În rădăcina repozitorului, rulează comanda de build și pornire a containerelor în modul detașat:
   ```bash
   docker compose up --build -d
   ```
2. **Verificarea stării containerelor**:
   Asigură-te că toate cele 14 containere financiare (inclusiv Gateway, Card Network, TSP, Băncile Emitente, PostgreSQL și Redis) rulează corect:
   ```bash
   docker ps
   ```

---

## 🔒 4. Sincronizarea și Verificarea Certificatelor (PKI & mTLS)
Pentru ca terminalul ESP32 să poată comunica securizat prin mTLS cu Gateway-ul, configurațiile de rețea și criptografice trebuie să fie perfect aliniate.

### A. Compatibilitatea mbedTLS pe ESP32
Firmware-ul ESP32 folosește librăria `mbedTLS 2.x` care are câteva limitări specifice pe care le-am rezolvat la nivel de gateway:
1. **Configurarea TLS 1.2 în NGINX**: ESP32 nu suportă TLS 1.3. Fișierul `nginx/nginx.conf` trebuie să permită ambele protocoale:
   ```nginx
   ssl_protocols TLSv1.2 TLSv1.3;
   ```
2. **Adăugarea IP-ului ca DNS SAN**: ESP32 realizează verificarea numelui de gazdă (hostname validation) doar împotriva câmpurilor **DNS SAN** din certificatul serverului, ignorând câmpurile *IP SAN*. Certificatul `gateway.crt` al NGINX-ului trebuie generat incluzând IP-ul central (`192.168.101.11`) atât ca IP, cât și ca DNS:
   ```ini
   subjectAltName = @alt_names
   [alt_names]
   DNS.1 = 192.168.101.11
   IP.1 = 192.168.101.11
   ```

### B. Sincronizarea Perechii de Cheie a Băncii (RSA)
Pentru a cripta blocul de PIN pe tastatura ESP32 și a-l decripta corect la Banca Emitentă (BT), perechea de chei publică/privată a băncii trebuie să fie identică:
* Dacă cheile sunt regenerate, extrage întotdeauna cheia publică corectă direct din cheia privată existentă din `./certs` pentru a evita eroarea `PIN_DECRYPT_FAILED` (mismatch):
  ```bash
  openssl rsa -in certs/bank_bt_private.pem -pubout -out certs/bank_bt_public.pem
  ```

---

## 🔌 5. Provisionarea și Programarea ESP32 (PlatformIO)
Sistemul utilizează o **Politică Zero-Secrete în Cod** (Zero Secret Policy). Certificatele client mTLS și cheia publică a băncii nu sunt hardcodate în firmware-ul principal, ci sunt stocate în siguranță în partiția `NVS` (Non-Volatile Storage) a plăcii ESP32.

### Pasul I: Flashează schița de Provisioning NVS
Schița de provisioning pregătește placa pentru a primi certificatele prin portul Serial.
1. Deschide un terminal în folderul `ESP32_code/provisioning`.
2. Rulează comanda de upload utilizând executabilul PlatformIO (înlocuiește calea cu calea specifică pe noul PC dacă PlatformIO este instalat în altă parte):
   ```powershell
   C:\Users\zarne\.platformio\penv\Scripts\platformio.exe run --project-dir "ESP32_code\provisioning" --target upload
   ```
3. Odată finalizat upload-ul, placa se va reseta și va intra în starea `READY` (așteptând certificatele pe Serial în baud rate `115200`).

### Pasul II: Rulează Scriptul de Provisionare
Rulează scriptul Python din rădăcina repozitorului utilizând interpreterul PlatformIO (care include automat biblioteca `pyserial`).
> [!IMPORTANT]
> **Este extrem de important să folosești flag-ul `--wipe`!**
> Acest flag curăță memoria NVS complet, eliminând fragmentarea anterioară pentru a asigura spațiul fizic necesar pentru fișierele voluminoase de mTLS (cheia privată, certificatul de client și certificatul CA).
>
> De asemenea, setează variabila `$env:PYTHONIOENCODING="utf-8"` în PowerShell pentru a preveni erorile de decodare a caracterelor din consolă:

```powershell
$env:PYTHONIOENCODING="utf-8"
C:\Users\zarne\.platformio\penv\Scripts\python.exe scripts/provision_esp32.py --port COM3 --wipe
```
*Scriptul va șterge memoria NVS, va citi fișierele locale `certs/ca.crt`, `certs/pos-buc-001.crt`, `certs/pos-buc-001.key`, `certs/bank_bt_public.pem`, le va injecta prin serial în NVS și va confirma succesul cu mesajul `OK:DONE`.*

### Pasul III: Flashează Firmware-ul Principal
Acum că toate secretele se află în siguranță în memoria NVS a ESP32, poți compila și încărca codul final al terminalului de plăți.
1. Deschide terminalul în folderul principal `ESP32_code`.
2. Rulează upload-ul și pornește automat monitorul Serial pentru a vizualiza logurile debug în timp real:
   ```powershell
   C:\Users\zarne\.platformio\penv\Scripts\platformio.exe run --project-dir "ESP32_code" --target upload --target monitor
   ```

---

## 🚀 6. Rularea Testului Manual de Plată (Step-Up PIN Challenge)
Pentru a rula o tranzacție completă cap-la-cap și a valida fluxul interactiv de introducere PIN:

1. **Copiază scriptul de test manual în containerul Gateway**:
   ```bash
   docker cp tests/live_manual_stepup.py nfc-gateway:/tmp/live_manual_stepup.py
   ```
2. **Execută scriptul din interiorul containerului**:
   ```bash
   docker exec nfc-gateway python /tmp/live_manual_stepup.py
   ```
3. **Fluxul interactiv pe care îl vei urmări pas cu pas**:
   * **Inițiere**: Scriptul inițiază o tranzacție de `12.50 RON` pe ESP32. Ecranul LCD al plăcii va afișa suma de plată.
   * **Simulare NFC**: Telefonul simulează apropierea NFC și trimite criptograma. Scriptul calculează corect MAC-ul pe 2 pași (derivând mai întâi cheia de sesiune din master key utilizând ATC-ul în secunde, prevenind astfel overflow-ul pe 32 de biți).
   * **Trimitere Autorizare**: ESP32 realizează handshake-ul mTLS cu NGINX și trimite payload-ul de autorizare la Gateway.
   * **Evaluare de Risc (Step-Up)**: Gateway-ul evaluează riscul tranzacției la valoarea `55` (risc mediu spre mare) și returnează un cod `401 CHALLENGE_REQUIRED`.
   * **Introducere PIN local (Multi-Attempt)**:
     * ESP32 realizează fallback pe DPAN-ul local (`g_tx.dpan`) în cazul în care câmpul `original_dpan` lipsește din payload-ul de răspuns de la gateway, și comută ecranul în modul galben **`INTRODU PIN`**.
     * **Testul de reziliență al PIN-ului**:
       * Introdu un PIN greșit la tastatură (de exemplu `9999`) și apasă tasta `#`.
       * Ecranul va afișa timp de 2 secunde mesajul roșu **`PIN incorect / Incercarea 1/3`** și va permite o nouă reîncercare fără a anula tranzacția.
       * Introdu din nou un PIN greșit pentru a vedea actualizarea contorului la **`Incercarea 2/3`**.
       * La a 3-a încercare, introdu PIN-ul corect **`1234`** și apasă tasta `#`.
     * **Decriptare & Aprobare**:
       * Blocul de PIN este criptat asimetric folosind RSA-OAEP direct pe microcontroler cu cheia publică a băncii BT citită din NVS.
       * Blocul criptat este decriptat cu succes de motorul băncii BT cu cheia sa privată.
       * Terminalul afișează verde **`APROBAT`** și finalizează curat fluxul.

---

## 🛠️ 7. Capabilități de Reziliență Rețea Implementate
În codul firmware-ului au fost integrate comportamente avansate de rețea specifice mediilor financiare de înaltă disponibilitate:
* **Suport complet pentru codul HTTP 409 (Concurrent Requests)**: Firmware-ul tratează acum statusul `409` drept o eroare tranzitorie și reîncearcă tranzacția în loc să eșueze imediat, prevenind eșecurile provocate de pachetele duplicat sau coliziunile de rețea.
* **Auto-Reglare Backoff (`retry_after_ms`)**: La primirea erorilor de supraîncărcare sau conflict (`503`, `429`, `409`), ESP32 parsează corpul JSON. Dacă gateway-ul indică un timp specificat de reîncercare (de exemplu `retry_after_ms: 2000`), microcontrolerul își va ajusta fereastra de așteptare din algoritmul backoff la `max(wait, server_retry_after_ms)`, prevenind congestionarea serverului central.
* **Auto-Corectare ATC**: Timestamp-urile și contorul ATC folosesc valori convertite în secunde, eliminând riscul de overflow al tipului de date pe 32 de biți (int) la nivelul firmware-ului ESP32.

