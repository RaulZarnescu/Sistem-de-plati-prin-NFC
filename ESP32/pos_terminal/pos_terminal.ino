// ============================================================
// pos_terminal.ino — Firmware POS NFC pentru ESP32
//
// Hardware necesar:
//   - Placă ESP32 (ex. ESP32 DevKit V1)
//   - Modul NFC PN532 (conectat I2C: SDA→GPIO21, SCL→GPIO22)
//
// Librării Arduino necesare (instalează din Library Manager):
//   - "Adafruit PN532" de Adafruit (>= 1.3.4)
//   - "ArduinoJson" de Benoit Blanchon (>= 7.0.0)
//
// Flux de plată:
//   1. ESP32 detectează telefonul (HCE activ)
//   2. Trimite SELECT AID → telefonul confirmă că e aplicația noastră
//   3. Trimite APDU plată cu suma, moneda, nonce, timestamp
//   4. Primește răspuns: DPAN|HMAC|ATC
//   5. Trimite POST la Gateway cu JSON complet
//   6. Afișează rezultatul: APPROVED / DECLINED / CHALLENGE_REQUIRED
// ============================================================

#include <Wire.h>
#include <Adafruit_PN532.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <Preferences.h>
#include "config.h"

// --- Certificate NVS ----------------------------------------
// Populate din NVS la boot via loadCertificatesFromNVS()
String g_ca_cert;
String g_client_cert;
String g_client_key;
String g_bank_pub;
bool   g_certs_loaded = false;

bool loadCertificatesFromNVS() {
    Preferences prefs;
    prefs.begin("certs", true);  // true = read-only

    g_ca_cert     = prefs.getString("ca_cert",     "");
    g_client_cert = prefs.getString("client_cert", "");
    g_client_key  = prefs.getString("client_key",  "");
    g_bank_pub    = prefs.getString("bank_pub",    "");

    prefs.end();

    if (g_ca_cert.isEmpty() || g_client_cert.isEmpty() ||
        g_client_key.isEmpty() || g_bank_pub.isEmpty()) {
        Serial.println("EROARE: Certificate lipsa in NVS!");
        Serial.println("   Flasheaza mai intai provisioning.ino");
        return false;
    }

    Serial.println("[Certs] Certificate incarcate din NVS.");
    return true;
}

// Apelat după /api/pki/renew — scrie certificatul nou în NVS
// și actualizează variabilele globale fără restart.
// LIMITARE PoC: cheia privată NU se actualizează via /pki/renew.
// În producție, ESP32 ar genera o cheie nouă local și ar trimite CSR-ul.
void updateCertificateInNVS(const String& new_cert,
                             const String& new_bank_pub) {
    Preferences prefs;
    prefs.begin("certs", false);  // false = read/write

    prefs.putString("client_cert", new_cert);

    if (!new_bank_pub.isEmpty()) {
        prefs.putString("bank_pub", new_bank_pub);
    }

    prefs.end();

    g_client_cert = new_cert;
    if (!new_bank_pub.isEmpty()) {
        g_bank_pub = new_bank_pub;
    }

    Serial.println("[Certs] Certificat nou salvat in NVS.");
    Serial.println("        Activ la urmatoarea conexiune mTLS.");
}

// --- NFC ----------------------------------------------------
Adafruit_PN532 nfc(PN532_IRQ_PIN, PN532_RESET_PIN);

// AID-ul aplicației Android — TREBUIE să fie identic cu
// android:name din apduservice.xml (F1000000000001 = 7 bytes)
const uint8_t AID[]    = { 0xF1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
const uint8_t AID_LEN  = sizeof(AID);

// SELECT AID APDU: CLA(00) INS(A4) P1(04) P2(00) Lc(07) [AID]
// Construit o singură dată în setup() pentru eficiență
uint8_t selectAidApdu[5 + sizeof(AID)];


// ============================================================
// UTILITARE
// ============================================================

// Generează un nonce aleator de 8 caractere hex (ex: "A7F90B1C")
String generateNonce() {
    char buf[9];
    snprintf(buf, sizeof(buf), "%08lX", (unsigned long)esp_random());
    return String(buf);
}

// Generează o cheie de idempotență unică per tranzacție
String generateIdempotencyKey() {
    char buf[32];
    snprintf(buf, sizeof(buf), "POS-%08lX%08lX",
             (unsigned long)esp_random(),
             (unsigned long)esp_random());
    return String(buf);
}

// Returnează timestamp-ul UTC curent în format ISO 8601
// Necesită sincronizare NTP (configTime apelat în setup)
String getTimestampISO8601() {
    time_t now;
    time(&now);
    struct tm* utc = gmtime(&now);
    char buf[25];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", utc);
    return String(buf);
}

// Trimite un APDU și returnează răspunsul (fără SW1SW2)
// Returnează "" la eroare sau dacă SW != 9000
String exchangeApdu(const uint8_t* apdu, uint8_t apduLen) {
    uint8_t response[256];
    uint8_t responseLen = sizeof(response);

    bool ok = nfc.inDataExchange(
        const_cast<uint8_t*>(apdu), apduLen,
        response, &responseLen
    );

    if (!ok || responseLen < 2) {
        Serial.printf("[NFC] inDataExchange eșuat (ok=%d, len=%d)\n", ok, responseLen);
        return "";
    }

    uint8_t sw1 = response[responseLen - 2];
    uint8_t sw2 = response[responseLen - 1];

    if (sw1 != 0x90 || sw2 != 0x00) {
        Serial.printf("[NFC] SW=%02X%02X (eroare)\n", sw1, sw2);
        return "";
    }

    // Payload = tot răspunsul mai puțin ultimii 2 bytes (SW1SW2)
    if (responseLen == 2) return "";  // Doar SW, fără date
    response[responseLen - 2] = '\0';
    return String((char*)response);
}


// ============================================================
// PAȘI PROTOCOL NFC
// ============================================================

// Pasul 1: SELECT AID
// Verifică că telefonul rulează aplicația noastră de plată.
// Returnează true dacă AID-ul e recunoscut (SW=9000).
bool doSelectAid() {
    String resp = exchangeApdu(selectAidApdu, sizeof(selectAidApdu));
    // SELECT AID returnează SW=9000 cu payload gol — exchangeApdu
    // returnează "" pentru payload gol dar SW valid, ceea ce e corect.
    // Dacă exchangeApdu returnează "" poate fi și eroare, verificăm
    // reapelând cu logging suplimentar:
    uint8_t response[64];
    uint8_t responseLen = sizeof(response);
    bool ok = nfc.inDataExchange(
        selectAidApdu, sizeof(selectAidApdu),
        response, &responseLen
    );
    if (!ok || responseLen < 2) return false;
    return (response[responseLen - 2] == 0x90 &&
            response[responseLen - 1] == 0x00);
}

// Pasul 2: PAYMENT APDU
// Trimite suma, moneda, nonce și timestamp către aplicația Android.
// Android calculează HMAC și răspunde cu "DPAN|HMAC|ATC".
// Format APDU: CLA(00) INS(A0) P1(00) P2(00) Lc(N) Data(N bytes UTF-8)
String doPaymentApdu(int amountCents, const String& currency,
                     const String& nonce, const String& timestamp) {
    // Construim câmpul Data
    String data = String(amountCents) + "|" + currency + "|"
                + nonce + "|" + timestamp;
    uint8_t dataLen = (uint8_t)data.length();

    // Construim APDU complet
    uint8_t apdu[5 + dataLen];
    apdu[0] = 0x00;      // CLA
    apdu[1] = 0xA0;      // INS — comandă proprie de plată
    apdu[2] = 0x00;      // P1
    apdu[3] = 0x00;      // P2
    apdu[4] = dataLen;   // Lc
    memcpy(apdu + 5, data.c_str(), dataLen);

    Serial.printf("[NFC] PAYMENT APDU data: %s\n", data.c_str());

    uint8_t response[256];
    uint8_t responseLen = sizeof(response);
    bool ok = nfc.inDataExchange(apdu, sizeof(apdu), response, &responseLen);

    if (!ok || responseLen < 2) {
        Serial.println("[NFC] PAYMENT APDU: fără răspuns");
        return "";
    }

    uint8_t sw1 = response[responseLen - 2];
    uint8_t sw2 = response[responseLen - 1];

    if (sw1 != 0x90 || sw2 != 0x00) {
        // SW=6A82 → niciun card activ în aplicație (STATUS_NO_CARD)
        // SW=6F00 → eroare generală (STATUS_FAILED)
        Serial.printf("[NFC] PAYMENT SW=%02X%02X\n", sw1, sw2);
        return "";
    }

    // Payload: "DPAN|HMAC|ATC" (fără SW1SW2)
    response[responseLen - 2] = '\0';
    return String((char*)response);
}


// ============================================================
// PASUL 3: AUTORIZARE LA GATEWAY
// ============================================================

// Trimite cererea de autorizare la backend și returnează status-ul:
// "APPROVED", "DECLINED", "CHALLENGE_REQUIRED" sau "ERROR:COD"
String authorizeAtGateway(const String& dpan, const String& mac, int atc,
                           int amountCents, const String& currency,
                           const String& nonce, const String& timestamp,
                           const String& idempotencyKey) {
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("[HTTP] WiFi deconectat!");
        return "ERROR:NO_WIFI";
    }

    HTTPClient http;
    String url = String(GATEWAY_URL) + "/api/v1/payments/authorize";
    http.begin(url);
    http.addHeader("Content-Type", "application/json");
    http.addHeader("X-Idempotency-Key", idempotencyKey);
    http.addHeader("X-Terminal-Id", TERMINAL_ID);
    http.setTimeout(5000);  // 5s timeout

    // Construim JSON-ul cererii
    JsonDocument doc;
    doc["dpan"]                             = dpan;
    doc["transaction"]["amount"]            = amountCents;
    doc["transaction"]["currency"]          = currency;
    doc["transaction"]["pos_nonce"]         = nonce;
    doc["transaction"]["terminal_timestamp"]= timestamp;
    doc["cryptogram"]["mac"]                = mac;
    doc["cryptogram"]["atc"]                = atc;

    String body;
    serializeJson(doc, body);

    Serial.printf("[HTTP] POST %s\n", url.c_str());
    int httpCode = http.POST(body);

    if (httpCode <= 0) {
        Serial.printf("[HTTP] Eroare conexiune: %s\n",
                      http.errorToString(httpCode).c_str());
        http.end();
        return "ERROR:CONNECTION";
    }

    String responseBody = http.getString();
    http.end();

    Serial.printf("[HTTP] %d: %s\n", httpCode, responseBody.c_str());

    JsonDocument resp;
    DeserializationError err = deserializeJson(resp, responseBody);
    if (err) return "ERROR:JSON_PARSE";

    if (httpCode == 200) {
        // status poate fi "APPROVED" sau "DECLINED" — ambele HTTP 200
        return resp["status"].as<String>();
    }
    if (httpCode == 401) {
        // Step-Up Authentication cerut de fraud engine
        return "CHALLENGE_REQUIRED";
    }

    // Orice altceva (400, 429, 503 etc.) — returnăm codul de eroare
    String errorCode = resp["detail"]["error_code"] | "UNKNOWN";
    return "ERROR:" + errorCode;
}


// ============================================================
// AFIȘARE REZULTAT
// ============================================================

void displayResult(const String& status) {
    Serial.println("\n╔══════════════════════════╗");
    if (status == "APPROVED") {
        Serial.println("║     ✅  APROBAT           ║");
    } else if (status == "DECLINED") {
        Serial.println("║     ❌  REFUZAT           ║");
    } else if (status == "CHALLENGE_REQUIRED") {
        Serial.println("║  🔐  AUTH SUPLIMENTAR    ║");
    } else {
        Serial.printf( "║  ⚠️  %s\n", status.c_str());
    }
    Serial.println("╚══════════════════════════╝\n");
}


// ============================================================
// SETUP
// ============================================================

void setup() {
    Serial.begin(115200);
    delay(500);
    Serial.println("\n\n=== NFC POS Terminal — Boot ===");

    // 1. Încarcă certificatele din NVS — primul pas, înainte de WiFi sau NFC
    g_certs_loaded = loadCertificatesFromNVS();
    if (!g_certs_loaded) {
        Serial.println("EROARE SECURITATE: Certificate lipsa in NVS! (Cod: 0x02)");
        Serial.println("Flasheaza provisioning.ino, apoi reflasheaza codul principal.");
        while (true) delay(1000);  // HALT
    }

    // --- Inițializare NFC ---
    Wire.begin();
    nfc.begin();

    uint32_t versiondata = nfc.getFirmwareVersion();
    if (!versiondata) {
        Serial.println("EROARE FATALĂ: Modulul PN532 nu a fost găsit!");
        Serial.println("Verifică conexiunile I2C (SDA→21, SCL→22).");
        while (true) delay(1000);
    }
    Serial.printf("[NFC] PN532 detectat. Chip: 0x%02X | Firmware: %d.%d\n",
        (versiondata >> 24) & 0xFF,
        (versiondata >> 16) & 0xFF,
        (versiondata >>  8) & 0xFF);

    nfc.SAMConfig();  // Configurează Security Access Module

    // Construim SELECT AID APDU o singură dată
    selectAidApdu[0] = 0x00;   // CLA
    selectAidApdu[1] = 0xA4;   // INS: SELECT FILE
    selectAidApdu[2] = 0x04;   // P1:  Select by name (AID)
    selectAidApdu[3] = 0x00;   // P2
    selectAidApdu[4] = AID_LEN;// Lc
    memcpy(selectAidApdu + 5, AID, AID_LEN);

    // --- Conectare WiFi ---
    Serial.printf("[WiFi] Conectare la '%s'...\n", WIFI_SSID);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

    int retries = 0;
    while (WiFi.status() != WL_CONNECTED && retries < 30) {
        delay(500);
        Serial.print(".");
        retries++;
    }
    Serial.println();

    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("[WiFi] EROARE: Nu s-a putut conecta la WiFi!");
        Serial.println("Continuăm — plata NFC va eșua la pasul HTTP.");
    } else {
        Serial.printf("[WiFi] Conectat. IP: %s\n",
                      WiFi.localIP().toString().c_str());
    }

    // --- Sincronizare NTP ---
    // Necesar pentru timestamp-uri ISO 8601 valide în HMAC
    configTime(0, 0, "pool.ntp.org", "time.nist.gov");
    Serial.print("[NTP] Sincronizare timp UTC");
    time_t now = 0;
    int ntpRetries = 0;
    while (now < 1000000000 && ntpRetries < 20) {
        time(&now);
        delay(500);
        Serial.print(".");
        ntpRetries++;
    }
    Serial.println();
    if (now > 1000000000) {
        Serial.printf("[NTP] OK — %s", ctime(&now));
    } else {
        Serial.println("[NTP] AVERTISMENT: Timp nesincronizat. Timestamp invalid.");
    }

    Serial.println("\n[POS] Gata. Asteapta telefon NFC...\n");
}


// ============================================================
// LOOP PRINCIPAL
// ============================================================

void loop() {
    uint8_t uid[7];
    uint8_t uidLength;

    // Așteptăm un card/telefon ISO14443A (timeout 500ms pentru polling rapid)
    bool cardDetected = nfc.readPassiveTargetID(
        PN532_MIFARE_ISO14443A, uid, &uidLength, 500
    );
    if (!cardDetected) return;

    Serial.println("--- Telefon NFC detectat ---");

    // ── Pasul 1: SELECT AID ──────────────────────────────────
    if (!doSelectAid()) {
        Serial.println("[NFC] SELECT AID eșuat — aplicația de plată nu e activă pe telefon.");
        delay(1500);
        return;
    }
    Serial.println("[NFC] SELECT AID: OK");

    // ── Pasul 2: PAYMENT APDU ────────────────────────────────
    String nonce     = generateNonce();
    String timestamp = getTimestampISO8601();
    int    amount    = PAYMENT_AMOUNT_CENTS;
    String currency  = PAYMENT_CURRENCY;

    Serial.printf("[POS] Suma: %d.%02d %s | Nonce: %s | Timp: %s\n",
                  amount / 100, amount % 100,
                  currency.c_str(), nonce.c_str(), timestamp.c_str());

    String hceResponse = doPaymentApdu(amount, currency, nonce, timestamp);
    if (hceResponse.isEmpty()) {
        Serial.println("[NFC] Răspuns HCE invalid sau gol.");
        delay(1500);
        return;
    }
    Serial.printf("[NFC] Răspuns HCE: %s\n", hceResponse.c_str());

    // Parsăm "DPAN|HMAC|ATC"
    int sep1 = hceResponse.indexOf('|');
    int sep2 = hceResponse.lastIndexOf('|');
    if (sep1 < 0 || sep2 <= sep1) {
        Serial.println("[NFC] Format răspuns invalid — așteptat DPAN|HMAC|ATC");
        delay(1500);
        return;
    }

    String dpan = hceResponse.substring(0, sep1);
    String mac  = hceResponse.substring(sep1 + 1, sep2);
    int    atc  = hceResponse.substring(sep2 + 1).toInt();

    Serial.printf("[NFC] DPAN: ...%s | ATC: %d\n",
                  dpan.substring(dpan.length() - 4).c_str(), atc);

    // ── Pasul 3: Autorizare la Gateway ───────────────────────
    String idempotencyKey = generateIdempotencyKey();
    String result = authorizeAtGateway(
        dpan, mac, atc,
        amount, currency, nonce, timestamp,
        idempotencyKey
    );

    // ── Pasul 4: Afișare rezultat ────────────────────────────
    displayResult(result);

    // Cooldown — evită procesarea dublă a aceluiași tap
    delay(3000);
    Serial.println("[POS] Asteapta telefon NFC...\n");
}
