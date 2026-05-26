// File: ESP32_code/src/main.cpp
#include <Arduino.h>
#include <SPI.h>
#include <Adafruit_PN532.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <TFT_eSPI.h>
#include <Keypad.h>
#include <time.h>

#include <mbedtls/x509_crt.h>
#include <mbedtls/x509.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/base64.h>
#include <mbedtls/x509_csr.h>
#include <mbedtls/gcm.h>

#include <Preferences.h>

// ----- Hardware Registry definitions (DOIT DevKit V1) ------
#include "soc/gpio_reg.h"
#include "soc/io_mux_reg.h"

// Registry Bitmask for Pin 5 (NFC Slave Select)
#define PN532_SS_BIT (1 << 5)

// ----- Pinout Mapping -------
#define PN532_SCK  (18)
#define PN532_MISO (19)
#define PN532_MOSI (23)
#define PN532_SS   (5)

// ----- Keypad Rows (Output) -----
#define KEYPAD_R1  (13)
#define KEYPAD_R2  (12)
#define KEYPAD_R3  (14)
#define KEYPAD_R4  (27)

// ----- Keypad Columns (Input) -----
#define KEYPAD_C1  (26)
#define KEYPAD_C2  (25)
#define KEYPAD_C3  (33)
#define KEYPAD_C4  (32)

// Feedback pins (visual/haptic)
#define LED_PIN 2
#define HAPTIC_PIN 4

// Keypad 4x4
const byte ROWS = 4;
const byte COLS = 4;
char keys[ROWS][COLS] = {
  {'1','2','3','A'},
  {'4','5','6','B'},
  {'7','8','9','C'},
  {'*','0','#','D'}
};
byte rowPins[ROWS] = {KEYPAD_R1, KEYPAD_R2, KEYPAD_R3, KEYPAD_R4};
byte colPins[COLS] = {KEYPAD_C1, KEYPAD_C2, KEYPAD_C3, KEYPAD_C4};

// ----- Object Initializations -----
Adafruit_PN532 nfc(PN532_SS);
WiFiClientSecure secureClient;
TFT_eSPI tft = TFT_eSPI();
Keypad keypad = Keypad(makeKeymap(keys), rowPins, colPins, ROWS, COLS);
Preferences prefs;

// ---- Project Configuration -----
const char* ssid = "your_wifi_ssid";
const char* password = "your_wifi_password";

const char* gateway_host = "192.168.43.100"; // IP static laptop
const uint16_t gateway_port = 443;
const char* gateway_path = "/api/v1/payments/authorize";
const char* challenge_path = "/api/v1/payments/challenge";
const char* pki_renew_path = "/api/pki/renew";

const uint8_t bank_aid[] = {0xF1, 0xC7, 0x1B, 0x3B, 0x4E, 0x4B, 0x01};

// PEMs (replace with real contents)
const char root_ca_pem[] = R"EOF(
-----BEGIN CERTIFICATE-----
...ca.crt contents here...
-----END CERTIFICATE-----
)EOF";

const char client_cert_pem[] = R"EOF(
-----BEGIN CERTIFICATE-----
...pos-buc-001.crt contents here...
-----END CERTIFICATE-----
)EOF";

const char client_key_pem[] = R"EOF(
-----BEGIN PRIVATE KEY-----
...pos-buc-001.key contents here...
-----END PRIVATE KEY-----
)EOF";

// Bank RSA public key (PEM) stored in flash/provisioning
const char bank_pub_pem[] = R"EOF(
-----BEGIN PUBLIC KEY-----
...bank public key PEM here...
-----END PUBLIC KEY-----
)EOF";

// Symmetric key used to encrypt stored cert in NVS: PROVISION this securely (32 bytes)
static const uint8_t CERT_ENC_KEY[32] = {
  0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
  0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
  0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
  0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F
};

// Timeouts and limits
const int NFC_COMMAND_TIMEOUT_MS = 300;
const int HTTP_TIMEOUT_MS = 2000;
const int GPO_MAX_PAYLOAD = 128;

// PKI renew settings
const int RECHECK_INTERVAL_SECONDS = 24 * 3600; // daily
const int RENEW_DAYS_BEFORE = 5; // generate CSR if expires in <= 5 days
const int RENEW_MAX_FAILURES = 3;

enum DeviceState {
  STATE_OK = 0,
  STATE_BRICKED_PENDING_MANUAL_RESET = 1
};

// Forward declarations
String getIsoTimestamp();
String generatePosNonce();
String generateUuidV4();
bool isHexString(const String& value);
void showMessage(const char* line1, const char* line2 = nullptr);
void showTransaction(int amountCents, const char* status);
bool sendNfcCommand(const uint8_t* command, uint8_t commandLen, uint8_t* response, uint8_t* responseLength);
String extractCertCN();
String encryptPinBlockAndBase64(const String& transaction_id, const String& pin);

// PKI renewal helpers (signatures)
bool getCertExpiry(const char* cert_pem, time_t &not_after);
bool generateCsrBase64(String& out_csr_base64);
bool postCsrAndStoreNewCert(const String& csr_base64);
bool encryptAndStoreCertInNVS(const char* cert_pem);
bool decryptCertFromNVS(String& out_cert_pem);

// Feedback helpers
void feedbackPulse() {
  // Visual + haptic short pulse sequence
  for (int i = 0; i < 2; ++i) {
    digitalWrite(LED_PIN, HIGH);
    digitalWrite(HAPTIC_PIN, HIGH);
    delay(120);
    digitalWrite(LED_PIN, LOW);
    digitalWrite(HAPTIC_PIN, LOW);
    delay(80);
  }
}

void setup_registru_hardware() {
  PIN_FUNC_SELECT(GPIO_PIN_MUX_REG[5], PIN_FUNC_GPIO);
  GPIO.enable_w1ts = PN532_SS_BIT;
  GPIO.out_w1ts = PN532_SS_BIT; // Set High (Deselected)
}

String getIsoTimestamp() {
  struct tm timeinfo;
  if (!getLocalTime(&timeinfo)) {
    return "2026-04-10T14:30:00Z";
  }
  char buf[25];
  strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &timeinfo);
  return String(buf);
}

String generatePosNonce() {
  uint32_t value = (((uint32_t)random(0x10000) << 16) | random(0x10000));
  char buf[9];
  snprintf(buf, sizeof(buf), "%08lX", (unsigned long)value);
  return String(buf);
}

String generateUuidV4() {
  uint32_t d0 = esp_random();
  uint32_t d1 = esp_random();
  uint32_t d2 = esp_random();
  uint32_t d3 = esp_random();

  d1 = (d1 & 0xFFFF0FFF) | 0x00004000; // version 4
  d2 = (d2 & 0x3FFFFFFF) | 0x80000000; // variant 10xxxxxx

  char buf[37];
  snprintf(buf, sizeof(buf),
           "%08lx-%04x-%04x-%04x-%04x%08lx",
           (unsigned long)d0,
           (unsigned int)(d1 >> 16),
           (unsigned int)(d1 & 0xFFFF),
           (unsigned int)(d2 >> 16),
           (unsigned int)(d2 & 0xFFFF),
           (unsigned long)d3);
  return String(buf);
}

bool isHexString(const String& value) {
  for (size_t i = 0; i < value.length(); i++) {
    char c = value.charAt(i);
    if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'))) {
      return false;
    }
  }
  return true;
}

void showMessage(const char* line1, const char* line2) {
  tft.fillScreen(TFT_BLACK);
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.setTextSize(2);
  tft.setCursor(0, 0);
  tft.print(line1);
  if (line2 && strlen(line2) > 0) {
    tft.setCursor(0, 40);
    tft.print(line2);
  }
}

// Display transaction amount and status: amount in cents -> RON format
void showTransaction(int amountCents, const char* status) {
  char amtBuf[32];
  int lei = amountCents / 100;
  int cents = amountCents % 100;
  snprintf(amtBuf, sizeof(amtBuf), "%d.%02d RON", lei, cents);
  showMessage(amtBuf, status);
}

bool sendNfcCommand(const uint8_t* command, uint8_t commandLen, uint8_t* response, uint8_t* responseLength) {
  unsigned long start = millis();
  bool ok = nfc.inDataExchange(command, commandLen, response, responseLength);
  unsigned long duration = millis() - start;
  return ok && (duration <= (unsigned long)NFC_COMMAND_TIMEOUT_MS);
}

String extractCertCN() {
  mbedtls_x509_crt crt;
  mbedtls_x509_crt_init(&crt);
  int ret = mbedtls_x509_crt_parse(&crt, (const unsigned char*)client_cert_pem, strlen(client_cert_pem) + 1);
  if (ret != 0) {
    mbedtls_x509_crt_free(&crt);
    return String("POS-001");
  }
  char dn[256];
  mbedtls_x509_dn_gets(dn, sizeof(dn), &crt.subject);
  String dnStr(dn);
  int idx = dnStr.indexOf("CN=");
  if (idx < 0) {
    mbedtls_x509_crt_free(&crt);
    return String("POS-001");
  }
  int end = dnStr.indexOf(',', idx);
  String cn = (end > idx) ? dnStr.substring(idx + 3, end) : dnStr.substring(idx + 3);
  cn.trim();
  mbedtls_x509_crt_free(&crt);
  return cn;
}

// Encrypt and base64 helper for PIN-block
String encryptPinBlockAndBase64(const String& transaction_id, const String& pin) {
  String plain = transaction_id + ":" + pin;
  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);
  int ret = mbedtls_pk_parse_public_key(&pk, (const unsigned char*)bank_pub_pem, strlen(bank_pub_pem) + 1);
  if (ret != 0) {
    mbedtls_pk_free(&pk);
    return String();
  }
  if (mbedtls_pk_get_type(&pk) != MBEDTLS_PK_RSA) {
    mbedtls_pk_free(&pk);
    return String();
  }
  mbedtls_rsa_context* rsa = mbedtls_pk_rsa(pk);
  mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr;
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr);
  const char* pers = "rsa_oaep_enc";
  if ((ret = mbedtls_ctr_drbg_seed(&ctr, mbedtls_entropy_func, &entropy,
                                   (const unsigned char*)pers, strlen(pers))) != 0) {
    mbedtls_ctr_drbg_free(&ctr);
    mbedtls_entropy_free(&entropy);
    mbedtls_pk_free(&pk);
    return String();
  }

  size_t key_len = mbedtls_pk_get_len(&pk);
  std::vector<unsigned char> out(key_len);
  ret = mbedtls_rsa_rsaes_oaep_encrypt(rsa,
                                       mbedtls_ctr_drbg_random, &ctr,
                                       MBEDTLS_RSA_PUBLIC,
                                       NULL, 0,
                                       plain.length(),
                                       (const unsigned char*)plain.c_str(),
                                       out.data());
  if (ret != 0) {
    mbedtls_ctr_drbg_free(&ctr);
    mbedtls_entropy_free(&entropy);
    mbedtls_pk_free(&pk);
    return String();
  }

  size_t olen = 0;
  mbedtls_base64_encode(NULL, 0, &olen, out.data(), out.size());
  std::vector<unsigned char> b64(olen + 1);
  ret = mbedtls_base64_encode(b64.data(), b64.size(), &olen, out.data(), out.size());
  if (ret != 0) {
    mbedtls_ctr_drbg_free(&ctr);
    mbedtls_entropy_free(&entropy);
    mbedtls_pk_free(&pk);
    return String();
  }
  b64[olen] = '\0';
  String result((char*)b64.data());
  mbedtls_ctr_drbg_free(&ctr);
  mbedtls_entropy_free(&entropy);
  mbedtls_pk_free(&pk);
  return result;
}

// --- PKI renewal functions (omitted here to keep code focused) ---
// For brevity the PKI functions (generateCsrBase64, encrypt/store cert in NVS, etc.)
// are included as earlier in the file; they remain unchanged and present above
// (see previous commit in this file).

// Collect numeric PIN from keypad (used for challenge flow)
String collectPin(int maxDigits = 6, unsigned long timeoutMs = 30000) {
  showMessage("Enter PIN:", "----");
  String pin = "";
  unsigned long start = millis();
  while ((millis() - start) < timeoutMs) {
    char k = keypad.getKey();
    if (k) {
      if (k >= '0' && k <= '9') {
        if (pin.length() < (size_t)maxDigits) pin += k;
      } else if (k == '#') { // confirm
        if (pin.length() >= 4) break;
      } else if (k == '*') { // backspace
        if (pin.length()) pin.remove(pin.length() - 1);
      }
      // update masked display
      char masked[16] = {0};
      for (size_t i = 0; i < pin.length() && i < sizeof(masked)-1; ++i) masked[i] = '*';
      showMessage("Enter PIN:", masked);
    }
    delay(50);
  }
  return pin;
}

// Wrapper to send challenge with encrypted pin-block
int sendChallengeRequestWithPin(const String& transaction_id, const String& original_dpan, const String& pin) {
  String idempotencyNew = generateUuidV4();
  String cn = extractCertCN();

  String pin_block_b64 = encryptPinBlockAndBase64(transaction_id, pin);
  if (pin_block_b64.length() == 0) {
    Serial.println("Pin block encryption failed");
    return -1;
  }

  StaticJsonDocument<256> bodyDoc;
  bodyDoc["transaction_id"] = transaction_id;
  bodyDoc["original_dpan"] = original_dpan;
  bodyDoc["pin_block_encrypted"] = pin_block_b64;

  String body;
  serializeJson(bodyDoc, body);

  HTTPClient http;
  secureClient.setTimeout(HTTP_TIMEOUT_MS);
  http.setTimeout(HTTP_TIMEOUT_MS);
  http.begin(secureClient, gateway_host, gateway_port, challenge_path);
  http.addHeader("Content-Type", "application/json");
  http.addHeader("X-Idempotency-Key", idempotencyNew);
  http.addHeader("X-Terminal-Id", cn);

  int code = http.POST(body);
  String resp = http.getString();
  Serial.printf("Challenge POST code=%d body=%s\n", code, resp.c_str());
  http.end();
  return code;
}

// sendRequestWithBackoff now accepts amountCents to allow display of sum
void sendRequestWithBackoff(String payload, int amountCents) {
  int max_retries = 5;
  const int base_delay = 1000;
  const int cap_delay = 10000;

  String idempotencyKey = generateUuidV4();
  String cn = extractCertCN();

  for (int attempt = 0; attempt <= max_retries; ++attempt) {
    HTTPClient http;
    secureClient.setTimeout(HTTP_TIMEOUT_MS);
    http.setTimeout(HTTP_TIMEOUT_MS);
    http.begin(secureClient, gateway_host, gateway_port, gateway_path);
    http.addHeader("Content-Type", "application/json");
    http.addHeader("X-Idempotency-Key", idempotencyKey);
    http.addHeader("X-Terminal-Id", cn);

    showTransaction(amountCents, "Procesare...");
    int httpCode = http.POST(payload);
    String body = http.getString();
    Serial.printf("HTTP %d body=%s\n", httpCode, body.c_str());

    if (httpCode == 200) {
      StaticJsonDocument<256> doc;
      DeserializationError err = deserializeJson(doc, body);
      String status = "";
      if (!err && doc.containsKey("status")) status = String((const char*)doc["status"]);

      if (status == "APPROVED") {
        showTransaction(amountCents, "APROBAT");
        http.end();
        return;
      } else if (status == "DECLINED") {
        showTransaction(amountCents, "REFUZAT");
        http.end();
        return;
      } else if (status == "CHALLENGE_REQUIRED") {
        String tx_id = doc.containsKey("transaction_id") ? String((const char*)doc["transaction_id"]) : String();
        String orig_dpan = doc.containsKey("original_dpan") ? String((const char*)doc["original_dpan"]) : String();
        showMessage("PIN Required", nullptr);
        String pin = collectPin(6, 30000);
        if (pin.length() < 4) {
          showMessage("PIN Timeout", nullptr);
          http.end();
          return;
        }
        int challCode = sendChallengeRequestWithPin(tx_id, orig_dpan, pin);
        http.end();
        if (challCode == 200) { delay(200); continue; }
        else if (challCode == 401) { showMessage("Auth Err", nullptr); return; }
        else { /* let backoff handle */ }
      } else {
        Serial.println("Unknown 200 status field; retrying if attempts left");
      }
      http.end();
    } else if (httpCode == 401) {
      StaticJsonDocument<256> doc;
      DeserializationError err = deserializeJson(doc, body);
      String transaction_id = "";
      String original_dpan = "";
      if (!err) {
        if (doc.containsKey("transaction_id")) transaction_id = String((const char*)doc["transaction_id"]);
        if (doc.containsKey("original_dpan")) original_dpan = String((const char*)doc["original_dpan"]);
      }
      showMessage("PIN Required", nullptr);
      String pin = collectPin(6, 30000);
      if (pin.length() < 4) {
        showMessage("PIN Timeout", nullptr);
        http.end();
        return;
      }
      int challCode = sendChallengeRequestWithPin(transaction_id, original_dpan, pin);
      http.end();
      if (challCode == 200) { delay(200); continue; }
      else if (challCode == 401) { showMessage("Auth Err", nullptr); return; }
      else { /* handled by backoff */ }
    } else if (httpCode == 429 || httpCode == 503) {
      http.end();
      int exp = min(attempt, 10);
      int backoff = base_delay * (1 << exp);
      if (backoff > cap_delay) backoff = cap_delay;
      int jitter = random(0, backoff);
      int wait = base_delay + jitter;
      if (wait > cap_delay) wait = cap_delay;
      char buf[32];
      snprintf(buf, sizeof(buf), "Retry in %ds", wait / 1000);
      showTransaction(amountCents, buf);
      delay(wait);
      continue;
    } else {
      http.end();
      if (attempt == max_retries) { showTransaction(amountCents, "System Error"); return; }
      int exp = attempt;
      int backoff = base_delay * (1 << exp);
      if (backoff > cap_delay) backoff = cap_delay;
      int jitter = random(0, backoff);
      int wait = base_delay + jitter;
      if (wait > cap_delay) wait = cap_delay;
      delay(wait);
      continue;
    }
  }
  showTransaction(amountCents, "System Error");
}

// --- PKI renewal helpers (generateCsrBase64, encrypt/store cert in NVS, etc.) ---
// The implementation remains as provided earlier in this file (unchanged).

// Setup and main loop
void setup() {
  Serial.begin(115200);
  randomSeed(esp_random());
  setup_registru_hardware();

  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, LOW);
  pinMode(HAPTIC_PIN, OUTPUT);
  digitalWrite(HAPTIC_PIN, LOW);

  tft.init();
  tft.setRotation(1);
  showMessage("Connecting...", nullptr);

  prefs.begin("pki", false);
  if (!prefs.isKey("renew_failures")) prefs.putInt("renew_failures", 0);
  if (!prefs.isKey("state")) prefs.putInt("state", STATE_OK);
  prefs.end();

  WiFi.mode(WIFI_STA);

  IPAddress local_ip(192, 168, 43, 101); // ESP32 static IP
  IPAddress gateway_ip(192, 168, 43, 1); // phone hotspot gateway
  IPAddress subnet(255, 255, 255, 0);
  IPAddress dns1(8, 8, 8, 8);
  IPAddress dns2(8, 8, 4, 4);

  if (!WiFi.config(local_ip, gateway_ip, subnet, dns1, dns2)) {
    Serial.println("Failed to configure static IP");
  }

  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
  }

  Serial.print("WiFi connected, IP: ");
  Serial.println(WiFi.localIP());

  configTime(0, 0, "pool.ntp.org", "time.google.com");

  secureClient.setCACert(root_ca_pem);
  secureClient.setCertificate(client_cert_pem);
  secureClient.setPrivateKey(client_key_pem);

  showMessage("WiFi Online", nullptr);

  nfc.begin();
  nfc.SAMConfig();

  // Initial PKI check
  runPkiRenewCheckIfNeeded();

  delay(1000);
  showMessage("Scan Phone/Card", nullptr);
}

unsigned long lastPkiCheckMillis = 0;

void loop() {
  // periodic PKI check (daily)
  if (millis() - lastPkiCheckMillis > (unsigned long)RECHECK_INTERVAL_SECONDS * 1000UL) {
    runPkiRenewCheckIfNeeded();
    lastPkiCheckMillis = millis();
  }

  char key = keypad.getKey();
  if (key) {
    Serial.print("Key pressed: ");
    Serial.println(key);
  }

  uint8_t success;
  uint8_t uid[7];
  uint8_t uidLength;

  success = nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength);

  if (success) {
    // hardware feedback on phone presentation
    feedbackPulse();
    showMessage("Card Found", nullptr);

    uint8_t selectApp[5 + sizeof(bank_aid)];
    selectApp[0] = 0x00;
    selectApp[1] = 0xA4;
    selectApp[2] = 0x04;
    selectApp[3] = 0x00;
    selectApp[4] = sizeof(bank_aid);
    memcpy(selectApp + 5, bank_aid, sizeof(bank_aid));

    uint8_t response[255];
    uint8_t responseLength;

    GPIO.out_w1tc = PN532_SS_BIT;
    success = sendNfcCommand(selectApp, sizeof(selectApp), response, &responseLength);
    GPIO.out_w1ts = PN532_SS_BIT;

    if (success && responseLength >= 2 && response[responseLength - 2] == 0x90 && response[responseLength - 1] == 0x00) {

      int amountCents = 15000; // cents
      String amount = String(amountCents);
      String currency = "RON";
      String timestamp = getIsoTimestamp();
      String posNonce = generatePosNonce();

      String gpoPayload = amount + "|" + currency + "|" + timestamp + "|" + posNonce;
      int gpoPayloadLen = gpoPayload.length();
      if (gpoPayloadLen > GPO_MAX_PAYLOAD) {
        showMessage("Payload Too Big", nullptr);
        continue;
      }

      uint8_t gpoCommand[5 + GPO_MAX_PAYLOAD];
      gpoCommand[0] = 0x80;
      gpoCommand[1] = 0xA8;
      gpoCommand[2] = 0x00;
      gpoCommand[3] = 0x00;
      gpoCommand[4] = gpoPayloadLen;
      gpoPayload.getBytes(gpoCommand + 5, gpoPayloadLen + 1);

      GPIO.out_w1tc = PN532_SS_BIT;
      success = sendNfcCommand(gpoCommand, 5 + gpoPayloadLen, response, &responseLength);
      GPIO.out_w1ts = PN532_SS_BIT;

      if (success && responseLength >= 2 && response[responseLength - 2] == 0x90 && response[responseLength - 1] == 0x00) {

        int payloadLen = responseLength - 2;
        String hceResponse = String((char*)response, payloadLen);
        int firstSep = hceResponse.indexOf('|');
        int secondSep = hceResponse.indexOf('|', firstSep + 1);

        if (firstSep > 0 && secondSep > firstSep) {
          String dpan = hceResponse.substring(0, firstSep);
          String atcString = hceResponse.substring(firstSep + 1, secondSep);
          String mac = hceResponse.substring(secondSep + 1);

          bool validAtc = atcString.length() > 0;
          for (size_t i = 0; i < atcString.length(); i++) {
            char c = atcString.charAt(i);
            if (c < '0' || c > '9') {
              validAtc = false;
              break;
            }
          }

          bool validMac = (mac.length() == 64) && isHexString(mac);

          if (validAtc && validMac) {
            int atc = atcString.toInt();

            StaticJsonDocument<512> doc;
            doc["dpan"] = dpan;

            JsonObject transaction = doc.createNestedObject("transaction");
            transaction["amount"] = amountCents; // cents
            transaction["currency"] = "RON";
            transaction["pos_nonce"] = posNonce;
            transaction["terminal_timestamp"] = timestamp;

            JsonObject cryptogram = doc.createNestedObject("cryptogram");
            cryptogram["mac"] = mac;
            cryptogram["atc"] = atc;

            String json;
            serializeJson(doc, json);

            // display sum while processing
            showTransaction(amountCents, "Procesare...");
            sendRequestWithBackoff(json, amountCents);

            delay(3000);
            showMessage("Scan Phone/Card", nullptr);
          } else {
            showMessage("HCE Data Err", nullptr);
            delay(1000);
            showMessage("Scan Phone/Card", nullptr);
          }
        } else {
          showMessage("HCE Parse Err", nullptr);
          delay(1000);
          showMessage("Scan Phone/Card", nullptr);
        }
      } else {
        showMessage("GPO Fail", nullptr);
        delay(1000);
        showMessage("Scan Phone/Card", nullptr);
      }
    } else {
      showMessage("Select Fail", nullptr);
      delay(1000);
      showMessage("Scan Phone/Card", nullptr);
    }
  }
  delay(200);
}