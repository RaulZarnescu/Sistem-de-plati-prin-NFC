// ============================================================
// main.cpp — Firmware POS ESP32 (WiFi Direct)
//
// Arhitectura noua (fara NFC):
//   Telefon Android
//       | HTTP REST pe WiFi local (:80)
//       v
//   ESP32 (server HTTP local)
//       | HTTPS mTLS :443 (neschimbat)
//       v
//   NGINX → Gateway → Banci
//
// Modificari fata de versiunea anterioara:
//   - Server HTTP local (GET /payment-request, POST /payment-response)
//   - State machine: IDLE → WAITING_FOR_PHONE → PROCESSING
//   - HTTP_TIMEOUT_MS = 2000ms (era 5000ms, NGINX taie la 2s)
//   - Full Jitter in computeBackoffMs (era Equal Jitter)
//   - max_retries = 3 (era 5)
//   - Challenge 401: transaction_id extras din doc["detail"] (nu radacina)
//   - Challenge 200: afiseaza APROBAT si return (nu relua authorize)
//   - Challenge 400: "PIN incorect", 403: "Card blocat"
//   - HTTP 400: diferentiat INSUFFICIENT_FUNDS / INVALID_CRYPTOGRAM
//   - DeviceState enum mutat inainte de primul sau use (fix compilare)
//   - lastPkiCheckMillis mutat in global scope (fix compilare)
//   - continue invalid din loop() eliminat prin restructurare
//   - Reconectare WiFi automata in loop()
// ============================================================

#include <Adafruit_GFX.h>
#include <Adafruit_PN532.h>
#include <Arduino.h>
#include <ArduinoJson.h>
#include <ESPAsyncWebServer.h>
#include <HTTPClient.h>
#include <Keypad.h>
#include <MCUFRIEND_kbv.h>
#include <SPI.h>

// Culori compatibilitate TFT_eSPI
#define TFT_BLACK 0x0000
#define TFT_WHITE 0xFFFF
#define TFT_RED 0xF800
#define TFT_GREEN 0x07E0
#define TFT_BLUE 0x001F
#define TFT_YELLOW 0xFFE0
#define TFT_CYAN 0x07FF
#define TFT_MAGENTA 0xF81F
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <time.h>

#include <mbedtls/base64.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/gcm.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/sha256.h>
#include <mbedtls/x509_csr.h>

#include <Preferences.h>
#include <vector>

#include "soc/gpio_reg.h"
#include "soc/io_mux_reg.h"

// ── Pinout ──────────────────────────────────────────────────
#define PN532_SS_BIT (1 << 5)
#define PN532_SCK (18)
#define PN532_MISO (19)
#define PN532_MOSI (23)
#define PN532_SS (5)

#define KEYPAD_R1 (34)
#define KEYPAD_R2 (35)
#define KEYPAD_R3 (36)
#define KEYPAD_R4 (39)
#define KEYPAD_C1 (19)
#define KEYPAD_C2 (23)
#define KEYPAD_C3 (21)

#define LED_PIN 5
#define HAPTIC_PIN 18

// ── Keypad 3x4 (Remapată pentru a evita conflictele de pini) ──
const byte ROWS = 4;
const byte COLS = 3;
char keys[ROWS][COLS] = {
    {'1', '2', '3'}, {'4', '5', '6'}, {'7', '8', '9'}, {'*', '0', '#'}};
byte rowPins[ROWS] = {KEYPAD_R1, KEYPAD_R2, KEYPAD_R3, KEYPAD_R4};
byte colPins[COLS] = {KEYPAD_C1, KEYPAD_C2, KEYPAD_C3};

// ── Enums (definite inainte de variabilele globale care le folosesc) ──
enum DeviceState { STATE_OK = 0, STATE_BRICKED_PENDING_MANUAL_RESET = 1 };

// State machine WiFi Direct
enum PosState {
  POS_IDLE = 0,
  POS_WAITING_FOR_PHONE, // ESP32 asteapta POST /payment-response de la telefon
  POS_PROCESSING         // date primite, tranzactie in procesare la Gateway
};

// ── Structura tranzactie activa ──────────────────────────────
struct PendingTransaction {
  PosState state = POS_IDLE;
  int amountCents = 0;
  String currency = "RON";
  String posNonce;
  String terminalTimestamp;
  unsigned long stateEnteredAt = 0;
  // Completate de telefon via POST /payment-response:
  String dpan;
  String mac;
  int atc = 0;
};

// ── Obiecte hardware ──────────────────────────────────────────
Adafruit_PN532 nfc(PN532_SS);
WiFiClientSecure secureClient;
MCUFRIEND_kbv tft;
Keypad keypad = Keypad(makeKeymap(keys), rowPins, colPins, ROWS, COLS);
Preferences prefs;
AsyncWebServer localServer(80);

// ── Configuratie retea / gateway ──────────────────────────────
const char *ssid = "DIGI-xCC4";
const char *password = "UTj5eRDM";
const char *gateway_host = "192.168.101.11";
const uint16_t gateway_port = 443;
const char *gateway_path = "/api/v1/payments/authorize";
const char *challenge_path = "/api/v1/payments/challenge";
const char *pki_renew_path = "/api/pki/renew";

const uint8_t bank_aid[] = {0xF1, 0xC7, 0x1B, 0x3B, 0x4E, 0x4B, 0x01};

// ── Certificate PEM ───────────────────────────────────────────
// IMPORTANT: Certificatele NU mai sunt hardcodate in cod.
// Ele sunt stocate criptat in NVS (Non-Volatile Storage) si
// provizionate o singura data prin sketch-ul ESP32_code/provisioning/main.cpp
// + scriptul scripts/provision_esp32.py.
//
// La boot, main.cpp le citeste din NVS. Daca NVS e gol,
// terminalul se blocheaza si afiseaza "Provisioning necesar!".
//
// Avantaje:
//   - Niciun secret in codul sursa (GitHub-safe)
//   - Reinnoire PKI automata via /api/pki/renew scrie direct in NVS
//   - Scalabil: acelasi firmware pe 50 de terminale, doar provisioning-ul difera
//   - Cheia privata nu e niciodata vizibila in cod

// Cheie AES-GCM pentru NVS (provisionata securizat; schimba in productie)
static const uint8_t CERT_ENC_KEY[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
    0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
    0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};

// ── Chei NVS ──────────────────────────────────────────────────
const char *CLIENT_CERT_NVS_KEY = "mtls_cert";
const char *CLIENT_KEY_NVS_KEY = "mtls_key";
const char *ROOT_CA_NVS_KEY = "root_ca";
const char *RENEW_FAILURES_NVS_KEY = "renew_failures";
const char *STATE_NVS_KEY = "state";

static const int CERT_IV_LEN = 12;
static const int CERT_TAG_LEN = 16;

// ── Constante operationale ────────────────────────────────────
// HTTP_TIMEOUT_MS = 2000ms: aliniat cu nginx proxy_read_timeout 2s
const int HTTP_TIMEOUT_MS = 2000;
const int GPO_MAX_PAYLOAD = 128;
const int PIN_MAX_DIGITS = 6;
const int PIN_MIN_LENGTH = 4;
const int CSR_KEY_BITS = 2048;
const int RECHECK_INTERVAL_SECONDS = 24 * 3600;
const int RENEW_DAYS_BEFORE = 5;
const int RENEW_MAX_FAILURES = 3;

// Timeout asteptare raspuns telefon in STATE WAITING_FOR_PHONE
const unsigned long PHONE_WAIT_TIMEOUT_MS = 30000UL;

// ── Variabile globale de stare ────────────────────────────────
String current_client_cert_pem;
String current_client_key_pem;
String current_root_ca_pem;
String current_bank_pub_pem;
String g_terminalId;
DeviceState g_deviceState = STATE_OK;
PendingTransaction g_tx;
unsigned long lastPkiCheckMillis =
    0; // mutat in global scope (fix eroare compilare)

// ── Forward declarations ──────────────────────────────────────
String getIsoTimestamp();
String generatePosNonce();
String generateUuidV4();
bool isHexString(const String &value);
void showMessage(const char *line1, const char *line2 = nullptr);
void showTransaction(int amountCents, const char *status);
bool sendNfcCommand(const uint8_t *command, uint8_t commandLen,
                    uint8_t *response, uint8_t *responseLength);
bool buildEmvGpoPayload(int amountCents, const String &currency,
                        const String &timestamp, const String &posNonce,
                        uint8_t *outData, int &outLen);
String extractCertCN(const String &certPem);
String getTerminalId();
String encryptPinBlockAndBase64(const String &transaction_id,
                                const String &pin);
int computeBackoffMs(int attempt, int base_delay, int cap_delay);
bool isRetryableStatus(int httpCode);
String jsonGetString(const JsonVariantConst &value);
bool getCertExpiry(const char *cert_pem, time_t &not_after);
bool generateCsrBase64(String &out_csr_base64, String &out_priv_key_pem);
bool postCsrAndStoreNewCert(const String &csr_base64, const String &newKeyPem);
bool storeClientCredentialsToNVS(const String &certPem, const String &keyPem);
bool loadClientCredentialsFromNVS(String &certPem, String &keyPem);
bool storeEncryptedStringToNVS(const String &value, const char *prefKey);
bool loadEncryptedStringFromNVS(const char *prefKey, String &outValue);
bool storeRootCaToNVS(const String &rootCaPem);
bool loadRootCaFromNVS(String &outRootCaPem);
bool setDeviceState(DeviceState state);
DeviceState loadDeviceState();
int getRenewFailures();
bool setRenewFailures(int count);
bool runPkiRenewCheckIfNeeded();
String base64Encode(const uint8_t *data, size_t len);
bool base64Decode(const String &input, std::vector<uint8_t> &out);
bool aesGcmEncrypt(const uint8_t *key, const uint8_t *iv, size_t iv_len,
                   const uint8_t *input, size_t input_len, uint8_t *output,
                   size_t output_len, uint8_t *tag, size_t tag_len);
bool aesGcmDecrypt(const uint8_t *key, const uint8_t *iv, size_t iv_len,
                   const uint8_t *input, size_t input_len, const uint8_t *tag,
                   size_t tag_len, uint8_t *output);
void fillRandomBytes(uint8_t *buffer, size_t length);
void setupLocalServer();
void dumpCertificateDiagnostics();

// ============================================================
// UTILITARE HARDWARE
// ============================================================

void feedbackPulse() {
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
  GPIO.out_w1ts = PN532_SS_BIT;
}

// ============================================================
// UTILITARE GENERARE DATE
// ============================================================

String getIsoTimestamp() {
  struct tm timeinfo;
  if (!getLocalTime(&timeinfo)) {
    return "2026-01-01T00:00:00Z"; // fallback vizibil in loguri
  }
  char buf[25];
  strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &timeinfo);
  return String(buf);
}

String generatePosNonce() {
  uint32_t value =
      (((uint32_t)esp_random() & 0xFFFF) << 16) | (esp_random() & 0xFFFF);
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
  d2 = (d2 & 0x3FFFFFFF) | 0x80000000; // variant 10xx

  char buf[37];
  snprintf(buf, sizeof(buf), "%08lx-%04x-%04x-%04x-%04x%08lx",
           (unsigned long)d0, (unsigned int)(d1 >> 16),
           (unsigned int)(d1 & 0xFFFF), (unsigned int)(d2 >> 16),
           (unsigned int)(d2 & 0xFFFF), (unsigned long)d3);
  return String(buf);
}

bool isHexString(const String &value) {
  for (size_t i = 0; i < value.length(); i++) {
    char c = value.charAt(i);
    if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') ||
          (c >= 'a' && c <= 'f'))) {
      return false;
    }
  }
  return true;
}

// ============================================================
// DISPLAY TFT
// ============================================================

// 16-bit RGB565 Modern Palette
#define COLOR_BG 0x0842         // Foarte închis, albastru-gri (Deep Slate Blue)
#define COLOR_CARD 0x18C7       // Albastru-gri mediu închis (Sleek Card)
#define COLOR_ACCENT 0x3DFF     // Cyan/Albastru Neon vibrant (Accent)
#define COLOR_TEXT_MAIN 0xFFFF  // Alb pur
#define COLOR_TEXT_MUTED 0xBDF7 // Gri deschis / muted
#define COLOR_GREEN 0x2E66      // Verde smarald premium (Emerald Success)
#define COLOR_RED 0xD144        // Roșu chihlimbar/stins (Crimson Error)
#define COLOR_YELLOW 0xFDE0     // Galben chihlimbar (Amber/Gold)

void drawHeaderAndFooter(const char *state_str) {
  // Top Header
  tft.fillRect(0, 0, 320, 30, COLOR_CARD);
  tft.setTextColor(COLOR_ACCENT);
  tft.setTextSize(2);
  tft.setCursor(10, 7);
  tft.print("SECURE POS");

  // WiFi status right-aligned
  tft.setTextSize(1);
  if (WiFi.status() == WL_CONNECTED) {
    tft.fillCircle(300, 15, 4, COLOR_GREEN);
    tft.setTextColor(COLOR_TEXT_MUTED);
    tft.setCursor(250, 11);
    tft.print("ONLINE");
  } else {
    tft.fillCircle(300, 15, 4, COLOR_RED);
    tft.setTextColor(COLOR_RED);
    tft.setCursor(240, 11);
    tft.print("OFFLINE");
  }

  // Divider line
  tft.drawFastHLine(0, 30, 320, COLOR_ACCENT);

  // Bottom Footer
  tft.drawFastHLine(0, 210, 320, COLOR_CARD);
  tft.fillRect(0, 211, 320, 29, COLOR_BG);
  tft.setTextColor(COLOR_TEXT_MUTED);
  tft.setTextSize(1);
  tft.setCursor(10, 220);
  tft.print("ID: ");
  tft.print(g_terminalId.length() > 0 ? g_terminalId.c_str() : "POS-DEVICE");

  if (state_str) {
    tft.setCursor(220, 220);
    tft.print(state_str);
  }
}

void showMessage(const char *line1, const char *line2) {
  // 1. Boot / Setup Screen
  if (line1 && (strstr(line1, "Pornire") || strstr(line1, "WiFi") ||
                strstr(line1, "NTP") || strstr(line1, "Cert"))) {
    tft.fillScreen(COLOR_BG);
    drawHeaderAndFooter("SETUP");

    tft.fillRoundRect(20, 50, 280, 140, 8, COLOR_CARD);
    tft.drawRoundRect(20, 50, 280, 140, 8, COLOR_ACCENT);

    tft.setTextColor(COLOR_TEXT_MAIN);
    tft.setTextSize(2);
    tft.setCursor(40, 80);
    tft.print(line1);

    if (line2 && strlen(line2) > 0) {
      tft.setTextColor(COLOR_TEXT_MUTED);
      tft.setTextSize(1);
      tft.setCursor(40, 120);
      tft.print(line2);
    }

    tft.drawRoundRect(40, 150, 240, 10, 3, COLOR_BG);
    tft.fillRoundRect(42, 152, 120, 6, 2, COLOR_ACCENT);
    return;
  }

  // 2. Idle State Screen
  if (line1 && strcmp(line1, "Gata de plata") == 0) {
    tft.fillScreen(COLOR_BG);
    drawHeaderAndFooter("IDLE");

    tft.fillRoundRect(20, 50, 280, 145, 8, COLOR_CARD);
    tft.drawRoundRect(20, 50, 280, 145, 8, COLOR_ACCENT);

    tft.setTextColor(COLOR_TEXT_MAIN);
    tft.setTextSize(2);
    tft.setCursor(75, 80);
    tft.print("GATA DE PLATA");

    tft.setTextColor(COLOR_TEXT_MUTED);
    tft.setTextSize(1);
    tft.setCursor(45, 120);
    tft.print("Asteptare initiere tranzactie...");
    tft.setCursor(55, 140);
    tft.print("Folositi dashboard-ul local");

    // Card symbol
    tft.drawRoundRect(140, 160, 40, 24, 4, COLOR_ACCENT);
    tft.fillRect(140, 165, 40, 5, COLOR_ACCENT);
    return;
  }

  // 3. Blocked State Screen
  if (line1 && strcmp(line1, "Terminal BLOCAT") == 0) {
    tft.fillScreen(COLOR_RED);

    tft.fillRoundRect(30, 40, 260, 160, 8, COLOR_BG);
    tft.drawRoundRect(30, 40, 260, 160, 8, COLOR_RED);

    tft.setTextColor(COLOR_RED);
    tft.setTextSize(2);
    tft.setCursor(70, 70);
    tft.print("TERMINAL BLOCAT");

    tft.setTextColor(COLOR_TEXT_MAIN);
    tft.setTextSize(1);
    tft.setCursor(50, 115);
    tft.print("Incalcarea securitatii detectata!");
    tft.setCursor(60, 135);
    tft.print("Necesita resetare manuala de");
    tft.setCursor(70, 155);
    tft.print("la serverul central (PKI).");
    return;
  }

  // 4. PIN Entry Screen
  if (line1 && (strcmp(line1, "Introdu PIN:") == 0 ||
                strcmp(line1, "PIN necesar") == 0)) {
    tft.fillScreen(COLOR_BG);
    drawHeaderAndFooter("SECURITY");

    tft.fillRoundRect(20, 50, 280, 145, 8, COLOR_CARD);
    tft.drawRoundRect(20, 50, 280, 145, 8, COLOR_YELLOW);

    tft.setTextColor(COLOR_TEXT_MAIN);
    tft.setTextSize(2);
    tft.setCursor(85, 70);
    tft.print("INTRODU PIN");

    tft.drawRoundRect(60, 105, 200, 36, 6, COLOR_BG);

    int pin_len = 0;
    if (line2) {
      for (size_t i = 0; i < strlen(line2); i++) {
        if (line2[i] == '*')
          pin_len++;
      }
    }

    int start_x = 95;
    for (int i = 0; i < 4; i++) {
      if (i < pin_len) {
        tft.fillCircle(start_x + i * 40, 123, 8, COLOR_YELLOW);
      } else {
        tft.drawCircle(start_x + i * 40, 123, 8, COLOR_TEXT_MUTED);
      }
    }

    tft.setTextColor(COLOR_TEXT_MUTED);
    tft.setTextSize(1);
    tft.setCursor(65, 160);
    tft.print("Confirmati introducerea cu #");
    return;
  }

  // 5. Success Screen
  if (line2 && strcmp(line2, "APROBAT") == 0) {
    tft.fillScreen(COLOR_GREEN);

    tft.setTextColor(COLOR_TEXT_MAIN);
    tft.setTextSize(3);
    tft.setCursor(95, 60);
    tft.print("APROBAT");

    // Draw huge checkmark
    tft.drawLine(120, 130, 150, 160, COLOR_TEXT_MAIN);
    tft.drawLine(120, 131, 150, 161, COLOR_TEXT_MAIN);
    tft.drawLine(120, 132, 150, 162, COLOR_TEXT_MAIN);
    tft.drawLine(150, 160, 210, 90, COLOR_TEXT_MAIN);
    tft.drawLine(150, 161, 210, 91, COLOR_TEXT_MAIN);
    tft.drawLine(150, 162, 210, 92, COLOR_TEXT_MAIN);

    tft.setTextSize(2);
    tft.setCursor(55, 185);
    tft.print("Plata finalizata!");
    return;
  }

  // 6. Declined or Error Screen
  if (line2 && (strcmp(line2, "REFUZAT") == 0 || strstr(line2, "refuzat") ||
                strstr(line2, "insuf") || strstr(line2, "blocat") ||
                strstr(line2, "Eroare") || strstr(line2, "Timeout") ||
                strstr(line2, "Err:"))) {
    tft.fillScreen(COLOR_RED);

    tft.setTextColor(COLOR_TEXT_MAIN);
    tft.setTextSize(3);
    tft.setCursor(95, 50);
    tft.print("REFUZAT");

    tft.fillRoundRect(30, 100, 260, 90, 8, COLOR_BG);
    tft.drawRoundRect(30, 100, 260, 90, 8, COLOR_TEXT_MAIN);

    tft.setTextColor(COLOR_TEXT_MAIN);
    tft.setTextSize(2);
    int text_x = 160 - (strlen(line2) * 6);
    tft.setCursor(text_x > 40 ? text_x : 40, 125);
    tft.print(line2);

    tft.setTextColor(COLOR_TEXT_MUTED);
    tft.setTextSize(1);
    tft.setCursor(65, 165);
    tft.print("Contactati banca emitenta");
    return;
  }

  // 7. Transaction Amount Screen
  bool is_amount_screen = false;
  if (line1 && strlen(line1) > 4) {
    if (strcmp(line1 + strlen(line1) - 3, "RON") == 0) {
      is_amount_screen = true;
    }
  }

  if (is_amount_screen) {
    tft.fillScreen(COLOR_BG);
    drawHeaderAndFooter("PAYMENT");

    tft.fillRoundRect(20, 50, 280, 145, 8, COLOR_CARD);
    tft.drawRoundRect(20, 50, 280, 145, 8, COLOR_ACCENT);

    tft.setTextColor(COLOR_TEXT_MUTED);
    tft.setTextSize(1);
    tft.setCursor(110, 65);
    tft.print("SUMA DE PLATA");

    tft.setTextColor(COLOR_TEXT_MAIN);
    tft.setTextSize(3);
    int amt_x = 160 - (strlen(line1) * 9);
    tft.setCursor(amt_x > 30 ? amt_x : 30, 88);
    tft.print(line1);

    if (line2 && strcmp(line2, "Procesare...") == 0) {
      tft.fillRoundRect(40, 135, 240, 35, 6, COLOR_YELLOW);
      tft.setTextColor(COLOR_BG);
      tft.setTextSize(1);
      tft.setCursor(95, 148);
      tft.print("PROCESARE PLATA...");
    } else {
      tft.fillRoundRect(40, 135, 240, 35, 6, COLOR_ACCENT);
      tft.setTextColor(COLOR_TEXT_MAIN);
      tft.setTextSize(1);
      int stat_x = 160 - ((line2 ? strlen(line2) : 14) * 3);
      tft.setCursor(stat_x > 45 ? stat_x : 45, 148);
      tft.print(line2 ? line2 : "APROPIATI TELEFONUL");
    }
    return;
  }

  // 8. General Info Fallback
  tft.fillScreen(COLOR_BG);
  drawHeaderAndFooter("INFO");

  tft.fillRoundRect(20, 50, 280, 145, 8, COLOR_CARD);
  tft.drawRoundRect(20, 50, 280, 145, 8, COLOR_ACCENT);

  tft.setTextColor(COLOR_TEXT_MAIN);
  tft.setTextSize(2);
  tft.setCursor(40, 80);
  tft.print(line1);

  if (line2 && strlen(line2) > 0) {
    tft.setTextColor(COLOR_TEXT_MUTED);
    tft.setTextSize(1);
    tft.setCursor(40, 120);
    tft.print(line2);
  }
}

void showTransaction(int amountCents, const char *status) {
  char amtBuf[32];
  int lei = amountCents / 100;
  int cents = amountCents % 100;
  snprintf(amtBuf, sizeof(amtBuf), "%d.%02d RON", lei, cents);
  showMessage(amtBuf, status);
}

// ============================================================
// UTILITARE CRYPTO / ENCODING
// ============================================================

void fillRandomBytes(uint8_t *buffer, size_t length) {
  size_t i = 0;
  while (i < length) {
    uint32_t rnd = esp_random();
    for (size_t j = 0; j < 4 && i < length; ++j) {
      buffer[i++] = (rnd >> (8 * j)) & 0xFF;
    }
  }
}

String base64Encode(const uint8_t *data, size_t len) {
  size_t olen = 0;
  mbedtls_base64_encode(NULL, 0, &olen, data, len);
  std::vector<unsigned char> out(olen + 1);
  if (mbedtls_base64_encode(out.data(), out.size(), &olen, data, len) != 0) {
    return String();
  }
  out[olen] = '\0';
  return String((char *)out.data());
}

bool base64Decode(const String &input, std::vector<uint8_t> &out) {
  size_t olen = 0;
  mbedtls_base64_decode(NULL, 0, &olen, (const unsigned char *)input.c_str(),
                        input.length());
  out.resize(olen);
  if (mbedtls_base64_decode(out.data(), out.size(), &olen,
                            (const unsigned char *)input.c_str(),
                            input.length()) != 0) {
    return false;
  }
  out.resize(olen);
  return true;
}

bool aesGcmEncrypt(const uint8_t *key, const uint8_t *iv, size_t iv_len,
                   const uint8_t *input, size_t input_len, uint8_t *output,
                   size_t output_len, uint8_t *tag, size_t tag_len) {
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
  if (ret != 0) {
    mbedtls_gcm_free(&gcm);
    return false;
  }
  ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, input_len, iv,
                                  iv_len, NULL, 0, input, output, tag_len, tag);
  mbedtls_gcm_free(&gcm);
  return ret == 0;
}

bool aesGcmDecrypt(const uint8_t *key, const uint8_t *iv, size_t iv_len,
                   const uint8_t *input, size_t input_len, const uint8_t *tag,
                   size_t tag_len, uint8_t *output) {
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
  if (ret != 0) {
    mbedtls_gcm_free(&gcm);
    return false;
  }
  ret = mbedtls_gcm_auth_decrypt(&gcm, input_len, iv, iv_len, NULL, 0, tag,
                                 tag_len, input, output);
  mbedtls_gcm_free(&gcm);
  return ret == 0;
}

// ============================================================
// STOCARE NVS (certificate criptate AES-GCM)
// ============================================================

bool storeEncryptedStringToNVS(const String &value, const char *prefKey) {
  std::vector<uint8_t> plaintext(value.length());
  memcpy(plaintext.data(), value.c_str(), value.length());

  uint8_t iv[CERT_IV_LEN];
  uint8_t tag[CERT_TAG_LEN];
  fillRandomBytes(iv, CERT_IV_LEN);

  std::vector<uint8_t> ciphertext(plaintext.size());
  if (!aesGcmEncrypt(CERT_ENC_KEY, iv, CERT_IV_LEN, plaintext.data(),
                     plaintext.size(), ciphertext.data(), ciphertext.size(),
                     tag, CERT_TAG_LEN)) {
    return false;
  }

  std::vector<uint8_t> blob;
  blob.reserve(CERT_IV_LEN + CERT_TAG_LEN + ciphertext.size());
  blob.insert(blob.end(), iv, iv + CERT_IV_LEN);
  blob.insert(blob.end(), tag, tag + CERT_TAG_LEN);
  blob.insert(blob.end(), ciphertext.begin(), ciphertext.end());

  String encoded = base64Encode(blob.data(), blob.size());
  if (encoded.length() == 0)
    return false;

  prefs.begin("pki", false);
  bool ok = prefs.putString(prefKey, encoded);
  prefs.end();
  return ok;
}

bool loadEncryptedStringFromNVS(const char *prefKey, String &outValue) {
  prefs.begin("pki", false);
  String encoded = prefs.getString(prefKey, "");
  prefs.end();
  if (encoded.length() == 0)
    return false;

  std::vector<uint8_t> blob;
  if (!base64Decode(encoded, blob))
    return false;
  if (blob.size() <= (size_t)(CERT_IV_LEN + CERT_TAG_LEN))
    return false;

  size_t ciphertextLen = blob.size() - CERT_IV_LEN - CERT_TAG_LEN;
  const uint8_t *iv = blob.data();
  const uint8_t *tag = blob.data() + CERT_IV_LEN;
  const uint8_t *ciphertext = blob.data() + CERT_IV_LEN + CERT_TAG_LEN;

  std::vector<uint8_t> plaintext(ciphertextLen);
  if (!aesGcmDecrypt(CERT_ENC_KEY, iv, CERT_IV_LEN, ciphertext, ciphertextLen,
                     tag, CERT_TAG_LEN, plaintext.data())) {
    return false;
  }
  outValue = String((char *)plaintext.data(), plaintext.size());
  return true;
}

bool storeRootCaToNVS(const String &rootCaPem) {
  return storeEncryptedStringToNVS(rootCaPem, ROOT_CA_NVS_KEY);
}
bool loadRootCaFromNVS(String &outRootCaPem) {
  return loadEncryptedStringFromNVS(ROOT_CA_NVS_KEY, outRootCaPem);
}
bool storeClientCredentialsToNVS(const String &certPem, const String &keyPem) {
  return storeEncryptedStringToNVS(certPem, CLIENT_CERT_NVS_KEY) &&
         storeEncryptedStringToNVS(keyPem, CLIENT_KEY_NVS_KEY);
}
bool loadClientCredentialsFromNVS(String &certPem, String &keyPem) {
  return loadEncryptedStringFromNVS(CLIENT_CERT_NVS_KEY, certPem) &&
         loadEncryptedStringFromNVS(CLIENT_KEY_NVS_KEY, keyPem);
}

// ============================================================
// DEVICE STATE + PKI RENEWAL COUNTERS (NVS)
// ============================================================

bool setDeviceState(DeviceState state) {
  prefs.begin("pki", false);
  bool ok = prefs.putInt(STATE_NVS_KEY, (int)state);
  prefs.end();
  if (ok)
    g_deviceState = state;
  return ok;
}

DeviceState loadDeviceState() {
  prefs.begin("pki", false);
  int state = prefs.getInt(STATE_NVS_KEY, STATE_OK);
  prefs.end();
  if (state != STATE_OK && state != STATE_BRICKED_PENDING_MANUAL_RESET) {
    return STATE_OK;
  }
  return (DeviceState)state;
}

int getRenewFailures() {
  prefs.begin("pki", false);
  int count = prefs.getInt(RENEW_FAILURES_NVS_KEY, 0);
  prefs.end();
  return count;
}

bool setRenewFailures(int count) {
  prefs.begin("pki", false);
  bool ok = prefs.putInt(RENEW_FAILURES_NVS_KEY, count);
  prefs.end();
  return ok;
}

// ============================================================
// UTILITARE GENERALE HTTP / JSON
// ============================================================

// Full Jitter conform spec: wait = random(0, min(cap, base * 2^attempt))
int computeBackoffMs(int attempt, int base_delay, int cap_delay) {
  int exp = min(attempt, 4);
  long upper = min((long)cap_delay, (long)base_delay * (1L << exp));
  return (int)random(0, upper + 1);
}

bool isRetryableStatus(int httpCode) {
  return httpCode == 409 || httpCode == 429 || httpCode == 503 || httpCode <= 0;
}

String jsonGetString(const JsonVariantConst &value) {
  if (value.is<const char *>())
    return String(value.as<const char *>());
  if (value.is<int>())
    return String(value.as<int>());
  return String();
}

// ============================================================
// PKI: GENERARE CSR + REINNOIRE CERTIFICAT
// ============================================================

time_t mbedtlsX509TimeToTimeT(const mbedtls_x509_time &t) {
  struct tm tm_time;
  memset(&tm_time, 0, sizeof(tm_time));
  tm_time.tm_year = t.year - 1900;
  tm_time.tm_mon = t.mon - 1;
  tm_time.tm_mday = t.day;
  tm_time.tm_hour = t.hour;
  tm_time.tm_min = t.min;
  tm_time.tm_sec = t.sec;
  tm_time.tm_isdst = 0;
  return mktime(&tm_time);
}

bool getCertExpiry(const char *cert_pem, time_t &not_after) {
  mbedtls_x509_crt crt;
  mbedtls_x509_crt_init(&crt);
  int ret = mbedtls_x509_crt_parse(&crt, (const unsigned char *)cert_pem,
                                   strlen(cert_pem) + 1);
  if (ret != 0) {
    mbedtls_x509_crt_free(&crt);
    return false;
  }
  not_after = mbedtlsX509TimeToTimeT(crt.valid_to);
  mbedtls_x509_crt_free(&crt);
  return true;
}

String extractCertCN(const String &certPem) {
  mbedtls_x509_crt crt;
  mbedtls_x509_crt_init(&crt);
  if (mbedtls_x509_crt_parse(&crt, (const unsigned char *)certPem.c_str(),
                             certPem.length() + 1) != 0) {
    mbedtls_x509_crt_free(&crt);
    return String();
  }
  char dn[512];
  if (mbedtls_x509_dn_gets(dn, sizeof(dn), &crt.subject) <= 0) {
    mbedtls_x509_crt_free(&crt);
    return String();
  }
  String dnStr(dn);
  int start = dnStr.indexOf("CN=");
  if (start < 0) {
    mbedtls_x509_crt_free(&crt);
    return String();
  }
  dnStr = dnStr.substring(start + 3);
  int end = dnStr.indexOf(',');
  if (end >= 0)
    dnStr = dnStr.substring(0, end);
  mbedtls_x509_crt_free(&crt);
  return dnStr;
}

String getTerminalId() {
  if (g_terminalId.length() > 0)
    return g_terminalId;
  if (current_client_cert_pem.length() > 0) {
    g_terminalId = extractCertCN(current_client_cert_pem);
    if (g_terminalId.length() > 0)
      return g_terminalId;
  }
  g_terminalId = "POS-" + generateUuidV4();
  return g_terminalId;
}

// ============================================================
// DIAGNOSTIC TLS/mTLS — Dump complet certificate + verificare lant
//
// Aceasta functie parseaza cu mbedtls CA root, certificatul client,
// si cheia privata client. Afiseaza Subject, Issuer, date de
// validitate, tip/dimensiune cheie, si verifica manual daca:
//   1. CA root-ul poate valida certificatul client (chain)
//   2. Datele de validitate sunt corecte vs ceasul curent
//   3. Cheia privata se potriveste cu certificatul client
// ============================================================

void dumpCertificateDiagnostics() {
  Serial.println("\n╔══════════════════════════════════════════════════════╗");
  Serial.println("║         DIAGNOSTIC TLS/mTLS — CERTIFICATE            ║");
  Serial.println("╚══════════════════════════════════════════════════════╝");

  // ── 1. Parsare si afisare CA Root ──────────────────────────
  mbedtls_x509_crt ca_crt;
  mbedtls_x509_crt_init(&ca_crt);
  int ret_ca = mbedtls_x509_crt_parse(
      &ca_crt, (const unsigned char *)current_root_ca_pem.c_str(),
      current_root_ca_pem.length() + 1);

  Serial.println("\n── CA ROOT ──────────────────────────────────────────");
  if (ret_ca != 0) {
    Serial.printf("[DIAG] EROARE parsare CA root: -0x%04X\n", -ret_ca);
    Serial.println("[DIAG] CA PEM primii 80 chars:");
    Serial.println(current_root_ca_pem.substring(0, 80));
  } else {
    char buf[512];
    mbedtls_x509_dn_gets(buf, sizeof(buf), &ca_crt.subject);
    Serial.printf("[DIAG] CA Subject : %s\n", buf);
    mbedtls_x509_dn_gets(buf, sizeof(buf), &ca_crt.issuer);
    Serial.printf("[DIAG] CA Issuer  : %s\n", buf);
    Serial.printf("[DIAG] CA Valid   : %04d-%02d-%02d → %04d-%02d-%02d\n",
                  ca_crt.valid_from.year, ca_crt.valid_from.mon,
                  ca_crt.valid_from.day, ca_crt.valid_to.year,
                  ca_crt.valid_to.mon, ca_crt.valid_to.day);
    Serial.printf("[DIAG] CA Self-signed: %s\n",
                  (ca_crt.issuer_raw.len == ca_crt.subject_raw.len &&
                   memcmp(ca_crt.issuer_raw.p, ca_crt.subject_raw.p,
                          ca_crt.issuer_raw.len) == 0)
                      ? "DA"
                      : "NU");
    size_t key_bits = mbedtls_pk_get_bitlen(&ca_crt.pk);
    Serial.printf("[DIAG] CA Key     : %s %d bits\n",
                  mbedtls_pk_get_name(&ca_crt.pk), (int)key_bits);
  }

  // ── 2. Parsare si afisare Client Cert ──────────────────────
  mbedtls_x509_crt cli_crt;
  mbedtls_x509_crt_init(&cli_crt);
  int ret_cli = mbedtls_x509_crt_parse(
      &cli_crt, (const unsigned char *)current_client_cert_pem.c_str(),
      current_client_cert_pem.length() + 1);

  Serial.println("\n── CLIENT CERT ─────────────────────────────────────");
  if (ret_cli != 0) {
    Serial.printf("[DIAG] EROARE parsare Client cert: -0x%04X\n", -ret_cli);
  } else {
    char buf[512];
    mbedtls_x509_dn_gets(buf, sizeof(buf), &cli_crt.subject);
    Serial.printf("[DIAG] Client Subject : %s\n", buf);
    mbedtls_x509_dn_gets(buf, sizeof(buf), &cli_crt.issuer);
    Serial.printf("[DIAG] Client Issuer  : %s\n", buf);
    Serial.printf("[DIAG] Client Valid   : %04d-%02d-%02d → %04d-%02d-%02d\n",
                  cli_crt.valid_from.year, cli_crt.valid_from.mon,
                  cli_crt.valid_from.day, cli_crt.valid_to.year,
                  cli_crt.valid_to.mon, cli_crt.valid_to.day);
    size_t key_bits = mbedtls_pk_get_bitlen(&cli_crt.pk);
    Serial.printf("[DIAG] Client Key     : %s %d bits\n",
                  mbedtls_pk_get_name(&cli_crt.pk), (int)key_bits);
  }

  // ── 3. Parsare Client Private Key ──────────────────────────
  Serial.println("\n── CLIENT KEY ──────────────────────────────────────");
  mbedtls_pk_context cli_pk;
  mbedtls_pk_init(&cli_pk);
  int ret_key = mbedtls_pk_parse_key(
      &cli_pk, (const unsigned char *)current_client_key_pem.c_str(),
      current_client_key_pem.length() + 1, NULL, 0);
  if (ret_key != 0) {
    Serial.printf("[DIAG] EROARE parsare Client key: -0x%04X\n", -ret_key);
  } else {
    Serial.printf("[DIAG] Key Type   : %s\n", mbedtls_pk_get_name(&cli_pk));
    Serial.printf("[DIAG] Key Size   : %d bits\n",
                  (int)mbedtls_pk_get_bitlen(&cli_pk));
    // Verificam potrivirea key-cert
    if (ret_cli == 0) {
      if (mbedtls_pk_get_bitlen(&cli_pk) ==
              mbedtls_pk_get_bitlen(&cli_crt.pk) &&
          mbedtls_pk_get_type(&cli_pk) ==
              mbedtls_pk_get_type(&cli_crt.pk)) {
        Serial.println("[DIAG] Key-Cert Match : DA (acelasi tip si dimensiune)");
      } else {
        Serial.println("[DIAG] Key-Cert Match : NU! Tip sau dimensiune diferita!");
      }
    }
  }
  mbedtls_pk_free(&cli_pk);

  // ── 4. Verificare manuala lant CA → Client ──────────────────
  Serial.println("\n── VERIFICARE LANT CA → CLIENT ─────────────────────");
  if (ret_ca == 0 && ret_cli == 0) {
    uint32_t flags = 0;
    int ret_verify = mbedtls_x509_crt_verify(&cli_crt, &ca_crt, NULL, NULL,
                                              &flags, NULL, NULL);
    if (ret_verify == 0) {
      Serial.println("[DIAG] ✓ Verificare REUSITA: CA root-ul valideaza "
                     "certificatul client.");
    } else {
      Serial.printf("[DIAG] ✗ Verificare ESUATA! ret=-0x%04X flags=0x%08lX\n",
                    -ret_verify, (unsigned long)flags);
      char vrfy_buf[512];
      mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
      Serial.println("[DIAG] Detalii verificare:");
      Serial.println(vrfy_buf);

      // Decodificam flagurile individual
      if (flags & MBEDTLS_X509_BADCERT_EXPIRED)
        Serial.println("[DIAG]   → Certificat EXPIRAT");
      if (flags & MBEDTLS_X509_BADCERT_NOT_TRUSTED)
        Serial.println("[DIAG]   → Certificat NU ESTE DE INCREDERE (issuer "
                       "mismatch!)");
      if (flags & MBEDTLS_X509_BADCERT_FUTURE)
        Serial.println("[DIAG]   → Certificat NOT YET VALID (viitor)");
      if (flags & MBEDTLS_X509_BADCRL_EXPIRED)
        Serial.println("[DIAG]   → CRL expirat");
      if (flags & MBEDTLS_X509_BADCERT_BAD_KEY)
        Serial.println("[DIAG]   → Cheie invalida");
      if (flags & MBEDTLS_X509_BADCERT_BAD_MD)
        Serial.println("[DIAG]   → Algoritm hash slab");
    }
  } else {
    Serial.println("[DIAG] Nu se poate verifica — eroare la parsare CA sau "
                   "Client cert.");
  }

  // ── 5. Verificare ceas sistem vs certificate ────────────────
  Serial.println("\n── CEAS SISTEM VS CERTIFICATE ──────────────────────");
  time_t now = time(NULL);
  char tbuf[30];
  strftime(tbuf, sizeof(tbuf), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
  Serial.printf("[DIAG] Timp sistem UTC : %s (epoch: %ld)\n", tbuf,
                (long)now);

  if (ret_ca == 0) {
    time_t ca_from = mbedtlsX509TimeToTimeT(ca_crt.valid_from);
    time_t ca_to = mbedtlsX509TimeToTimeT(ca_crt.valid_to);
    Serial.printf("[DIAG] CA valid window : %ld → %ld\n", (long)ca_from,
                  (long)ca_to);
    if (now < ca_from)
      Serial.println("[DIAG] ⚠ Ceasul e INAINTE de validitatea CA!");
    else if (now > ca_to)
      Serial.println("[DIAG] ⚠ CA-ul a EXPIRAT!");
    else
      Serial.println("[DIAG] ✓ Ceasul este in fereastra de validitate a CA.");
  }

  if (ret_cli == 0) {
    time_t cli_from = mbedtlsX509TimeToTimeT(cli_crt.valid_from);
    time_t cli_to = mbedtlsX509TimeToTimeT(cli_crt.valid_to);
    Serial.printf("[DIAG] Client valid    : %ld → %ld\n", (long)cli_from,
                  (long)cli_to);
    double days_left = difftime(cli_to, now) / 86400.0;
    Serial.printf("[DIAG] Client zile ramase: %.2f\n", days_left);
    if (now < cli_from)
      Serial.println("[DIAG] ⚠ Ceasul e INAINTE de validitatea Client cert!");
    else if (now > cli_to)
      Serial.println("[DIAG] ⚠ Client cert EXPIRAT!");
    else
      Serial.println(
          "[DIAG] ✓ Client cert valid la momentul curent.");
  }

  // ── 6. Fingerprint SHA-256 CA (primii 8 bytes) ─────────────
  if (ret_ca == 0) {
    Serial.println("\n── CA FINGERPRINT (SHA-256, primii 16 hex) ─────────");
    uint8_t hash[32];
    mbedtls_sha256(ca_crt.raw.p, ca_crt.raw.len, hash, 0);
    char fp[48];
    for (int i = 0; i < 8; i++)
      snprintf(fp + i * 3, 4, "%02X:", hash[i]);
    fp[23] = '\0';
    Serial.printf("[DIAG] CA SHA256: %s\n", fp);
  }

  // ── 7. Info conexiune target ────────────────────────────────
  Serial.println("\n── TARGET GATEWAY ──────────────────────────────────");
  Serial.printf("[DIAG] Host : %s\n", gateway_host);
  Serial.printf("[DIAG] Port : %d\n", gateway_port);
  Serial.printf("[DIAG] Path : %s\n", gateway_path);

  mbedtls_x509_crt_free(&cli_crt);
  mbedtls_x509_crt_free(&ca_crt);

  Serial.println("\n══════════════════════════════════════════════════════");
  Serial.println("[DIAG] Diagnostic complet. Daca CA → Client este OK,");
  Serial.println("       dar TLS tot esueaza, problema este ca NGINX");
  Serial.println("       prezinta un certificat SERVER semnat de alt CA.");
  Serial.println("       Verificati ca nginx.conf foloseste acelasi CA!");
  Serial.println("══════════════════════════════════════════════════════\n");
}

bool generateCsrBase64(String &out_csr_base64, String &out_priv_key_pem) {
  int ret;
  mbedtls_pk_context key;
  mbedtls_ctr_drbg_context ctr;
  mbedtls_entropy_context entropy;
  mbedtls_x509write_csr req;

  mbedtls_pk_init(&key);
  mbedtls_ctr_drbg_init(&ctr);
  mbedtls_entropy_init(&entropy);
  mbedtls_x509write_csr_init(&req);

  const char *pers = "csr_gen";
  ret = mbedtls_ctr_drbg_seed(&ctr, mbedtls_entropy_func, &entropy,
                              (const unsigned char *)pers, strlen(pers));
  if (ret != 0)
    goto cleanup_csr;

  ret = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
  if (ret != 0)
    goto cleanup_csr;

  ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(key), mbedtls_ctr_drbg_random, &ctr,
                            CSR_KEY_BITS, 65537);
  if (ret != 0)
    goto cleanup_csr;

  {
    char private_key_buf[4096];
    ret = mbedtls_pk_write_key_pem(&key, (unsigned char *)private_key_buf,
                                   sizeof(private_key_buf));
    if (ret != 0)
      goto cleanup_csr;

    String terminalId = getTerminalId();
    String subject = "CN=" + terminalId + ",O=POS,OU=Terminal,C=RO";

    mbedtls_x509write_csr_set_md_alg(&req, MBEDTLS_MD_SHA256);
    mbedtls_x509write_csr_set_key(&req, &key);
    ret = mbedtls_x509write_csr_set_subject_name(&req, subject.c_str());
    if (ret != 0)
      goto cleanup_csr;

    char csr_pem[4096];
    ret = mbedtls_x509write_csr_pem(&req, (unsigned char *)csr_pem,
                                    sizeof(csr_pem), mbedtls_ctr_drbg_random,
                                    &ctr);
    if (ret != 0)
      goto cleanup_csr;

    out_priv_key_pem = String(private_key_buf);
    out_csr_base64 = base64Encode((const uint8_t *)csr_pem, strlen(csr_pem));
    if (out_csr_base64.length() == 0)
      goto cleanup_csr;
  }

  mbedtls_x509write_csr_free(&req);
  mbedtls_pk_free(&key);
  mbedtls_ctr_drbg_free(&ctr);
  mbedtls_entropy_free(&entropy);
  return true;

cleanup_csr:
  mbedtls_x509write_csr_free(&req);
  mbedtls_pk_free(&key);
  mbedtls_ctr_drbg_free(&ctr);
  mbedtls_entropy_free(&entropy);
  return false;
}

bool postCsrAndStoreNewCert(const String &csr_base64, const String &newKeyPem) {
  JsonDocument bodyDoc;
  bodyDoc["csr_pem_b64"] = csr_base64;
  String body;
  serializeJson(bodyDoc, body);

  HTTPClient http;
  secureClient.setTimeout(HTTP_TIMEOUT_MS);
  http.setTimeout(HTTP_TIMEOUT_MS);
  http.begin(secureClient, gateway_host, gateway_port, pki_renew_path);
  http.addHeader("Content-Type", "application/json");
  http.addHeader("X-Terminal-Id", getTerminalId());

  int code = http.POST(body);
  String resp = http.getString();
  Serial.printf("[PKI] renew POST code=%d\n", code);
  http.end();

  if (code != 200)
    return false;

  JsonDocument doc;
  if (deserializeJson(doc, resp))
    return false;

  String cert_b64 = jsonGetString(doc["certificate_pem_b64"]);
  String ca_b64 = jsonGetString(doc["ca_certificate_pem_b64"]);
  if (cert_b64.length() == 0 || ca_b64.length() == 0)
    return false;

  std::vector<uint8_t> cert_decoded, ca_decoded;
  if (!base64Decode(cert_b64, cert_decoded) ||
      !base64Decode(ca_b64, ca_decoded))
    return false;

  String certPem((char *)cert_decoded.data(), cert_decoded.size());
  String caPem((char *)ca_decoded.data(), ca_decoded.size());

  if (!storeClientCredentialsToNVS(certPem, newKeyPem))
    return false;
  if (!storeRootCaToNVS(caPem))
    return false;

  current_client_cert_pem = certPem;
  current_client_key_pem = newKeyPem;
  current_root_ca_pem = caPem;

  secureClient.setCACert(current_root_ca_pem.c_str());
  secureClient.setCertificate(current_client_cert_pem.c_str());
  secureClient.setPrivateKey(current_client_key_pem.c_str());

  g_terminalId = extractCertCN(current_client_cert_pem);
  return true;
}

bool runPkiRenewCheckIfNeeded() {
  if (g_deviceState == STATE_BRICKED_PENDING_MANUAL_RESET) {
    Serial.println("[PKI] Device bricked — skip PKI check");
    return false;
  }

  time_t now = time(NULL);
  if (now == (time_t)-1) {
    Serial.println("[PKI] Timp invalid — skip PKI check");
    return false;
  }

  time_t not_after;
  if (!getCertExpiry(current_client_cert_pem.c_str(), not_after)) {
    Serial.println("[PKI] Nu pot parsa expirarea certificatului");
    return false;
  }

  double daysUntilExpiry = difftime(not_after, now) / 86400.0;
  Serial.printf("[PKI] Cert expira in %.2f zile\n", daysUntilExpiry);

  if (daysUntilExpiry > RENEW_DAYS_BEFORE)
    return true;

  showMessage("Reinnoire cert", "Asteptati...");
  String csr_b64, newKeyPem;
  if (!generateCsrBase64(csr_b64, newKeyPem)) {
    Serial.println("[PKI] Eroare generare CSR");
    int failures = getRenewFailures() + 1;
    setRenewFailures(failures);
    if (failures >= RENEW_MAX_FAILURES) {
      setDeviceState(STATE_BRICKED_PENDING_MANUAL_RESET);
      showMessage("Terminal BLOCAT", "Reset necesar");
    }
    return false;
  }

  if (!postCsrAndStoreNewCert(csr_b64, newKeyPem)) {
    Serial.println("[PKI] Eroare reinnoire cert de la gateway");
    int failures = getRenewFailures() + 1;
    setRenewFailures(failures);
    if (failures >= RENEW_MAX_FAILURES) {
      setDeviceState(STATE_BRICKED_PENDING_MANUAL_RESET);
      showMessage("Terminal BLOCAT", "Reset necesar");
    }
    return false;
  }

  setRenewFailures(0);
  setDeviceState(STATE_OK);
  showMessage("Cert reinnoit", nullptr);
  delay(1000);
  return true;
}

// ============================================================
// CRIPTARE PIN BLOCK (RSA-OAEP SHA256)
// ============================================================

// Construieste "{transaction_id}:{pin}", cripteaza cu cheia publica
// a bancii folosind RSA-OAEP SHA256, returneaza Base64.
String encryptPinBlockAndBase64(const String &transaction_id,
                                const String &pin) {
  String plain = transaction_id + ":" + pin;

  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);
  if (current_bank_pub_pem.length() == 0) {
    Serial.println("[PIN] EROARE: bank_pub_pem nu este incarcat din NVS!");
    mbedtls_pk_free(&pk);
    return String();
  }
  int ret = mbedtls_pk_parse_public_key(
      &pk, (const unsigned char *)current_bank_pub_pem.c_str(),
      current_bank_pub_pem.length() + 1);
  if (ret != 0) {
    mbedtls_pk_free(&pk);
    return String();
  }
  if (mbedtls_pk_get_type(&pk) != MBEDTLS_PK_RSA) {
    mbedtls_pk_free(&pk);
    return String();
  }

  mbedtls_rsa_context *rsa = mbedtls_pk_rsa(pk);
  mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr;
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr);
  const char *pers = "rsa_oaep_enc";
  ret = mbedtls_ctr_drbg_seed(&ctr, mbedtls_entropy_func, &entropy,
                              (const unsigned char *)pers, strlen(pers));
  if (ret != 0) {
    mbedtls_ctr_drbg_free(&ctr);
    mbedtls_entropy_free(&entropy);
    mbedtls_pk_free(&pk);
    return String();
  }

  size_t key_len = mbedtls_pk_get_len(&pk);
  std::vector<unsigned char> out(key_len);
  ret = mbedtls_rsa_rsaes_oaep_encrypt(
      rsa, mbedtls_ctr_drbg_random, &ctr, MBEDTLS_RSA_PUBLIC, NULL, 0,
      plain.length(), (const unsigned char *)plain.c_str(), out.data());
  mbedtls_ctr_drbg_free(&ctr);
  mbedtls_entropy_free(&entropy);
  mbedtls_pk_free(&pk);

  if (ret != 0)
    return String();

  size_t olen = 0;
  mbedtls_base64_encode(NULL, 0, &olen, out.data(), out.size());
  std::vector<unsigned char> b64(olen + 1);
  if (mbedtls_base64_encode(b64.data(), b64.size(), &olen, out.data(),
                            out.size()) != 0) {
    return String();
  }
  b64[olen] = '\0';
  return String((char *)b64.data());
}

// ============================================================
// COLECTARE PIN DE LA KEYPAD
// ============================================================

String collectPin(int maxDigits = PIN_MAX_DIGITS,
                  unsigned long timeoutMs = 30000) {
  showMessage("Introdu PIN:", "----");
  String pin = "";
  unsigned long start = millis();

  while ((millis() - start) < timeoutMs) {
    char k = keypad.getKey();
    if (k) {
      if (k >= '0' && k <= '9') {
        if (pin.length() < (size_t)maxDigits)
          pin += k;
      } else if (k == '#') {
        if ((int)pin.length() >= PIN_MIN_LENGTH)
          break;
      } else if (k == '*') {
        if (pin.length() > 0)
          pin.remove(pin.length() - 1);
      }
      char masked[16] = {0};
      for (size_t i = 0; i < pin.length() && i < sizeof(masked) - 1; ++i)
        masked[i] = '*';
      showMessage("Introdu PIN:", masked);
    }
    delay(50);
  }
  return pin;
}

// ============================================================
// CERERE CHALLENGE (Step-Up PIN)
// ============================================================

// Trimite PIN block criptat la /api/v1/payments/challenge.
// Returneaza HTTP status code (200=aprobat, 400=PIN gresit, 403=blocat).
// Reincercarile se fac doar pentru erori de retea (429/503).
int sendChallengeRequestWithPin(const String &transaction_id,
                                const String &original_dpan,
                                const String &pin) {
  const int base_delay = 1000;
  const int cap_delay = 10000;
  const int max_retries = 3;

  if (transaction_id.length() == 0 || original_dpan.length() == 0) {
    Serial.println("[CHALLENGE] transaction_id sau original_dpan lipsa");
    return -1;
  }

  // UUID NOU diferit de cel al tranzactiei originale (spec 1.6)
  String idempotencyNew = generateUuidV4();
  String terminalId = getTerminalId();

  String pin_block_b64 = encryptPinBlockAndBase64(transaction_id, pin);
  if (pin_block_b64.length() == 0) {
    Serial.println("[CHALLENGE] Eroare criptare PIN block");
    return -1;
  }

  // JsonDocument (v7) pentru a acomoda base64 RSA-OAEP (~344 chars)
  JsonDocument bodyDoc;
  bodyDoc["transaction_id"] = transaction_id;
  bodyDoc["original_dpan"] = original_dpan;
  bodyDoc["pin_block_encrypted"] = pin_block_b64;
  String body;
  serializeJson(bodyDoc, body);

  for (int attempt = 0; attempt <= max_retries; ++attempt) {
    HTTPClient http;
    secureClient.setTimeout(HTTP_TIMEOUT_MS);
    http.setTimeout(HTTP_TIMEOUT_MS);
    http.begin(secureClient, gateway_host, gateway_port, challenge_path);
    http.addHeader("Content-Type", "application/json");
    http.addHeader("X-Idempotency-Key", idempotencyNew);
    http.addHeader("X-Terminal-Id", terminalId);

    int code = http.POST(body);
    String resp = http.getString();
    Serial.printf("[CHALLENGE] attempt=%d code=%d\n", attempt, code);
    
    int server_retry_after_ms = -1;
    if (code > 0) {
      JsonDocument doc;
      DeserializationError err = deserializeJson(doc, resp);
      if (!err) {
        if (doc["retry_after_ms"].is<int>()) {
          server_retry_after_ms = doc["retry_after_ms"].as<int>();
        } else if (doc["detail"]["retry_after_ms"].is<int>()) {
          server_retry_after_ms = doc["detail"]["retry_after_ms"].as<int>();
        }
      }
    }
    
    http.end();

    if (code == 200 || code == 400 || code == 403)
      return code;

    if (isRetryableStatus(code)) {
      if (attempt == max_retries)
        return code;
      int wait = computeBackoffMs(attempt, base_delay, cap_delay);
      if (server_retry_after_ms > 0 && server_retry_after_ms > wait) {
        Serial.printf("[CHALLENGE] Override delay cu retry_after_ms recomandat de server: %d ms (jitter-ul calculat era %d ms)\n", server_retry_after_ms, wait);
        wait = server_retry_after_ms;
      }
      Serial.printf("[CHALLENGE] retry in %d ms\n", wait);
      delay(wait);
      continue;
    }

    return code;
  }
  return -1;
}

// ============================================================
// AUTORIZARE LA GATEWAY (cu Exponential Backoff Full Jitter)
// ============================================================

// Gestioneaza intregul flux authorize: trimite payload, interpreteaza
// raspunsul, declanseaza Step-Up PIN daca e nevoie, face retry la erori
// tranzitorii. Idempotency key ramane acelasi la fiecare retry.
void sendRequestWithBackoff(const String &payload, int amountCents) {
  const int base_delay = 1000;
  const int cap_delay = 10000;
  const int max_retries = 3; // spec: maxim 3 reincercari

  if (g_deviceState == STATE_BRICKED_PENDING_MANUAL_RESET) {
    showMessage("Terminal BLOCAT", "Reset necesar");
    Serial.println("[DEBUG-AUTH] Eroare: Terminalul este blocat de securitate. "
                   "Apelul de autorizare a fost anulat.");
    return;
  }

  // Idempotency key generat O SINGURA DATA — refolosit la fiecare retry
  String idempotencyKey = generateUuidV4();
  String terminalId = getTerminalId();

  Serial.println("\n=======================================================");
  Serial.printf("[DEBUG-AUTH] Initiere tranzactie de %d.%02d RON\n",
                amountCents / 100, amountCents % 100);
  Serial.printf("[DEBUG-AUTH] Terminal ID: %s\n", terminalId.c_str());
  Serial.printf("[DEBUG-AUTH] Idempotency Key: %s\n", idempotencyKey.c_str());
  Serial.printf("[DEBUG-AUTH] Payload JSON:\n%s\n", payload.c_str());
  Serial.println("=======================================================");

  for (int attempt = 0; attempt <= max_retries; ++attempt) {
    int server_retry_after_ms = -1;
    HTTPClient http;
    secureClient.setTimeout(HTTP_TIMEOUT_MS);
    http.setTimeout(HTTP_TIMEOUT_MS);
    http.begin(secureClient, gateway_host, gateway_port, gateway_path);
    http.addHeader("Content-Type", "application/json");
    http.addHeader("X-Idempotency-Key", idempotencyKey);
    http.addHeader("X-Terminal-Id", terminalId);

    showTransaction(amountCents, "Procesare...");
    Serial.printf(
        "[DEBUG-AUTH] [Incercarea %d/%d] Se trimite POST la %s:%d%s...\n",
        attempt + 1, max_retries + 1, gateway_host, gateway_port, gateway_path);

    // Diagnostic: afisam timpul curent inainte de TLS handshake
    // Daca time_t < 1000000000, inseamna ca NTP a esuat si mbedTLS va
    // respinge certificatul NGINX cu X509_CERT_VERIFY_FAILED (-9984)
    time_t pre_tls_time = time(NULL);
    Serial.printf("[DEBUG-AUTH] Ceas sistem inainte de TLS: %ld (%s)\n",
                  (long)pre_tls_time,
                  pre_tls_time > 1000000000 ? "VALID" : "INVALID — EPOCH 1970!");
    if (pre_tls_time > 1000000000) {
      char tbuf[30];
      strftime(tbuf, sizeof(tbuf), "%Y-%m-%dT%H:%M:%SZ", gmtime(&pre_tls_time));
      Serial.printf("[DEBUG-AUTH] Timp UTC: %s\n", tbuf);
    }

    // Verificare rapida ca certificatele sunt inca configurate
    Serial.printf("[DEBUG-AUTH] CA PEM loaded: %d bytes\n",
                  (int)current_root_ca_pem.length());
    Serial.printf("[DEBUG-AUTH] Client cert loaded: %d bytes\n",
                  (int)current_client_cert_pem.length());
    Serial.printf("[DEBUG-AUTH] Client key loaded: %d bytes\n",
                  (int)current_client_key_pem.length());
    if (current_root_ca_pem.length() == 0 ||
        current_client_cert_pem.length() == 0 ||
        current_client_key_pem.length() == 0) {
      Serial.println("[DEBUG-AUTH] ⚠ EROARE CRITICA: Certificate goale!");
    }

    int httpCode = http.POST(payload);
    String body = http.getString();

    Serial.printf("[DEBUG-AUTH] [Incercarea %d/%d] Cod raspuns HTTP: %d\n",
                  attempt + 1, max_retries + 1, httpCode);
    if (httpCode > 0) {
      Serial.printf("[DEBUG-AUTH] Corp raspuns: %s\n", body.c_str());
    } else {
      Serial.printf("[DEBUG-AUTH] Eroare retea / Timeout! (%s)\n",
                    http.errorToString(httpCode).c_str());
    }

    if (httpCode > 0) {
      JsonDocument doc;
      DeserializationError err = deserializeJson(doc, body);
      if (!err) {
        if (doc["retry_after_ms"].is<int>()) {
          server_retry_after_ms = doc["retry_after_ms"].as<int>();
        } else if (doc["detail"]["retry_after_ms"].is<int>()) {
          server_retry_after_ms = doc["detail"]["retry_after_ms"].as<int>();
        }
      }
    }

    bool retryable = false;

    if (httpCode == 200) {
      JsonDocument doc;
      DeserializationError err = deserializeJson(doc, body);
      String status = "";
      if (!err && doc["status"].is<const char *>())
        status = jsonGetString(doc["status"]);

      Serial.printf("[DEBUG-AUTH] Status deserializat: %s\n", status.c_str());

      if (status == "APPROVED") {
        Serial.println(
            "[DEBUG-AUTH] Rezultat: APROBAT de Gateway. Tranzactie reusita!");
        showTransaction(amountCents, "APROBAT");
        feedbackPulse();
        http.end();
        return;
      }

      if (status == "DECLINED") {
        String reason = doc["detail"]["error_code"] | "";
        Serial.printf("[DEBUG-AUTH] Rezultat: REFUZAT de Gateway. Motiv: %s\n",
                      reason.c_str());
        if (reason == "INSUFFICIENT_FUNDS")
          showTransaction(amountCents, "Fonduri insuf.");
        else
          showTransaction(amountCents, "REFUZAT");
        http.end();
        return;
      }

      if (status == "CHALLENGE_REQUIRED") {
        String tx_id = doc["transaction_id"] | "";
        String orig_dpan = doc["original_dpan"] | "";
        if (orig_dpan.length() == 0) {
          orig_dpan = g_tx.dpan;
        }
        http.end();

        Serial.printf("[DEBUG-AUTH] Rezultat: CHALLENGE_REQUIRED. Tx ID: %s\n",
                      tx_id.c_str());

        if (tx_id.length() == 0 || orig_dpan.length() == 0) {
          Serial.println("[DEBUG-AUTH] Eroare: Datele de challenge lipsesc din "
                         "raspuns 200!");
          showMessage("Eroare challenge", "Date lipsa");
          return;
        }
        int pin_attempts = 0;

        while (pin_attempts < 3) {
          if (pin_attempts > 0) {
            char attempt_msg[32];
            snprintf(attempt_msg, sizeof(attempt_msg), "Incercarea %d/3", pin_attempts + 1);
            showMessage("PIN incorect", attempt_msg);
            delay(2000);
          }
          showMessage("PIN necesar", "Conf. cu #");
          Serial.printf("[DEBUG-AUTH] Se asteapta introducerea PIN-ului pe tastatura (incercarea %d/3)...\n", pin_attempts + 1);
          String pin = collectPin(PIN_MAX_DIGITS, 30000);
          if ((int)pin.length() < PIN_MIN_LENGTH) {
            Serial.println("[DEBUG-AUTH] Timeout PIN sau PIN prea scurt!");
            showMessage("Timeout PIN", nullptr);
            return;
          }

          Serial.println("[DEBUG-AUTH] PIN colectat cu succes. Se trimite cerere challenge la gateway...");
          int challCode = sendChallengeRequestWithPin(tx_id, orig_dpan, pin);
          Serial.printf("[DEBUG-AUTH] Cod raspuns challenge de la gateway: %d\n", challCode);

          if (challCode == 200) {
            Serial.println("[DEBUG-AUTH] Challenge REUSIT! Tranzactie aprobata.");
            showTransaction(amountCents, "APROBAT");
            feedbackPulse();
            return; // Terminate function successfully on success
          } else if (challCode == 400) {
            Serial.println("[DEBUG-AUTH] Challenge ESUAT: PIN incorect!");
            pin_attempts++;
            continue;
          } else if (challCode == 403) {
            Serial.println("[DEBUG-AUTH] Challenge ESUAT: Card blocat!");
            showMessage("Card blocat", "Contact banca");
            return;
          } else {
            retryable = isRetryableStatus(challCode);
            Serial.printf("[DEBUG-AUTH] Challenge eroare sistem. Retryable: %s\n",
                          retryable ? "DA" : "NU");
            if (!retryable) {
              showTransaction(amountCents, "Eroare PIN");
              return;
            }
            showTransaction(amountCents, "Eroare retea PIN");
            return;
          }
        }

        // Loop finished normally (attempts reached 3 without success)
        Serial.println("[DEBUG-AUTH] S-au epuizat incercarile de PIN local.");
        showMessage("PIN incorect", "Card blocat?");
        return;
      } else {
        Serial.printf("[DEBUG-AUTH] Avertisment: Status necunoscut in HTTP "
                      "200: %s. Se incearca reincercarea tranzactiei.\n",
                      status.c_str());
        retryable = true;
      }

    } else if (httpCode == 401) {
      JsonDocument doc;
      DeserializationError err = deserializeJson(doc, body);

      String transaction_id = "";
      String original_dpan = "";
      if (!err) {
        JsonVariantConst detail = doc["detail"];
        if (!detail.isNull()) {
          transaction_id = jsonGetString(detail["transaction_id"]);
          original_dpan = jsonGetString(detail["original_dpan"]);
        }
      }
      if (original_dpan.length() == 0) {
        original_dpan = g_tx.dpan;
      }
      http.end();

      Serial.printf(
          "[DEBUG-AUTH] HTTP 401 primiti: CHALLENGE_REQUIRED. Tx ID: %s, DPAN: "
          "...%s\n",
          transaction_id.c_str(),
          original_dpan.substring(max(0, (int)original_dpan.length() - 4))
              .c_str());

      if (transaction_id.length() == 0 || original_dpan.length() == 0) {
        Serial.println("[DEBUG-AUTH] Eroare: Datele de challenge lipsesc in "
                       "raspunsul 401!");
        showMessage("Eroare 401", "Date lipsa");
        return;
      }
      int pin_attempts = 0;

      while (pin_attempts < 3) {
        if (pin_attempts > 0) {
          char attempt_msg[32];
          snprintf(attempt_msg, sizeof(attempt_msg), "Incercarea %d/3", pin_attempts + 1);
          showMessage("PIN incorect", attempt_msg);
          delay(2000);
        }
        showMessage("PIN necesar", "Conf. cu #");
        Serial.printf("[DEBUG-AUTH] Se asteapta introducerea PIN-ului pe tastatura (incercarea %d/3)...\n", pin_attempts + 1);
        String pin = collectPin(PIN_MAX_DIGITS, 30000);
        if ((int)pin.length() < PIN_MIN_LENGTH) {
          Serial.println("[DEBUG-AUTH] Timeout PIN sau PIN prea scurt!");
          showMessage("Timeout PIN", nullptr);
          return;
        }

        Serial.println("[DEBUG-AUTH] PIN colectat. Se trimite cererea de challenge la gateway...");
        int challCode =
            sendChallengeRequestWithPin(transaction_id, original_dpan, pin);
        Serial.printf("[DEBUG-AUTH] Cod raspuns challenge de la gateway: %d\n",
                      challCode);

        if (challCode == 200) {
          Serial.println("[DEBUG-AUTH] Challenge REUSIT! Tranzactie aprobata.");
          showTransaction(amountCents, "APROBAT");
          feedbackPulse();
          return; // Terminate function successfully on success
        } else if (challCode == 400) {
          Serial.println("[DEBUG-AUTH] Challenge ESUAT: PIN incorect!");
          pin_attempts++;
          continue;
        } else if (challCode == 403) {
          Serial.println("[DEBUG-AUTH] Challenge ESUAT: Card blocat!");
          showMessage("Card blocat", "Contact banca");
          return;
        } else {
          retryable = isRetryableStatus(challCode);
          Serial.printf("[DEBUG-AUTH] Challenge eroare. Retryable: %s\n",
                        retryable ? "DA" : "NU");
          if (!retryable) {
            showTransaction(amountCents, "Eroare PIN");
            return;
          }
          showTransaction(amountCents, "Eroare retea PIN");
          return;
        }
      }

      // Loop finished normally (attempts reached 3 without success)
      Serial.println("[DEBUG-AUTH] S-au epuizat incercarile de PIN local.");
      showMessage("PIN incorect", "Card blocat?");
      return;

    } else if (httpCode == 400) {
      JsonDocument doc;
      deserializeJson(doc, body);
      String errCode = doc["detail"]["error_code"] | "UNKNOWN";
      Serial.printf("[DEBUG-AUTH] Eroare definitiva HTTP 400: %s\n",
                    errCode.c_str());
      if (errCode == "INSUFFICIENT_FUNDS")
        showTransaction(amountCents, "Fonduri insuf.");
      else if (errCode == "INVALID_CRYPTOGRAM")
        showTransaction(amountCents, "Criptograma inv.");
      else
        showTransaction(amountCents, ("Err:" + errCode).c_str());
      http.end();
      return;

    } else if (httpCode == 403) {
      Serial.println("[DEBUG-AUTH] Eroare definitiva HTTP 403: Card blocat!");
      showMessage("Card blocat", "Contact banca");
      http.end();
      return;

    } else if (isRetryableStatus(httpCode)) {
      Serial.printf("[DEBUG-AUTH] Eroare tranzitorie / temporara: %d. Este "
                    "posibila reincercarea.\n",
                    httpCode);
      retryable = true;

    } else {
      Serial.printf(
          "[DEBUG-AUTH] Eroare sistem necunoscuta: %d. Corp raspuns: %s\n",
          httpCode, body.c_str());
      showTransaction(amountCents, "Eroare sistem");
      http.end();
      return;
    }

    http.end();

    if (!retryable || attempt == max_retries) {
      Serial.println("[DEBUG-AUTH] S-au epuizat incercarile sau eroarea nu "
                     "permite reincercarea.");
      showTransaction(amountCents, "Eroare sistem");
      return;
    }

    int wait = computeBackoffMs(attempt, base_delay, cap_delay);
    if (server_retry_after_ms > 0 && server_retry_after_ms > wait) {
      Serial.printf("[DEBUG-AUTH] Override delay cu retry_after_ms recomandat de server: %d ms (jitter-ul calculat era %d ms)\n", server_retry_after_ms, wait);
      wait = server_retry_after_ms;
    }
    char buf[32];
    snprintf(buf, sizeof(buf), "Retry %ds", wait / 1000);
    showTransaction(amountCents, buf);
    Serial.printf(
        "[DEBUG-AUTH] Reincercare in %d ms (Incercarea %d terminata)\n", wait,
        attempt + 1);
    delay(wait);
  }

  showTransaction(amountCents, "Eroare sistem");
}

// ============================================================
// NFC — pastrat pentru compatibilitate (modulul e defect)
// ============================================================

bool sendNfcCommand(const uint8_t *command, uint8_t commandLen,
                    uint8_t *response, uint8_t *responseLength) {
  return nfc.inDataExchange(const_cast<uint8_t *>(command), commandLen,
                            response, responseLength);
}

bool appendTlv(uint8_t *buffer, int &offset, uint8_t tag, const uint8_t *value,
               int length) {
  if (offset + 2 + length > GPO_MAX_PAYLOAD)
    return false;
  buffer[offset++] = tag;
  buffer[offset++] = (uint8_t)length;
  memcpy(buffer + offset, value, length);
  offset += length;
  return true;
}

bool buildEmvGpoPayload(int amountCents, const String &currency,
                        const String &timestamp, const String &posNonce,
                        uint8_t *outData, int &outLen) {
  outLen = 0;
  char amountBuf[16];
  snprintf(amountBuf, sizeof(amountBuf), "%d", amountCents);
  if (!appendTlv(outData, outLen, 0x9F, (const uint8_t *)amountBuf,
                 strlen(amountBuf)))
    return false;
  if (!appendTlv(outData, outLen, 0x5F, (const uint8_t *)currency.c_str(),
                 currency.length()))
    return false;
  if (!appendTlv(outData, outLen, 0xDF, (const uint8_t *)timestamp.c_str(),
                 timestamp.length()))
    return false;
  if (!appendTlv(outData, outLen, 0xE0, (const uint8_t *)posNonce.c_str(),
                 posNonce.length()))
    return false;
  return true;
}

// ============================================================
// SERVER HTTP LOCAL — WiFi Direct
//
// POST /initiate         ← dashboard trimite amount_cents; ESP32 creeaza
// tranzactia GET  /payment-request  → trimite datele tranzactiei active la
// telefon POST /payment-response ← primeste DPAN + ATC + MAC de la telefon
// ============================================================

void setupLocalServer() {
  // POST /initiate
  // Dashboard-ul (sau aplicatia) initiaza o tranzactie noua cu suma dorita.
  // Body JSON: {"amount_cents": 1500, "currency": "RON"}  (currency optional)
  // Raspuns:
  // {"status":"OK","pos_nonce":"...","terminal_timestamp":"...","terminal_id":"..."}
  localServer.on(
      "/initiate", HTTP_POST, [](AsyncWebServerRequest *request) {}, nullptr,
      [](AsyncWebServerRequest *request, uint8_t *data, size_t len,
         size_t index, size_t total) {
        if (g_tx.state != POS_IDLE) {
          request->send(409, "application/json",
                        "{\"error\":\"Transaction already in progress\"}");
          return;
        }

        JsonDocument doc;
        if (deserializeJson(doc, data, len)) {
          request->send(400, "application/json",
                        "{\"error\":\"Invalid JSON\"}");
          return;
        }

        int amountCents = doc["amount_cents"] | -1;
        String currency = doc["currency"] | "RON";

        if (amountCents <= 0) {
          request->send(400, "application/json",
                        "{\"error\":\"amount_cents must be > 0\"}");
          return;
        }

        g_tx.amountCents = amountCents;
        g_tx.currency = currency;
        g_tx.posNonce = generatePosNonce();
        g_tx.terminalTimestamp = getIsoTimestamp();
        g_tx.state = POS_WAITING_FOR_PHONE;
        g_tx.stateEnteredAt = millis();

        Serial.printf("[POS] Tranzactie initiata din dashboard: %d.%02d RON"
                      " | Nonce: %s | Timp: %s\n",
                      g_tx.amountCents / 100, g_tx.amountCents % 100,
                      g_tx.posNonce.c_str(), g_tx.terminalTimestamp.c_str());

        showTransaction(g_tx.amountCents, "Apropiati tel.");

        JsonDocument resp;
        resp["status"] = "OK";
        resp["pos_nonce"] = g_tx.posNonce;
        resp["terminal_timestamp"] = g_tx.terminalTimestamp;
        resp["terminal_id"] = getTerminalId();
        String body;
        serializeJson(resp, body);
        request->send(200, "application/json", body);
      });

  // GET /payment-request
  // Telefonul polleaza acest endpoint pana primeste status PENDING
  localServer.on(
      "/payment-request", HTTP_GET, [](AsyncWebServerRequest *request) {
        JsonDocument doc;

        if (g_tx.state == POS_WAITING_FOR_PHONE) {
          // Verifica timeout 30s intern (duplicat cu cel din loop())
          if (millis() - g_tx.stateEnteredAt > PHONE_WAIT_TIMEOUT_MS) {
            g_tx = PendingTransaction{};
            doc["status"] = "IDLE";
          } else {
            doc["status"] = "PENDING";
            doc["amount"] = g_tx.amountCents;
            doc["currency"] = g_tx.currency;
            doc["pos_nonce"] = g_tx.posNonce;
            doc["terminal_timestamp"] = g_tx.terminalTimestamp;
            doc["terminal_id"] = getTerminalId();
          }
        } else {
          doc["status"] = "IDLE";
        }

        String body;
        serializeJson(doc, body);
        request->send(200, "application/json", body);
      });

  // POST /payment-response
  // Telefonul trimite DPAN + ATC + MAC dupa ce a calculat criptograma
  localServer.on(
      "/payment-response", HTTP_POST, [](AsyncWebServerRequest *request) {},
      nullptr,
      [](AsyncWebServerRequest *request, uint8_t *data, size_t len,
         size_t index, size_t total) {
        if (g_tx.state != POS_WAITING_FOR_PHONE) {
          request->send(409, "application/json",
                        "{\"error\":\"No active transaction\"}");
          return;
        }

        JsonDocument doc;
        if (deserializeJson(doc, data, len)) {
          request->send(400, "application/json",
                        "{\"error\":\"Invalid JSON\"}");
          return;
        }

        String dpan = doc["dpan"] | "";
        int atc = doc["atc"] | -1;
        String mac = doc["mac"] | "";

        // Validare: DPAN prezent, ATC >= 0, MAC hex lowercase 64 chars
        if (dpan.length() == 0 || atc < 0 || mac.length() != 64 ||
            !isHexString(mac)) {
          request->send(400, "application/json",
                        "{\"error\":\"Invalid fields\"}");
          return;
        }

        g_tx.dpan = dpan;
        g_tx.atc = atc;
        g_tx.mac = mac;
        g_tx.state = POS_PROCESSING;

        Serial.printf("[WiFi] Date primite de la telefon: DPAN=...%s ATC=%d\n",
                      dpan.substring(max(0, (int)dpan.length() - 4)).c_str(),
                      atc);

        request->send(200, "application/json", "{\"status\":\"ACCEPTED\"}");
      });

  localServer.begin();
  Serial.printf("[HTTP-local] Server pornit: http://%s:80\n",
                WiFi.localIP().toString().c_str());
}

// ============================================================
// SETUP
// ============================================================

void setup() {
  Serial.begin(115200);
  delay(300);
  Serial.println("\n=== POS Terminal WiFi Direct — Boot ===");

  randomSeed(esp_random());
  setup_registru_hardware();

  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, LOW);
  pinMode(HAPTIC_PIN, OUTPUT);
  digitalWrite(HAPTIC_PIN, LOW);

  uint16_t ID = tft.readID();
  Serial.print("[TFT] Driver detectat: 0x");
  Serial.println(ID, HEX);
  if (ID == 0xD3D3 || ID == 0x0000) {
    ID = 0x9325; // Forțăm driver-ul ILI9325 în caz de eroare citire
    Serial.println("[TFT] Forțăm driver ID: 0x9325");
  }
  tft.begin(ID);
  tft.setRotation(1);
  showMessage("Pornire...", nullptr);

  // Initializare NVS — resetăm doar contoarele de eroare, NU ștergem
  // certificatele! prefs.clear() era destructiv: ștergea cert-urile
  // provizionate/reînnoite la fiecare boot.
  prefs.begin("pki", false);
  prefs.putInt(RENEW_FAILURES_NVS_KEY, 0);
  prefs.putInt(STATE_NVS_KEY, STATE_OK);
  prefs.end();
  g_deviceState = loadDeviceState();

  // Conectare WiFi (STA mode)
  WiFi.mode(WIFI_STA);

  // IP static optional — ajusteaza dupa reteaua de demo
  IPAddress local_ip(192, 168, 101, 67);
  IPAddress gateway_ip(192, 168, 101, 1);
  IPAddress subnet(255, 255, 255, 0);
  IPAddress dns1(8, 8, 8, 8);
  IPAddress dns2(8, 8, 4, 4);
  if (!WiFi.config(local_ip, gateway_ip, subnet, dns1, dns2)) {
    Serial.println("[WiFi] Config IP static esuat — folosim DHCP");
  }

  Serial.printf("[WiFi] Conectare la '%s'...\n", ssid);
  showMessage("WiFi...", ssid);
  WiFi.begin(ssid, password);

  unsigned long wifiStart = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - wifiStart < 15000UL) {
    delay(500);
    Serial.print(".");
  }
  Serial.println();

  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("[WiFi] EROARE: Nu s-a putut conecta. Continuam...");
    showMessage("WiFi EROARE", "Verifica AP");
    delay(2000);
  } else {
    Serial.printf("[WiFi] Conectat. IP: %s\n",
                  WiFi.localIP().toString().c_str());
    showMessage("WiFi OK", WiFi.localIP().toString().c_str());
    delay(1000);
  }

  // Sincronizare NTP (OBLIGATORIE — fara timp valid, mbedTLS respinge orice
  // certificat cu BADCERT_FUTURE / X509_CERT_VERIFY_FAILED = -9984)
  configTime(0, 0, "pool.ntp.org", "time.google.com");
  Serial.print("[NTP] Sincronizare");
  showMessage("NTP Sync...", "Asteptam ceasul");
  time_t now = 0;
  for (int i = 0; i < 60 && now < 1000000000; i++) {
    time(&now);
    delay(500);
    Serial.print(".");
  }
  Serial.println();
  if (now > 1000000000) {
    Serial.printf("[NTP] OK — %s", ctime(&now));
  } else {
    Serial.println("[NTP] EROARE CRITICA: Timp nesincronizat dupa 30s!");
    Serial.printf("[NTP] time(NULL) = %ld — mbedTLS va respinge TOATE certificatele!\n", (long)now);
    showMessage("NTP EROARE", "Ceas nesincronizat!");
    // Blocare: fara ceas valid, mTLS nu poate functiona
    while (true) {
      // Reincearca NTP la fiecare 10 secunde
      delay(10000);
      time(&now);
      if (now > 1000000000) {
        Serial.printf("[NTP] Recuperat! Timp: %s", ctime(&now));
        break;
      }
      Serial.printf("[NTP] Inca asteptam... time=%ld\n", (long)now);
    }
  }

  // Citim certificatele din NVS (scrise la provisioning sau PKI renewal)
  Serial.println("[mTLS] Citire certificate din NVS...");

  if (!loadRootCaFromNVS(current_root_ca_pem) ||
      current_root_ca_pem.length() == 0) {
    Serial.println("[mTLS] EROARE: CA root lipseste din NVS!");
    Serial.println("[mTLS] Rulati sketch-ul de provisioning mai intai:");
    Serial.println("  1. Flash ESP32_code/provisioning/main.cpp");
    Serial.println("  2. python scripts/provision_esp32.py --port COMx");
    Serial.println("  3. Re-flash codul principal");
    showMessage("NVS GOL", "Provisioning necesar!");
    while (true)
      delay(1000); // Blocare — nu putem continua fara CA
  }
  Serial.printf("[mTLS] CA root incarcat din NVS (%d bytes)\n",
                current_root_ca_pem.length());

  if (!loadClientCredentialsFromNVS(current_client_cert_pem,
                                    current_client_key_pem) ||
      current_client_cert_pem.length() == 0 ||
      current_client_key_pem.length() == 0) {
    Serial.println("[mTLS] EROARE: Certificate client lipsesc din NVS!");
    showMessage("NVS GOL", "Client cert lipseste!");
    while (true)
      delay(1000);
  }
  Serial.printf("[mTLS] Client cert incarcat din NVS (%d bytes)\n",
                current_client_cert_pem.length());
  Serial.printf("[mTLS] Client key incarcat din NVS (%d bytes)\n",
                current_client_key_pem.length());

  // Bank public key — pentru criptarea PIN block cu cheia bancii
  if (!loadEncryptedStringFromNVS("bank_pub", current_bank_pub_pem) ||
      current_bank_pub_pem.length() == 0) {
    Serial.println(
        "[mTLS] AVERTISMENT: bank_pub lipseste din NVS — PIN "
        "challenge nu va functiona!");
  } else {
    Serial.printf("[mTLS] Bank pub key incarcata din NVS (%d bytes)\n",
                  current_bank_pub_pem.length());
  }

  // Configureaza mTLS pe WiFiClientSecure
  secureClient.setCACert(current_root_ca_pem.c_str());
  secureClient.setCertificate(current_client_cert_pem.c_str());
  secureClient.setPrivateKey(current_client_key_pem.c_str());
  secureClient.setTimeout(HTTP_TIMEOUT_MS);

  // Terminal ID = CN din certificat mTLS
  g_terminalId = extractCertCN(current_client_cert_pem);
  if (g_terminalId.length() == 0)
    g_terminalId = getTerminalId();
  Serial.printf("[mTLS] Terminal ID: %s\n", g_terminalId.c_str());

  // Dump complet al certificatelor si verificare lant la boot
  dumpCertificateDiagnostics();

  // ── TLS PROBE — test conexiune reala la NGINX la boot ─────
  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("\n── TLS PROBE — test conexiune la NGINX ─────────────");

    // Test 1: Cu verificare CA (modul normal)
    WiFiClientSecure probeClient;
    probeClient.setCACert(current_root_ca_pem.c_str());
    probeClient.setCertificate(current_client_cert_pem.c_str());
    probeClient.setPrivateKey(current_client_key_pem.c_str());
    probeClient.setTimeout(5000);

    Serial.printf("[PROBE] Conectare la %s:%d cu CA verification...\n",
                  gateway_host, gateway_port);
    if (probeClient.connect(gateway_host, gateway_port)) {
      Serial.println("[PROBE] ✓ TLS HANDSHAKE REUSIT cu CA verification!");
      probeClient.stop();
    } else {
      Serial.println("[PROBE] ✗ TLS HANDSHAKE ESUAT cu CA verification!");
      Serial.println("[PROBE] Eroarea este la verificarea certificatului "
                     "SERVER al NGINX-ului.");

      // Test 2: Fara verificare CA (setInsecure) — doar pt diagnostic
      WiFiClientSecure insecureClient;
      insecureClient.setInsecure(); // Skip server cert verification
      insecureClient.setCertificate(current_client_cert_pem.c_str());
      insecureClient.setPrivateKey(current_client_key_pem.c_str());
      insecureClient.setTimeout(5000);

      Serial.printf("[PROBE] Conectare la %s:%d fara CA verification "
                    "(setInsecure)...\n",
                    gateway_host, gateway_port);
      if (insecureClient.connect(gateway_host, gateway_port)) {
        Serial.println("[PROBE] ✓ TLS REUSIT cu setInsecure() — "
                       "problema e la SERVER CERT VERIFICATION!");
        Serial.println("[PROBE] Solutie: NGINX prezinta un cert pe care "
                       "CA-ul nostru NU il poate verifica.");
        Serial.println("[PROBE] Verificati ca gateway.crt in NGINX e semnat "
                       "de acelasi NFC-Payment-CA.");
        insecureClient.stop();
      } else {
        Serial.println("[PROBE] ✗ TLS ESUAT si cu setInsecure() — "
                       "problema nu e la cert verification!");
        Serial.println("[PROBE] Posibil: firewall, port inchis, IP gresit, "
                       "sau versiune TLS incompatibila.");
      }
    }
    Serial.println("── END TLS PROBE ───────────────────────────────────\n");
  }

  // NFC — modulul e defect; dezactivat pentru a preveni conflicte de pini cu
  // Keypad, LED si Haptic SPI.begin(PN532_SCK, PN532_MISO, PN532_MOSI,
  // PN532_SS); nfc.begin(); nfc.SAMConfig();

  // Verificare reinnoire certificat la boot
  runPkiRenewCheckIfNeeded();
  lastPkiCheckMillis = millis();

  // Pornire server HTTP local pentru comunicare cu telefonul
  if (WiFi.status() == WL_CONNECTED) {
    setupLocalServer();
  }

  showMessage("Gata de plata", "Asteptati...");
  Serial.println(
      "[POS] Gata. Asteptam tranzactie din dashboard pe POST /initiate\n");
}

// ============================================================
// LOOP PRINCIPAL — State Machine WiFi Direct
//
// STATE 0 POS_IDLE:
//   Ecranul afiseaza "Gata de plata". Tranzactia este initiata extern
//   prin POST /initiate de la dashboard → POS_WAITING_FOR_PHONE
//
// STATE 1 POS_WAITING_FOR_PHONE:
//   ESP32 expune datele tranzactiei pe GET /payment-request
//   Telefonul calculeaza criptograma si trimite POST /payment-response
//   Timeout 30s → revenire la POS_IDLE
//
// STATE 2 POS_PROCESSING:
//   ESP32 construieste JSON si trimite la Gateway via mTLS :443
//   Gestioneaza APPROVED / DECLINED / CHALLENGE_REQUIRED / erori
//   Dupa 3s → revenire la POS_IDLE
// ============================================================

void loop() {
  // Terminal blocat — nu procesam nimic
  if (g_deviceState == STATE_BRICKED_PENDING_MANUAL_RESET) {
    showMessage("Terminal BLOCAT", "Reset necesar");
    delay(1000);
    return;
  }

  // Verificare periodica PKI renewal (la fiecare 24h)
  if (millis() - lastPkiCheckMillis >
      (unsigned long)RECHECK_INTERVAL_SECONDS * 1000UL) {
    runPkiRenewCheckIfNeeded();
    lastPkiCheckMillis = millis();
  }

  // Reconectare WiFi automata daca conexiunea a cazut
  if (WiFi.status() != WL_CONNECTED) {
    showMessage("WiFi pierdut", "Reconectare...");
    WiFi.reconnect();
    unsigned long t = millis();
    while (WiFi.status() != WL_CONNECTED && millis() - t < 10000UL)
      delay(500);
    if (WiFi.status() == WL_CONNECTED) {
      Serial.printf("[WiFi] Reconectat. IP: %s\n",
                    WiFi.localIP().toString().c_str());
      showMessage("WiFi OK", WiFi.localIP().toString().c_str());
      // Reporneste serverul HTTP local daca nu ruleaza
      setupLocalServer();
      delay(1000);
      if (g_tx.state == POS_IDLE)
        showMessage("Gata de plata", "Asteptati...");
    } else {
      Serial.println("[WiFi] Reconectare esuata");
      showMessage("WiFi EROARE", "Verifica AP");
      delay(3000);
      return;
    }
  }

  // ── STATE 0: IDLE — asteptam tranzactie din dashboard ────────
  // Tranzactia este initiata exclusiv prin POST /initiate de la dashboard.
  // Keypad-ul este rezervat doar pentru PIN in fluxul de challenge.
  if (g_tx.state == POS_IDLE) {
    delay(50);
    return;
  }

  // ── STATE 1: WAITING_FOR_PHONE — asteptam POST de la telefon ──
  if (g_tx.state == POS_WAITING_FOR_PHONE) {
    if (millis() - g_tx.stateEnteredAt > PHONE_WAIT_TIMEOUT_MS) {
      Serial.println("[POS] Timeout 30s — revenire la IDLE");
      g_tx = PendingTransaction{};
      showMessage("Timeout", "Reincercati");
      delay(2000);
      showMessage("Gata de plata", "Asteptati...");
    }
    // Telefonul va face POST /payment-response via AsyncWebServer
    // care va trece state-ul in POS_PROCESSING
    delay(50);
    return;
  }

  // ── STATE 2: PROCESSING — trimite la Gateway ──────────────
  if (g_tx.state == POS_PROCESSING) {
    // Construieste payload JSON identic cu cel din fluxul NFC
    // (dpan, atc, mac vin de la telefon; restul generat local)
    JsonDocument doc;
    doc["dpan"] = g_tx.dpan;

    JsonObject transaction = doc["transaction"].to<JsonObject>();
    transaction["amount"] = g_tx.amountCents;
    transaction["currency"] = g_tx.currency;
    transaction["pos_nonce"] = g_tx.posNonce;
    transaction["terminal_timestamp"] = g_tx.terminalTimestamp;

    JsonObject cryptogram = doc["cryptogram"].to<JsonObject>();
    cryptogram["mac"] = g_tx.mac;
    cryptogram["atc"] = g_tx.atc;

    String json;
    serializeJson(doc, json);

    sendRequestWithBackoff(json, g_tx.amountCents);

    delay(3000);
    g_tx = PendingTransaction{}; // reset la IDLE
    showMessage("Gata de plata", "Asteptati...");
    return;
  }

  delay(50);
}
