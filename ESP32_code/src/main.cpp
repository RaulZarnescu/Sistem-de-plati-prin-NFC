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
#include <vector>

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

const char* gateway_host = "192.168.43.100";
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

const char* CLIENT_CERT_NVS_KEY = "mtls_cert";
const char* CLIENT_KEY_NVS_KEY = "mtls_key";
const char* ROOT_CA_NVS_KEY = "root_ca";
const char* RENEW_FAILURES_NVS_KEY = "renew_failures";
const char* STATE_NVS_KEY = "state";

static const int CERT_IV_LEN = 12;
static const int CERT_TAG_LEN = 16;

String current_client_cert_pem;
String current_client_key_pem;
String current_root_ca_pem;
String g_terminalId;
DeviceState g_deviceState = STATE_OK;

const int NFC_COMMAND_TIMEOUT_MS = 300;
const int HTTP_TIMEOUT_MS = 5000;
const int GPO_MAX_PAYLOAD = 128;
const int PIN_MAX_DIGITS = 6;
const int PIN_MIN_LENGTH = 4;
const int CSR_KEY_BITS = 2048;

const int RECHECK_INTERVAL_SECONDS = 24 * 3600;
const int RENEW_DAYS_BEFORE = 5;
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
bool buildEmvGpoPayload(int amountCents, const String& currency, const String& timestamp, const String& posNonce, uint8_t* outData, int& outLen);
String extractCertCN(const String& certPem);
String getTerminalId();
String encryptPinBlockAndBase64(const String& transaction_id, const String& pin);
int computeBackoffMs(int attempt, int base_delay, int cap_delay);
bool isRetryableStatus(int httpCode);
String jsonGetString(const JsonVariantConst& value);

bool getCertExpiry(const char* cert_pem, time_t &not_after);
bool generateCsrBase64(String& out_csr_base64, String& out_priv_key_pem);
bool postCsrAndStoreNewCert(const String& csr_base64, const String& newKeyPem);
bool encryptAndStoreCertInNVS(const char* cert_pem);
bool decryptCertFromNVS(String& out_cert_pem);
bool encryptAndStoreKeyInNVS(const char* key_pem);
bool decryptKeyFromNVS(String& out_key_pem);
bool storeClientCredentialsToNVS(const String& certPem, const String& keyPem);
bool loadClientCredentialsFromNVS(String& certPem, String& keyPem);
bool storeEncryptedStringToNVS(const String& value, const char* prefKey);
bool loadEncryptedStringFromNVS(const char* prefKey, String& outValue);
bool storeRootCaToNVS(const String& rootCaPem);
bool loadRootCaFromNVS(String& outRootCaPem);
bool setDeviceState(DeviceState state);
DeviceState loadDeviceState();
int getRenewFailures();
bool setRenewFailures(int count);
bool runPkiRenewCheckIfNeeded();
String base64Encode(const uint8_t* data, size_t len);
bool base64Decode(const String& input, std::vector<uint8_t>& out);
bool aesGcmEncrypt(const uint8_t* key, const uint8_t* iv, size_t iv_len,
                   const uint8_t* input, size_t input_len,
                   uint8_t* output, size_t output_len,
                   uint8_t* tag, size_t tag_len);
bool aesGcmDecrypt(const uint8_t* key, const uint8_t* iv, size_t iv_len,
                   const uint8_t* input, size_t input_len,
                   const uint8_t* tag, size_t tag_len,
                   uint8_t* output);
void fillRandomBytes(uint8_t* buffer, size_t length);

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

  d1 = (d1 & 0xFFFF0FFF) | 0x00004000;
  d2 = (d2 & 0x3FFFFFFF) | 0x80000000;

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

void showTransaction(int amountCents, const char* status) {
  char amtBuf[32];
  int lei = amountCents / 100;
  int cents = amountCents % 100;
  snprintf(amtBuf, sizeof(amtBuf), "%d.%02d RON", lei, cents);
  showMessage(amtBuf, status);
}

void fillRandomBytes(uint8_t* buffer, size_t length) {
  size_t i = 0;
  while (i < length) {
    uint32_t rnd = esp_random();
    for (size_t j = 0; j < 4 && i < length; ++j) {
      buffer[i++] = (rnd >> (8 * j)) & 0xFF;
    }
  }
}

int computeBackoffMs(int attempt, int base_delay, int cap_delay) {
  int exp = min(attempt, 4);
  int backoff = base_delay * (1 << exp);
  if (backoff > cap_delay) backoff = cap_delay;
  int jitter = random(0, backoff / 2 + 1);
  int wait = backoff / 2 + jitter;
  if (wait > cap_delay) wait = cap_delay;
  return wait;
}

bool isRetryableStatus(int httpCode) {
  return httpCode == 429 || httpCode == 503 || httpCode <= 0;
}

String jsonGetString(const JsonVariantConst& value) {
  if (value.is<const char*>()) {
    return String(value.as<const char*>());
  }
  if (value.is<int>()) {
    return String(value.as<int>());
  }
  return String();
}

String base64Encode(const uint8_t* data, size_t len) {
  size_t olen = 0;
  mbedtls_base64_encode(NULL, 0, &olen, data, len);
  std::vector<unsigned char> out(olen + 1);
  if (mbedtls_base64_encode(out.data(), out.size(), &olen, data, len) != 0) {
    return String();
  }
  out[olen] = '\0';
  return String((char*)out.data());
}

bool base64Decode(const String& input, std::vector<uint8_t>& out) {
  size_t olen = 0;
  mbedtls_base64_decode(NULL, 0, &olen, (const unsigned char*)input.c_str(), input.length());
  out.resize(olen);
  if (mbedtls_base64_decode(out.data(), out.size(), &olen,
                            (const unsigned char*)input.c_str(), input.length()) != 0) {
    return false;
  }
  out.resize(olen);
  return true;
}

bool aesGcmEncrypt(const uint8_t* key, const uint8_t* iv, size_t iv_len,
                   const uint8_t* input, size_t input_len,
                   uint8_t* output, size_t output_len,
                   uint8_t* tag, size_t tag_len) {
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
  if (ret != 0) {
    mbedtls_gcm_free(&gcm);
    return false;
  }
  ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT,
                                  input_len, iv, iv_len,
                                  NULL, 0,
                                  input, output,
                                  tag_len, tag);
  mbedtls_gcm_free(&gcm);
  return ret == 0;
}

bool aesGcmDecrypt(const uint8_t* key, const uint8_t* iv, size_t iv_len,
                   const uint8_t* input, size_t input_len,
                   const uint8_t* tag, size_t tag_len,
                   uint8_t* output) {
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
  if (ret != 0) {
    mbedtls_gcm_free(&gcm);
    return false;
  }
  ret = mbedtls_gcm_auth_decrypt(&gcm, input_len, iv, iv_len,
                                 NULL, 0,
                                 tag, tag_len,
                                 input, output);
  mbedtls_gcm_free(&gcm);
  return ret == 0;
}

bool storeEncryptedStringToNVS(const String& value, const char* prefKey) {
  std::vector<uint8_t> plaintext(value.length());
  memcpy(plaintext.data(), value.c_str(), value.length());

  uint8_t iv[CERT_IV_LEN];
  uint8_t tag[CERT_TAG_LEN];
  fillRandomBytes(iv, CERT_IV_LEN);

  std::vector<uint8_t> ciphertext(plaintext.size());
  if (!aesGcmEncrypt(CERT_ENC_KEY, iv, CERT_IV_LEN,
                     plaintext.data(), plaintext.size(),
                     ciphertext.data(), ciphertext.size(),
                     tag, CERT_TAG_LEN)) {
    return false;
  }

  std::vector<uint8_t> blob;
  blob.reserve(CERT_IV_LEN + CERT_TAG_LEN + ciphertext.size());
  blob.insert(blob.end(), iv, iv + CERT_IV_LEN);
  blob.insert(blob.end(), tag, tag + CERT_TAG_LEN);
  blob.insert(blob.end(), ciphertext.begin(), ciphertext.end());

  String encoded = base64Encode(blob.data(), blob.size());
  if (encoded.length() == 0) {
    return false;
  }

  prefs.begin("pki", false);
  bool ok = prefs.putString(prefKey, encoded);
  prefs.end();
  return ok;
}

bool loadEncryptedStringFromNVS(const char* prefKey, String& outValue) {
  prefs.begin("pki", false);
  String encoded = prefs.getString(prefKey, "");
  prefs.end();
  if (encoded.length() == 0) {
    return false;
  }

  std::vector<uint8_t> blob;
  if (!base64Decode(encoded, blob)) {
    return false;
  }
  if (blob.size() <= CERT_IV_LEN + CERT_TAG_LEN) {
    return false;
  }

  size_t ciphertextLen = blob.size() - CERT_IV_LEN - CERT_TAG_LEN;
  const uint8_t* iv = blob.data();
  const uint8_t* tag = blob.data() + CERT_IV_LEN;
  const uint8_t* ciphertext = blob.data() + CERT_IV_LEN + CERT_TAG_LEN;

  std::vector<uint8_t> plaintext(ciphertextLen);
  if (!aesGcmDecrypt(CERT_ENC_KEY, iv, CERT_IV_LEN,
                     ciphertext, ciphertextLen,
                     tag, CERT_TAG_LEN,
                     plaintext.data())) {
    return false;
  }

  outValue = String((char*)plaintext.data(), plaintext.size());
  return true;
}

bool storeRootCaToNVS(const String& rootCaPem) {
  return storeEncryptedStringToNVS(rootCaPem, ROOT_CA_NVS_KEY);
}

bool loadRootCaFromNVS(String& outRootCaPem) {
  return loadEncryptedStringFromNVS(ROOT_CA_NVS_KEY, outRootCaPem);
}

bool storeClientCredentialsToNVS(const String& certPem, const String& keyPem) {
  return storeEncryptedStringToNVS(certPem, CLIENT_CERT_NVS_KEY)
      && storeEncryptedStringToNVS(keyPem, CLIENT_KEY_NVS_KEY);
}

bool loadClientCredentialsFromNVS(String& certPem, String& keyPem) {
  return loadEncryptedStringFromNVS(CLIENT_CERT_NVS_KEY, certPem)
      && loadEncryptedStringFromNVS(CLIENT_KEY_NVS_KEY, keyPem);
}

bool setDeviceState(DeviceState state) {
  prefs.begin("pki", false);
  bool ok = prefs.putInt(STATE_NVS_KEY, (int)state);
  prefs.end();
  if (ok) g_deviceState = state;
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

time_t mbedtlsX509TimeToTimeT(const mbedtls_x509_time& t) {
  struct tm tm_time;
  memset(&tm_time, 0, sizeof(tm_time));
  tm_time.tm_year = t.year - 1900;
  tm_time.tm_mon  = t.mon - 1;
  tm_time.tm_mday = t.day;
  tm_time.tm_hour = t.hour;
  tm_time.tm_min  = t.min;
  tm_time.tm_sec  = t.sec;
  tm_time.tm_isdst = 0;
  return mktime(&tm_time);
}

bool getCertExpiry(const char* cert_pem, time_t &not_after) {
  mbedtls_x509_crt crt;
  mbedtls_x509_crt_init(&crt);
  int ret = mbedtls_x509_crt_parse(&crt, (const unsigned char*)cert_pem, strlen(cert_pem) + 1);
  if (ret != 0) {
    mbedtls_x509_crt_free(&crt);
    return false;
  }
  not_after = mbedtlsX509TimeToTimeT(crt.valid_to);
  mbedtls_x509_crt_free(&crt);
  return true;
}

bool generateCsrBase64(String& out_csr_base64, String& out_priv_key_pem) {
  int ret;
  mbedtls_pk_context key;
  mbedtls_ctr_drbg_context ctr;
  mbedtls_entropy_context entropy;
  mbedtls_x509write_csr req;

  mbedtls_pk_init(&key);
  mbedtls_ctr_drbg_init(&ctr);
  mbedtls_entropy_init(&entropy);
  mbedtls_x509write_csr_init(&req);

  const char* pers = "csr_gen";
  ret = mbedtls_ctr_drbg_seed(&ctr, mbedtls_entropy_func, &entropy,
                              (const unsigned char*)pers, strlen(pers));
  if (ret != 0) goto cleanup_csr;

  ret = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
  if (ret != 0) goto cleanup_csr;

  ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(key), mbedtls_ctr_drbg_random, &ctr,
                            CSR_KEY_BITS, 65537);
  if (ret != 0) goto cleanup_csr;

  char private_key_buf[4096];
  ret = mbedtls_pk_write_key_pem(&key, (unsigned char*)private_key_buf, sizeof(private_key_buf));
  if (ret != 0) goto cleanup_csr;

  String terminalId = getTerminalId();
  String subject = "CN=" + terminalId + ",O=POS,OU=Terminal,C=RO";

  mbedtls_x509write_csr_set_md_alg(&req, MBEDTLS_MD_SHA256);
  mbedtls_x509write_csr_set_key(&req, &key);
  ret = mbedtls_x509write_csr_set_subject_name(&req, subject.c_str());
  if (ret != 0) goto cleanup_csr;

  char csr_pem[4096];
  ret = mbedtls_x509write_csr_pem(&req, (unsigned char*)csr_pem, sizeof(csr_pem),
                                 mbedtls_ctr_drbg_random, &ctr);
  if (ret != 0) goto cleanup_csr;

  out_priv_key_pem = String(private_key_buf);
  out_csr_base64 = base64Encode((const uint8_t*)csr_pem, strlen(csr_pem));
  if (out_csr_base64.length() == 0) goto cleanup_csr;

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

bool postCsrAndStoreNewCert(const String& csr_base64, const String& newKeyPem) {
  StaticJsonDocument<512> bodyDoc;
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
  Serial.printf("PKI renew POST code=%d body=%s\n", code, resp.c_str());
  http.end();

  if (code != 200) {
    return false;
  }

  StaticJsonDocument<1024> doc;
  DeserializationError err = deserializeJson(doc, resp);
  if (err) {
    return false;
  }

  String cert_b64 = jsonGetString(doc["certificate_pem_b64"]);
  String ca_b64 = jsonGetString(doc["ca_certificate_pem_b64"]);
  if (cert_b64.length() == 0 || ca_b64.length() == 0) {
    return false;
  }

  std::vector<uint8_t> cert_decoded;
  std::vector<uint8_t> ca_decoded;
  if (!base64Decode(cert_b64, cert_decoded) || !base64Decode(ca_b64, ca_decoded)) {
    return false;
  }

  String certPem((char*)cert_decoded.data(), cert_decoded.size());
  String caPem((char*)ca_decoded.data(), ca_decoded.size());

  if (!storeClientCredentialsToNVS(certPem, newKeyPem)) {
    return false;
  }
  if (!storeRootCaToNVS(caPem)) {
    return false;
  }

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
    Serial.println("Device is bricked pending manual reset; skipping PKI check");
    return false;
  }

  time_t now = time(NULL);
  if (now == ((time_t)-1)) {
    Serial.println("Invalid system time; cannot perform PKI renewal");
    return false;
  }

  time_t not_after;
  if (!getCertExpiry(current_client_cert_pem.c_str(), not_after)) {
    Serial.println("Failed to parse current client certificate expiry");
    return false;
  }

  double daysUntilExpiry = difftime(not_after, now) / 86400.0;
  Serial.printf("Cert expires in %.2f days\n", daysUntilExpiry);

  if (daysUntilExpiry > RENEW_DAYS_BEFORE) {
    return true;
  }

  showMessage("Renewing cert", "Please wait...");
  String csr_b64;
  String newKeyPem;
  if (!generateCsrBase64(csr_b64, newKeyPem)) {
    Serial.println("Failed to generate CSR");
    int failures = getRenewFailures() + 1;
    setRenewFailures(failures);
    if (failures >= RENEW_MAX_FAILURES) {
      setDeviceState(STATE_BRICKED_PENDING_MANUAL_RESET);
      showMessage("Device BRICKED", "Manual reset needed");
    }
    return false;
  }

  if (!postCsrAndStoreNewCert(csr_b64, newKeyPem)) {
    Serial.println("Failed to renew certificate from gateway");
    int failures = getRenewFailures() + 1;
    setRenewFailures(failures);
    if (failures >= RENEW_MAX_FAILURES) {
      setDeviceState(STATE_BRICKED_PENDING_MANUAL_RESET);
      showMessage("Device BRICKED", "Manual reset needed");
    }
    return false;
  }

  setRenewFailures(0);
  setDeviceState(STATE_OK);
  showMessage("Cert renewed", nullptr);
  delay(1000);
  return true;
}

String encryptPinBlockAndBase64(const String& transaction_id, const String& pin) {
  String plain = transaction_id + ":" + pin;

  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);
  int ret = mbedtls_pk_parse_public_key(&pk,
                                        (const unsigned char*)bank_pub_pem,
                                        strlen(bank_pub_pem) + 1);
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

String collectPin(int maxDigits = PIN_MAX_DIGITS, unsigned long timeoutMs = 30000) {
  showMessage("Enter PIN:", "----");
  String pin = "";
  unsigned long start = millis();
  while ((millis() - start) < timeoutMs) {
    char k = keypad.getKey();
    if (k) {
      if (k >= '0' && k <= '9') {
        if (pin.length() < (size_t)maxDigits) pin += k;
      } else if (k == '#') {
        if (pin.length() >= PIN_MIN_LENGTH) break;
      } else if (k == '*') {
        if (pin.length()) pin.remove(pin.length() - 1);
      }
      char masked[16] = {0};
      for (size_t i = 0; i < pin.length() && i < sizeof(masked) - 1; ++i) masked[i] = '*';
      showMessage("Enter PIN:", masked);
    }
    delay(50);
  }
  return pin;
}

int sendChallengeRequestWithPin(const String& transaction_id, const String& original_dpan, const String& pin) {
  const int max_retries = 3;
  const int base_delay = 1000;
  const int cap_delay = 10000;

  if (transaction_id.length() == 0 || original_dpan.length() == 0) {
    Serial.println("Challenge request missing transaction_id or original_dpan");
    return -1;
  }

  String idempotencyNew = generateUuidV4();
  String terminalId = getTerminalId();

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
    Serial.printf("Challenge POST code=%d body=%s\n", code, resp.c_str());
    http.end();

    if (code == 200 || code == 401) {
      return code;
    }

    if (isRetryableStatus(code)) {
      if (attempt == max_retries) {
        return code;
      }
      int wait = computeBackoffMs(attempt, base_delay, cap_delay);
      Serial.printf("Challenge retry in %d ms\n", wait);
      delay(wait);
      continue;
    }

    return code;
  }

  return -1;
}

void sendRequestWithBackoff(String payload, int amountCents) {
  const int max_retries = 5;
  const int base_delay = 1000;
  const int cap_delay = 10000;

  if (g_deviceState == STATE_BRICKED_PENDING_MANUAL_RESET) {
    showMessage("Terminal BLOCKED", "Manual reset needed");
    return;
  }

  String idempotencyKey = generateUuidV4();
  String terminalId = getTerminalId();

  for (int attempt = 0; attempt <= max_retries; ++attempt) {
    HTTPClient http;
    secureClient.setTimeout(HTTP_TIMEOUT_MS);
    http.setTimeout(HTTP_TIMEOUT_MS);
    http.begin(secureClient, gateway_host, gateway_port, gateway_path);
    http.addHeader("Content-Type", "application/json");
    http.addHeader("X-Idempotency-Key", idempotencyKey);
    http.addHeader("X-Terminal-Id", terminalId);

    showTransaction(amountCents, "Procesare...");
    int httpCode = http.POST(payload);
    String body = http.getString();
    Serial.printf("HTTP %d body=%s\n", httpCode, body.c_str());

    bool retryable = false;

    if (httpCode == 200) {
      StaticJsonDocument<256> doc;
      DeserializationError err = deserializeJson(doc, body);
      String status = "";
      if (!err && doc.containsKey("status")) status = jsonGetString(doc["status"]);

      if (status == "APPROVED") {
        showTransaction(amountCents, "APROBAT");
        http.end();
        return;
      } else if (status == "DECLINED") {
        showTransaction(amountCents, "REFUZAT");
        http.end();
        return;
      } else if (status == "CHALLENGE_REQUIRED") {
        String tx_id = doc.containsKey("transaction_id") ? jsonGetString(doc["transaction_id"]) : String();
        String orig_dpan = doc.containsKey("original_dpan") ? jsonGetString(doc["original_dpan"]) : String();
        if (tx_id.length() == 0 || orig_dpan.length() == 0) {
          showMessage("Challenge Err", "Missing data");
          http.end();
          return;
        }
        showMessage("PIN Required", "Press # to send");
        String pin = collectPin(PIN_MAX_DIGITS, 30000);
        if (pin.length() < PIN_MIN_LENGTH) {
          showMessage("PIN Timeout", nullptr);
          http.end();
          return;
        }
        int challCode = sendChallengeRequestWithPin(tx_id, orig_dpan, pin);
        http.end();
        if (challCode == 200) {
          delay(200);
          continue;
        } else if (challCode == 401) {
          showMessage("Auth Err", nullptr);
          return;
        } else {
          retryable = true;
        }
      } else {
        Serial.println("Unknown 200 status field; retrying if attempts left");
        retryable = true;
      }
    } else if (httpCode == 401) {
      StaticJsonDocument<256> doc;
      DeserializationError err = deserializeJson(doc, body);
      String transaction_id = "";
      String original_dpan = "";
      if (!err) {
        if (doc.containsKey("transaction_id")) transaction_id = jsonGetString(doc["transaction_id"]);
        if (doc.containsKey("original_dpan")) original_dpan = jsonGetString(doc["original_dpan"]);
      }
      if (transaction_id.length() == 0 || original_dpan.length() == 0) {
        showMessage("Auth Err", "Missing 401 data");
        http.end();
        return;
      }
      showMessage("PIN Required", "Press # to send");
      String pin = collectPin(PIN_MAX_DIGITS, 30000);
      if (pin.length() < PIN_MIN_LENGTH) {
        showMessage("PIN Timeout", nullptr);
        http.end();
        return;
      }
      int challCode = sendChallengeRequestWithPin(transaction_id, original_dpan, pin);
      http.end();
      if (challCode == 200) {
        delay(200);
        continue;
      } else if (challCode == 401) {
        showMessage("Auth Err", nullptr);
        return;
      } else {
        retryable = true;
      }
    } else if (isRetryableStatus(httpCode)) {
      retryable = true;
    } else {
      http.end();
      showTransaction(amountCents, "System Error");
      return;
    }

    http.end();

    if (!retryable || attempt == max_retries) {
      showTransaction(amountCents, "System Error");
      return;
    }

    int wait = computeBackoffMs(attempt, base_delay, cap_delay);
    char buf[32];
    snprintf(buf, sizeof(buf), "Retry in %ds", wait / 1000);
    showTransaction(amountCents, buf);
    delay(wait);
  }

  showTransaction(amountCents, "System Error");
}

String extractCertCN(const String& certPem) {
  mbedtls_x509_crt crt;
  mbedtls_x509_crt_init(&crt);
  if (mbedtls_x509_crt_parse(&crt, (const unsigned char*)certPem.c_str(), certPem.length() + 1) != 0) {
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
  if (end >= 0) {
    dnStr = dnStr.substring(0, end);
  }

  mbedtls_x509_crt_free(&crt);
  return dnStr;
}

String getTerminalId() {
  if (g_terminalId.length() > 0) {
    return g_terminalId;
  }
  if (current_client_cert_pem.length() > 0) {
    g_terminalId = extractCertCN(current_client_cert_pem);
    if (g_terminalId.length() > 0) {
      return g_terminalId;
    }
  }
  g_terminalId = "POS-" + generateUuidV4();
  return g_terminalId;
}

bool appendTlv(uint8_t* buffer, int& offset, uint8_t tag, const uint8_t* value, int length) {
  if (offset + 2 + length > GPO_MAX_PAYLOAD) {
    return false;
  }
  buffer[offset++] = tag;
  buffer[offset++] = length;
  memcpy(buffer + offset, value, length);
  offset += length;
  return true;
}

bool buildEmvGpoPayload(int amountCents, const String& currency, const String& timestamp, const String& posNonce, uint8_t* outData, int& outLen) {
  outLen = 0;
  char amountBuf[16];
  snprintf(amountBuf, sizeof(amountBuf), "%d", amountCents);
  if (!appendTlv(outData, outLen, 0x9F, (const uint8_t*)amountBuf, strlen(amountBuf))) {
    return false;
  }

  const char* currencyCode = currency.c_str();
  if (!appendTlv(outData, outLen, 0x5F, (const uint8_t*)currencyCode, strlen(currencyCode))) {
    return false;
  }

  if (!appendTlv(outData, outLen, 0xDF, (const uint8_t*)timestamp.c_str(), timestamp.length())) {
    return false;
  }

  if (!appendTlv(outData, outLen, 0xE0, (const uint8_t*)posNonce.c_str(), posNonce.length())) {
    return false;
  }

  return true;
}

bool sendNfcCommand(const uint8_t* command, uint8_t commandLen, uint8_t* response, uint8_t* responseLength) {
  bool success = nfc.inDataExchange(command, commandLen, response, responseLength);
  if (!success) {
    Serial.println("NFC command failed");
    return false;
  }
  return true;
}

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
  if (!prefs.isKey(RENEW_FAILURES_NVS_KEY)) prefs.putInt(RENEW_FAILURES_NVS_KEY, 0);
  if (!prefs.isKey(STATE_NVS_KEY)) prefs.putInt(STATE_NVS_KEY, STATE_OK);
  prefs.end();

  g_deviceState = loadDeviceState();

  WiFi.mode(WIFI_STA);

  IPAddress local_ip(192, 168, 43, 101);
  IPAddress gateway_ip(192, 168, 43, 1);
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

  String loadedCert;
  String loadedKey;
  if (loadClientCredentialsFromNVS(loadedCert, loadedKey)) {
    current_client_cert_pem = loadedCert;
    current_client_key_pem = loadedKey;
    Serial.println("Loaded mTLS credentials from NVS");
  } else {
    current_client_cert_pem = String(client_cert_pem);
    current_client_key_pem = String(client_key_pem);
    if (storeClientCredentialsToNVS(current_client_cert_pem, current_client_key_pem)) {
      Serial.println("Stored mTLS credentials in NVS");
    } else {
      Serial.println("Failed to store mTLS credentials in NVS");
    }
  }

  String loadedRootCa;
  if (loadRootCaFromNVS(loadedRootCa)) {
    current_root_ca_pem = loadedRootCa;
    Serial.println("Loaded root CA from NVS");
  } else {
    current_root_ca_pem = String(root_ca_pem);
    storeRootCaToNVS(current_root_ca_pem);
  }

  secureClient.setCACert(current_root_ca_pem.c_str());
  secureClient.setCertificate(current_client_cert_pem.c_str());
  secureClient.setPrivateKey(current_client_key_pem.c_str());
  secureClient.setTimeout(HTTP_TIMEOUT_MS);

  g_terminalId = extractCertCN(current_client_cert_pem);
  if (g_terminalId.length() == 0) {
    g_terminalId = getTerminalId();
  }

  showMessage("WiFi Online", nullptr);

  SPI.begin(PN532_SCK, PN532_MISO, PN532_MOSI, PN532_SS);
  nfc.begin();
  nfc.SAMConfig();

  runPkiRenewCheckIfNeeded();
  lastPkiCheckMillis = millis();

  delay(1000);
  showMessage("Scan Phone/Card", nullptr);
}

unsigned long lastPkiCheckMillis = 0;

void loop() {
  if (g_deviceState == STATE_BRICKED_PENDING_MANUAL_RESET) {
    showMessage("Device BRICKED", "Manual reset needed");
    delay(1000);
    return;
  }

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
      int amountCents = 15000;
      String currency = "RON";
      String timestamp = getIsoTimestamp();
      String posNonce = generatePosNonce();

      uint8_t gpoData[GPO_MAX_PAYLOAD];
      int gpoDataLen = 0;
      if (!buildEmvGpoPayload(amountCents, currency, timestamp, posNonce, gpoData, gpoDataLen)) {
        showMessage("Payload Err", nullptr);
        delay(1000);
        showMessage("Scan Phone/Card", nullptr);
        continue;
      }

      uint8_t gpoCommand[5 + GPO_MAX_PAYLOAD];
      gpoCommand[0] = 0x80;
      gpoCommand[1] = 0xA8;
      gpoCommand[2] = 0x00;
      gpoCommand[3] = 0x00;
      gpoCommand[4] = gpoDataLen;
      memcpy(gpoCommand + 5, gpoData, gpoDataLen);

      GPIO.out_w1tc = PN532_SS_BIT;
      success = sendNfcCommand(gpoCommand, 5 + gpoDataLen, response, &responseLength);
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
            transaction["amount"] = amountCents;
            transaction["currency"] = "RON";
            transaction["pos_nonce"] = posNonce;
            transaction["terminal_timestamp"] = timestamp;

            JsonObject cryptogram = doc.createNestedObject("cryptogram");
            cryptogram["mac"] = mac;
            cryptogram["atc"] = atc;

            String json;
            serializeJson(doc, json);

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