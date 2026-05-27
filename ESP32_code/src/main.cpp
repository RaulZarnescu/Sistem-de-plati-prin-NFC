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

#include <Adafruit_PN532.h>
#include <Arduino.h>
#include <ArduinoJson.h>
#include <ESPAsyncWebServer.h>
#include <HTTPClient.h>
#include <Keypad.h>
#include <SPI.h>
#include <MCUFRIEND_kbv.h>
#include <Adafruit_GFX.h>

// Culori compatibilitate TFT_eSPI
#define TFT_BLACK   0x0000
#define TFT_WHITE   0xFFFF
#define TFT_RED     0xF800
#define TFT_GREEN   0x07E0
#define TFT_BLUE    0x001F
#define TFT_YELLOW  0xFFE0
#define TFT_CYAN    0x07FF
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
char keys[ROWS][COLS] = {{'1', '2', '3'},
                         {'4', '5', '6'},
                         {'7', '8', '9'},
                         {'*', '0', '#'}};
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
// Inlocuieste continutul cu certificatele reale generate de CA-ul intern.
const char root_ca_pem[] = R"EOF(
-----BEGIN CERTIFICATE-----
MIIFWTCCA0GgAwIBAgIUAdTlb92c83ekn34pFv7MKNy8X+kwDQYJKoZIhvcNAQEL
BQAwPDELMAkGA1UEBhMCUk8xFDASBgNVBAoMC0ZpY3RpdmVCYW5rMRcwFQYDVQQD
DA5ORkMtUGF5bWVudC1DQTAeFw0yNjA1MjYxNDI3MTdaFw0zNjA1MjMxNDI3MTda
MDwxCzAJBgNVBAYTAlJPMRQwEgYDVQQKDAtGaWN0aXZlQmFuazEXMBUGA1UEAwwO
TkZDLVBheW1lbnQtQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCt
rOI/XewpzPxMlFB0T9rbElqwwbkAvxUG+T6AKSBTXvPXSoaup9I4OQ8jmVHjyVKm
PcmoVvvfMEpnS0APs/Fh3LYEJVex5DVse2X1PFPMGxtT5F5DlIJQcgElhnXKj4Kv
NxMFfRQki6nW7oidT2TRNDasJ3zDz6aVet/gTsDlF/SOcZoQhhxSlJ1sEQBeEy0+
yjxNl16BxYH295jXhXKXj6OUOIw0yzdX3nVIk2/PybyxiPPbZl/MfeRqVZkNSN5d
zl4O8cC8eVbhybYL6jspxWB2/bbsJ9n/zsC+0DvcBr06eGLYJJlzv/ByDKnyg2cZ
K9MliGM+7zZD4AY9fx0LwDLL8Qya+R+8yrdFsr6lrxqFmkypLBnyGneYIzY4UPV+
Ube/XvQ/wrPDVZVx+aVEX8xsFchl37gBwAC6kWYP6wzP6fTWU4TUn8zo4igHnVc7
UWOdUf89Oz3vLpj69MWUvJiUMCQfThDww1RCSYnzIA+iR0/I8WGI/ZsmQ6dcqv9x
btK7JY0sViwFNXPjmzje/EBiNghgDyNHg6S1wTnqORe7Ygzk50EyAYLa0DlKCpfD
hil60J6ZEjp/Y1sbXz7cI4xtJwOvoMhsxXbMXfr8ZawMlK+QhHp0ZhucoOARMm3y
OcTKZqAgYp1e0Xgu7Y/gvKIONjZLILgiErXUkg28aQIDAQABo1MwUTAdBgNVHQ4E
FgQUwBmTRfcD14BJJsM5S2gE8Mk9STwwHwYDVR0jBBgwFoAUwBmTRfcD14BJJsM5
S2gE8Mk9STwwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAgEAdFMG
Brii8gYjhgMgFSONXgkJ9kqTgeqtO0THfHZHe7/JZpdDnSlSxvLfsYdUEuIrtYdi
BufCEJsO6laqfaF0Uvii+HYXmwDhlOApdseNdboHVG152PsAWlgWvwngDw85thkB
fi0gU7KmUSL/RWaTU5Jd90FwYaDR6XmvyPrt42N2jpmoQhkKSE+68k75JD2tBSNb
lffYkL3UBOyM7I/Tr2ON10E+vw8VYRvs8sKQuFt3mGCayl0csrY4G+kAyzhL1tZv
OMR8E+UhmP1WaiEKaPum7RqR0nD4WfBUpQ7Nf3T+0VE5IR1Aau4SH0KKLhwCDNT0
4iRZtqNd6p4CSLXk1pA+hh+ftvoS8Wo9nlTHBu2BxN9JT0ji8g/sGY5EqsMMeCi8
dISwWpPwnQ/IejTUcL3pFeei5s+ebzdCIk2mDXFXXG/gSCCz/9sKup6vZywLrR3b
aKFKRaTHCjBt+jwB7b/0lDy6o8CCh8D812Pa4IAQhFGC1HfNjIE51A9KJdjtpATy
RJLTxAL9XtL3kkNRUtxqUAa9JabpUwK+By9blzGDhWbRxyx6xeXlpfsD1/UzBWZi
yDNTYuGYGnViOKDPpvWEkZQOiac3msjH9hr+09km+D7rSAB73djFmjOcNM4Kq6so
zFHx9StHkWxAzV7EORNNhFYl8Wva2dQDDnTQDLU=
-----END CERTIFICATE-----
)EOF";

const char client_cert_pem[] = R"EOF(
-----BEGIN CERTIFICATE-----
MIIERTCCAi2gAwIBAgIUDzB26FHqHqVDnH+cppv/ZhSlbmMwDQYJKoZIhvcNAQEL
BQAwPDELMAkGA1UEBhMCUk8xFDASBgNVBAoMC0ZpY3RpdmVCYW5rMRcwFQYDVQQD
DA5ORkMtUGF5bWVudC1DQTAeFw0yNjA1MjYxNDI3MTdaFw0yNjA2MjUxNDI3MTda
MDkxCzAJBgNVBAYTAlJPMRQwEgYDVQQKDAtGaWN0aXZlQmFuazEUMBIGA1UEAwwL
UE9TLUJVQy0wMDEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDFYMEd
AKoCBQzpEXLX6HbtJem0LfSapjkcLCV7zYmCAXWuqPQpfH+hTe8GIVDVxIwWsU4c
CoOrALU+ZmbcC8MegZorKI4zlx0FMYOkE+Ik2xccOczn8PZarrnUqz5AmGlqUfSv
FDkLpN92kPWqNfyxxIcCvoGWcpP62A2uKHRcGYYYgZTT95JrUgQ5lhJdos4NO7Wr
u2Vxy8heDKT42Rq8T/ARUcsg2gIQcxp/u12T8vW+zmuXrajGjoE1keBRkbrHbFrp
h6AedAkxM4mw9wii1sKuxkT7clGwPjamlALqFK+8ZDv02mZO5E/DLBSGLnlytxps
8lzCimEvIpPl72DnAgMBAAGjQjBAMB0GA1UdDgQWBBQ9zEWW/982X9d45sVeF85v
QRpo6zAfBgNVHSMEGDAWgBTAGZNF9wPXgEkmwzlLaATwyT1JPDANBgkqhkiG9w0B
AQsFAAOCAgEASMEijW/iyWMN4LqP45Pntr6HpjsrkDDgtgZPzJVb8w7jqBJTOXYr
wdpxzfSKujGF79oVett3zqTZU1x6Jp6DCpO3OLw84XBMHN+QEbg9V4TqcMByU+Kk
yJrBTOkDFI0bdvev2o4MRsuI3fDKe15SpFiBKNWD/3+iw+EM1IZ7XXfqurxnYVPy
vr9qkqEqVfbocWZsgQwAthCkT7mBiaemsqpqW/o469iIJdctPDtB9sgHxPEdGpVV
2KT+6IIHm+BZeSXaaOndWkDp1VLKka3wsIc79rYdRRFpuTdj49/NhCTUO1MzCrjk
UbMcAmLhbdoR0ULv7apKJMIQT+r+ZyT0q0FaWrD+DRWLSEdW6q9TsdsJihAgeA5W
ZJ/T/iS3J6owc8W3yPVB2zgV8lHSc5rrCjj6wnHB27LylIWQ2G6On6ek3s5PC2JE
xRjP0/mEmQo2/FyGL3HaSPwtUGN0v4QEih7EAcxBVJcRfV00ZFkYxwJ9qmv7a5S9
H7wEJvwbTEpiQlX7mg5SCHu/xqaB3cGMxMHuy5cI/nZGrFPLKq578nWxJrSzJqzO
TGxiZ8Z9dRFQVfwcypSrujVybRGSye2EWIK1eKN8ZVM0Q5R97r4pjtZ4iutFaseC
GSkMLXE8u3Vor391f7vTiAYxW+DuwIXuGQO+7zjFjiTb/YGqIDoGGtQ=
-----END CERTIFICATE-----
)EOF";

const char client_key_pem[] = R"EOF(
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDFYMEdAKoCBQzp
EXLX6HbtJem0LfSapjkcLCV7zYmCAXWuqPQpfH+hTe8GIVDVxIwWsU4cCoOrALU+
ZmbcC8MegZorKI4zlx0FMYOkE+Ik2xccOczn8PZarrnUqz5AmGlqUfSvFDkLpN92
kPWqNfyxxIcCvoGWcpP62A2uKHRcGYYYgZTT95JrUgQ5lhJdos4NO7Wru2Vxy8he
DKT42Rq8T/ARUcsg2gIQcxp/u12T8vW+zmuXrajGjoE1keBRkbrHbFrph6AedAkx
M4mw9wii1sKuxkT7clGwPjamlALqFK+8ZDv02mZO5E/DLBSGLnlytxps8lzCimEv
IpPl72DnAgMBAAECggEAOzBhmNXrJYHoNjhSTSbcCw+0fqDNWlcAh09Byld/penU
JZVq6sn36CJbzGXPPNuc+u0etE/+3hfvQhApRlGMqKhK2ChoRFZLkJQhmuGPjmfZ
DVDT/rYG2njNJ1ZW674I1qZPDvWsia5eiMq9sNZRuelqZ0tDxx8C+1Uw/QoKotdJ
IP/kM3j5AaD6DZaNUSykSTkVQX7xl5325k0rNHPOdEdnatWk50MzhSEi7l32orBG
y4HgX8uKd0reBEDxLMSFXl4NoZBAFi6BBF+vFAGRsxFx0/ED2c4dkJNJlm3o7p7e
/Wf49Z3646OxkCJzRPuknP4B8YBF/qTmgK1zIFgB6QKBgQD4No0fnsT7DTFrpqPE
vSCYrvloGb7BIn1wWW5kiaahddv+11H4Tka7FZxmn3NMi5OnfOM4Yd6ua0G8Ilpv
YJwum19fvHQFPrE4oe1SrvRKlhYFD3xrwdMliE6KlBnZXHngGOt1AWqw7azqQJOT
lmxtagVzeebHv4Jw1E92p9vMFQKBgQDLke+YtkHJUIdFZUhQrbsFmoaG5zah59v7
WPyXqVGsFqmPr0wyyUynMteJF5deaWQed8kZeZ97VEmdDr/KsbV4ixiPsMVgGFnt
PphZ1+pPN19BZrf1xHQNNdLom5HCvrp00VLkjSTawZ0+gzUwK3G748UqerVN7hYp
T1lw30IsCwKBgFwIfhM3X3pmzehIhXixV6DFYBzFTwF1tGUwA8qrb2l2tfesBuy2
uWss/Czg+nNrXXhAyk9hmpu5kUocwsOBYue1HIv26F35fOSuxbxeup3dQJTnxQ5/
c7b674RanasGqvn4w3VC7ThlKDRDdXTH1bRMF3FVxchSrh7/2eb5HnpxAoGBAKt5
Tj1wqJGPB6Lo4bUz4imiNFdGQ7q1t5NNLdgChA1VOZcSrjjJX4wnQ27zNEoOtIsF
k5ul2zTjlu55Eg0HDDlx0UqYOGntmTJCW8qyGWiI1/AbOjIHPUozYGkXQfys9Bqa
iByE19p85JtXomHk9nSyM87IdhgiyQAbGtf895xpAoGBAOvuo82VtFhTtwnY4cZa
bfe0mMxzah2CDW/R26Xy/ebWGuvViOC/ZlEEraPzn5qzVyTrwJtdiUxKlhsfvTU4
JCkx7De8dBkAppcZxcDEveAeJAw+jD9iaYVhMvzFYv5n4KstRjTRq7goa4VqLZvf
Cd81ZTvShf17t/BbGA6jn8qW
-----END PRIVATE KEY-----
)EOF";

// Cheia publica RSA a bancii — folosita la criptarea PIN block-ului
const char bank_pub_pem[] = R"EOF(
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuSgizMI8t3KubCl188XN
IiT8kZq9e6Y/k2BlXvkFmxhIGua08Znle9TbjI8oIVpsZP9kQmv5XQcMqxWi0uLE
IxyksztOCkro6OwU20NeHMwIQrCeKVekZNRJKVTo3ULqr8XvE9golHX4RSNXS81H
py5CljY7PXgGoCIWN7mdC8fbBhjus66HhaHBugrLsVma5j9zEMNKqySApH2ABYf2
Z68yVtOneb9rPgcebk8owzmprvyOvzTa1setswqPrdr7R7TQnp/7jLvtUEmyMck8
1takct2t0TKNjahe+3Xi2eXVCunpqLi0Djnm5YkhnyhcjppAL7nnn3QlDnAYoq0K
hQIDAQAB
-----END PUBLIC KEY-----
)EOF";

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
String g_terminalId;
DeviceState g_deviceState = STATE_OK;
PendingTransaction g_tx;
String g_amountInput = ""; // cifre introduse de casier pe keypad
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

void showMessage(const char *line1, const char *line2) {
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
  return httpCode == 429 || httpCode == 503 || httpCode <= 0;
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
  Serial.printf("[PKI] renew POST code=%d\n", code);
  http.end();

  if (code != 200)
    return false;

  StaticJsonDocument<1024> doc;
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
  int ret = mbedtls_pk_parse_public_key(
      &pk, (const unsigned char *)bank_pub_pem, strlen(bank_pub_pem) + 1);
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
    http.end();

    if (code == 200 || code == 400 || code == 403)
      return code;

    if (isRetryableStatus(code)) {
      if (attempt == max_retries)
        return code;
      int wait = computeBackoffMs(attempt, base_delay, cap_delay);
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
    return;
  }

  // Idempotency key generat O SINGURA DATA — refolosit la fiecare retry
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
    Serial.printf("[HTTP] attempt=%d code=%d\n", attempt, httpCode);

    bool retryable = false;

    if (httpCode == 200) {
      JsonDocument doc;
      DeserializationError err = deserializeJson(doc, body);
      String status = "";
      if (!err && doc.containsKey("status"))
        status = jsonGetString(doc["status"]);

      if (status == "APPROVED") {
        showTransaction(amountCents, "APROBAT");
        feedbackPulse();
        http.end();
        return;
      }

      if (status == "DECLINED") {
        // Incearca sa extraga motivul daca exista
        String reason = doc["detail"]["error_code"] | "";
        if (reason == "INSUFFICIENT_FUNDS")
          showTransaction(amountCents, "Fonduri insuf.");
        else
          showTransaction(amountCents, "REFUZAT");
        http.end();
        return;
      }

      // Caz defensiv: gateway ar putea returna 200+CHALLENGE_REQUIRED
      // (in practica vine ca 401, dar tratam si aceasta ramura)
      if (status == "CHALLENGE_REQUIRED") {
        // PaymentResponse este serializat flat — doc["transaction_id"]
        String tx_id = doc["transaction_id"] | "";
        String orig_dpan = doc["original_dpan"] | "";
        http.end();

        if (tx_id.length() == 0 || orig_dpan.length() == 0) {
          showMessage("Eroare challenge", "Date lipsa");
          return;
        }
        showMessage("PIN necesar", "Conf. cu #");
        String pin = collectPin(PIN_MAX_DIGITS, 30000);
        if ((int)pin.length() < PIN_MIN_LENGTH) {
          showMessage("Timeout PIN", nullptr);
          return;
        }
        int challCode = sendChallengeRequestWithPin(tx_id, orig_dpan, pin);
        if (challCode == 200) {
          showTransaction(amountCents, "APROBAT");
          feedbackPulse();
          return;
        } else if (challCode == 400) {
          showMessage("PIN incorect", "Reincercati");
          return;
        } else if (challCode == 403) {
          showMessage("Card blocat", "Contact banca");
          return;
        } else {
          retryable = isRetryableStatus(challCode);
          if (!retryable) {
            showTransaction(amountCents, "Eroare PIN");
            return;
          }
        }
      } else {
        // status necunoscut in HTTP 200 — retryable daca mai sunt incercari
        Serial.printf("[HTTP] Status necunoscut in 200: %s\n", status.c_str());
        retryable = true;
      }

    } else if (httpCode == 401) {
      // CHALLENGE_REQUIRED: FastAPI serializeaza HTTPException ca
      // {"detail": {"error_code": "...", "transaction_id": "...", ...}}
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
      http.end();

      if (transaction_id.length() == 0 || original_dpan.length() == 0) {
        showMessage("Eroare 401", "Date lipsa");
        return;
      }
      showMessage("PIN necesar", "Conf. cu #");
      String pin = collectPin(PIN_MAX_DIGITS, 30000);
      if ((int)pin.length() < PIN_MIN_LENGTH) {
        showMessage("Timeout PIN", nullptr);
        return;
      }
      int challCode =
          sendChallengeRequestWithPin(transaction_id, original_dpan, pin);
      if (challCode == 200) {
        showTransaction(amountCents, "APROBAT");
        feedbackPulse();
        return;
      } else if (challCode == 400) {
        showMessage("PIN incorect", "Reincercati");
        return;
      } else if (challCode == 403) {
        showMessage("Card blocat", "Contact banca");
        return;
      } else {
        retryable = isRetryableStatus(challCode);
        if (!retryable) {
          showTransaction(amountCents, "Eroare PIN");
          return;
        }
      }

    } else if (httpCode == 400) {
      // Erori definitive — NU face retry
      JsonDocument doc;
      deserializeJson(doc, body);
      String errCode = doc["detail"]["error_code"] | "UNKNOWN";
      if (errCode == "INSUFFICIENT_FUNDS")
        showTransaction(amountCents, "Fonduri insuf.");
      else if (errCode == "INVALID_CRYPTOGRAM")
        showTransaction(amountCents, "Criptograma inv.");
      else
        showTransaction(amountCents, ("Err:" + errCode).c_str());
      http.end();
      return;

    } else if (httpCode == 403) {
      showMessage("Card blocat", "Contact banca");
      http.end();
      return;

    } else if (isRetryableStatus(httpCode)) {
      // 429 RATE_LIMIT sau 503 IDEMPOTENCY_STORE_DOWN
      retryable = true;

    } else {
      showTransaction(amountCents, "Eroare sistem");
      http.end();
      return;
    }

    http.end();

    if (!retryable || attempt == max_retries) {
      showTransaction(amountCents, "Eroare sistem");
      return;
    }

    int wait = computeBackoffMs(attempt, base_delay, cap_delay);
    char buf[32];
    snprintf(buf, sizeof(buf), "Retry %ds", wait / 1000);
    showTransaction(amountCents, buf);
    Serial.printf("[HTTP] backoff %d ms (attempt %d)\n", wait, attempt);
    delay(wait);
  }

  showTransaction(amountCents, "Eroare sistem");
}

// ============================================================
// NFC — pastrat pentru compatibilitate (modulul e defect)
// ============================================================

bool sendNfcCommand(const uint8_t *command, uint8_t commandLen,
                    uint8_t *response, uint8_t *responseLength) {
  return nfc.inDataExchange(command, commandLen, response, responseLength);
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
// GET  /payment-request  → trimite datele tranzactiei active la telefon
// POST /payment-response ← primeste DPAN + ATC + MAC de la telefon
// ============================================================

void setupLocalServer() {
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

  // Initializare NVS
  prefs.begin("pki", false);
  if (!prefs.isKey(RENEW_FAILURES_NVS_KEY))
    prefs.putInt(RENEW_FAILURES_NVS_KEY, 0);
  if (!prefs.isKey(STATE_NVS_KEY))
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

  // Sincronizare NTP (necesara pentru timestamp ISO 8601 valid in criptograma)
  configTime(0, 0, "pool.ntp.org", "time.google.com");
  Serial.print("[NTP] Sincronizare");
  time_t now = 0;
  for (int i = 0; i < 20 && now < 1000000000; i++) {
    time(&now);
    delay(500);
    Serial.print(".");
  }
  Serial.println();
  if (now > 1000000000)
    Serial.printf("[NTP] OK — %s", ctime(&now));
  else
    Serial.println("[NTP] AVERTISMENT: Timp nesincronizat");

  // Incarcare certificate mTLS (din NVS sau fallback la PEM-urile hardcodate)
  String loadedCert, loadedKey;
  if (loadClientCredentialsFromNVS(loadedCert, loadedKey)) {
    current_client_cert_pem = loadedCert;
    current_client_key_pem = loadedKey;
    Serial.println("[mTLS] Certificate incarcate din NVS");
  } else {
    current_client_cert_pem = String(client_cert_pem);
    current_client_key_pem = String(client_key_pem);
    if (storeClientCredentialsToNVS(current_client_cert_pem,
                                    current_client_key_pem)) {
      Serial.println("[mTLS] Certificate stocate in NVS");
    }
  }

  String loadedRootCa;
  if (loadRootCaFromNVS(loadedRootCa)) {
    current_root_ca_pem = loadedRootCa;
    Serial.println("[mTLS] CA incarcat din NVS");
  } else {
    current_root_ca_pem = String(root_ca_pem);
    storeRootCaToNVS(current_root_ca_pem);
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

  // NFC — modulul e defect; dezactivat pentru a preveni conflicte de pini cu Keypad, LED si Haptic
  // SPI.begin(PN532_SCK, PN532_MISO, PN532_MOSI, PN532_SS);
  // nfc.begin();
  // nfc.SAMConfig();

  // Verificare reinnoire certificat la boot
  runPkiRenewCheckIfNeeded();
  lastPkiCheckMillis = millis();

  // Pornire server HTTP local pentru comunicare cu telefonul
  if (WiFi.status() == WL_CONNECTED) {
    setupLocalServer();
  }

  showMessage("Introduceti suma:", "---");
  Serial.println("[POS] Gata. Introduceti suma pe keypad si apasati #\n");
}

// ============================================================
// LOOP PRINCIPAL — State Machine WiFi Direct
//
// STATE 0 POS_IDLE:
//   Casierul introduce suma pe keypad (cifre = RON, # = confirma, * = sterg)
//   La confirmare → POS_WAITING_FOR_PHONE
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
        showMessage("Introduceti suma:", "---");
    } else {
      Serial.println("[WiFi] Reconectare esuata");
      showMessage("WiFi EROARE", "Verifica AP");
      delay(3000);
      return;
    }
  }

  // ── STATE 0: IDLE — introducere suma ──────────────────────
  if (g_tx.state == POS_IDLE) {
    char key = keypad.getKey();
    if (!key) {
      delay(50);
      return;
    }

    if (key >= '0' && key <= '9') {
      if (g_amountInput.length() < 6) // max 999999 RON
        g_amountInput += key;
    } else if (key == '*') {
      // Backspace
      if (g_amountInput.length() > 0)
        g_amountInput.remove(g_amountInput.length() - 1);
    } else if (key == '#') {
      // Confirmare suma
      if (g_amountInput.length() == 0) {
        delay(50);
        return;
      }
      long amountRon = g_amountInput.toInt();
      if (amountRon <= 0) {
        showMessage("Suma invalida", "Reintroduceti");
        g_amountInput = "";
        delay(1500);
        showMessage("Introduceti suma:", "---");
        return;
      }

      g_tx.amountCents = (int)(amountRon * 100);
      g_tx.currency = "RON";
      g_tx.posNonce = generatePosNonce();
      g_tx.terminalTimestamp = getIsoTimestamp();
      g_tx.state = POS_WAITING_FOR_PHONE;
      g_tx.stateEnteredAt = millis();
      g_amountInput = "";

      showTransaction(g_tx.amountCents, "Apropiati tel.");
      Serial.printf("[POS] Tranzactie initiata: %d.%02d RON"
                    " | Nonce: %s | Timp: %s\n",
                    g_tx.amountCents / 100, g_tx.amountCents % 100,
                    g_tx.posNonce.c_str(), g_tx.terminalTimestamp.c_str());
      return;
    }

    // Actualizeaza display cu suma curenta
    if (g_amountInput.length() > 0) {
      char buf[32];
      snprintf(buf, sizeof(buf), "%s RON", g_amountInput.c_str());
      showMessage("Suma:", buf);
    } else {
      showMessage("Introduceti suma:", "---");
    }
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
      showMessage("Introduceti suma:", "---");
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
    StaticJsonDocument<512> doc;
    doc["dpan"] = g_tx.dpan;

    JsonObject transaction = doc.createNestedObject("transaction");
    transaction["amount"] = g_tx.amountCents;
    transaction["currency"] = g_tx.currency;
    transaction["pos_nonce"] = g_tx.posNonce;
    transaction["terminal_timestamp"] = g_tx.terminalTimestamp;

    JsonObject cryptogram = doc.createNestedObject("cryptogram");
    cryptogram["mac"] = g_tx.mac;
    cryptogram["atc"] = g_tx.atc;

    String json;
    serializeJson(doc, json);

    sendRequestWithBackoff(json, g_tx.amountCents);

    delay(3000);
    g_tx = PendingTransaction{}; // reset la IDLE
    showMessage("Introduceti suma:", "---");
    return;
  }

  delay(50);
}
