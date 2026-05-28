// ============================================================
// provisioning.cpp — Provisioning NVS pentru ESP32 POS
//
// Scop:
//   Scrie certificatele mTLS (CA, client cert, client key, bank pub)
//   în NVS (Non-Volatile Storage) criptat cu AES-GCM.
//
// Utilizare:
//   1. Flash acest sketch pe ESP32
//   2. Rulează scripts/provision_esp32.py care trimite certificatele
//      din certs/ pe Serial
//   3. Flash codul principal (ESP32_code/src/main.cpp)
//
// Protocolul Serial:
//   Scriptul Python trimite fiecare certificat ca:
//     CERT_KEY\n         (ex: "root_ca\n")
//     ...PEM content...
//     <<<END>>>\n
//   ESP32 răspunde cu:
//     OK:CERT_KEY\n       (dacă stocarea a reușit)
//     ERR:CERT_KEY:msg\n  (dacă a eșuat)
//
// Chei NVS acceptate:
//   root_ca    → CA root (NFC-Payment-CA) — validează serverul NGINX
//   mtls_cert  → Certificat client mTLS (POS-BUC-001)
//   mtls_key   → Cheie privată client mTLS
//   bank_pub   → Cheie publică RSA a băncii (criptare PIN block)
//
// Securitate NVS:
//   Toate valorile sunt criptate cu AES-256-GCM înainte de stocare.
//   Cheia AES este aceeași ca în main.cpp (CERT_ENC_KEY).
//   În producție, această cheie ar fi provisionată via eFuse/secure boot.
// ============================================================

#include <Arduino.h>
#include <Preferences.h>
#include <mbedtls/base64.h>
#include <mbedtls/gcm.h>
#include <mbedtls/sha256.h>
#include <vector>

// ── Cheie AES-GCM identică cu main.cpp ────────────────────────
// (Opțiunea A: duplicare. În producție se mută într-un header partajat)
static const uint8_t CERT_ENC_KEY[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
    0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
    0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};

static const int CERT_IV_LEN = 12;
static const int CERT_TAG_LEN = 16;

Preferences prefs;

// ── Funcții criptografice (copiate din main.cpp — opțiunea A) ──

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

// ── Chei NVS valide ──────────────────────────────────────────
const char *VALID_KEYS[] = {"root_ca", "mtls_cert", "mtls_key", "bank_pub"};
const int NUM_VALID_KEYS = 4;

bool isValidKey(const String &key) {
  for (int i = 0; i < NUM_VALID_KEYS; i++) {
    if (key == VALID_KEYS[i])
      return true;
  }
  return false;
}

// ── Citire PEM de pe Serial ──────────────────────────────────
// Protocol: prima linie = numele cheii, apoi conținutul PEM,
// terminat cu "<<<END>>>" pe o linie separată.
String readPemFromSerial(String &outKey) {
  // Citim prima linie = numele cheii
  outKey = Serial.readStringUntil('\n');
  outKey.trim();

  if (outKey.length() == 0) {
    return "";
  }

  // Citim conținutul PEM până la delimitatorul de final
  String pem = "";
  unsigned long timeout = millis() + 30000; // 30s timeout

  while (millis() < timeout) {
    if (Serial.available()) {
      String line = Serial.readStringUntil('\n');
      line.trim();
      if (line == "<<<END>>>") {
        break;
      }
      pem += line + "\n";
    }
    delay(1);
  }

  return pem;
}

// ── SHA-256 fingerprint (primii 8 bytes) ─────────────────────
void printFingerprint(const String &pem, const char *label) {
  uint8_t hash[32];
  mbedtls_sha256((const uint8_t *)pem.c_str(), pem.length(), hash, 0);
  Serial.printf("[PROV] %s SHA256: ", label);
  for (int i = 0; i < 8; i++) {
    Serial.printf("%02X", hash[i]);
    if (i < 7)
      Serial.print(":");
  }
  Serial.printf(" (%d bytes)\n", pem.length());
}

// ── Setup ────────────────────────────────────────────────────
void setup() {
  Serial.begin(115200);
  delay(2000); // Așteptăm Serial Monitor

  Serial.println("\n====================================================");
  Serial.println("  ESP32 POS — PROVISIONING NVS");
  Serial.println("====================================================");
  Serial.println("Protocol: trimite pe Serial:");
  Serial.println("  CERT_KEY<newline>");
  Serial.println("  ...PEM content...");
  Serial.println("  <<<END>>><newline>");
  Serial.println();
  Serial.println("Chei acceptate: root_ca, mtls_cert, mtls_key, bank_pub");
  Serial.println("Trimite 'DONE' pentru a finaliza și verifica.");
  Serial.println("Trimite 'WIPE' pentru a șterge tot NVS-ul pki.");
  Serial.println("====================================================");
  Serial.println("READY");
}

// ── Loop ─────────────────────────────────────────────────────
void loop() {
  if (!Serial.available())
    return;

  // Peek la prima linie
  String firstLine = Serial.readStringUntil('\n');
  firstLine.trim();

  // Comandă specială: DONE → afișează status final
  if (firstLine == "DONE") {
    Serial.println("\n[PROV] === VERIFICARE FINALĂ ===");
    prefs.begin("pki", true);
    for (int i = 0; i < NUM_VALID_KEYS; i++) {
      String val = prefs.getString(VALID_KEYS[i], "");
      if (val.length() > 0) {
        Serial.printf("[PROV] ✓ %s: %d bytes (criptat)\n", VALID_KEYS[i],
                      val.length());
      } else {
        Serial.printf("[PROV] ✗ %s: LIPSEȘTE!\n", VALID_KEYS[i]);
      }
    }
    prefs.end();
    Serial.println("[PROV] Provisioning complet. Flashează codul principal.");
    Serial.println("OK:DONE");
    return;
  }

  // Comandă specială: WIPE → șterge tot NVS-ul pki
  if (firstLine == "WIPE") {
    prefs.begin("pki", false);
    prefs.clear();
    prefs.end();
    Serial.println("[PROV] NVS pki șters complet.");
    Serial.println("OK:WIPE");
    return;
  }

  // Altfel: interpretăm ca numele unei chei, urmată de PEM + <<<END>>>
  String key = firstLine;
  if (!isValidKey(key)) {
    Serial.printf("ERR:%s:Cheie invalida. Acceptate: root_ca, mtls_cert, "
                  "mtls_key, bank_pub\n",
                  key.c_str());
    // Consumăm restul până la <<<END>>> ca să nu corupem protocolul
    unsigned long timeout = millis() + 10000;
    while (millis() < timeout) {
      if (Serial.available()) {
        String line = Serial.readStringUntil('\n');
        line.trim();
        if (line == "<<<END>>>")
          break;
      }
      delay(1);
    }
    return;
  }

  // Citim PEM-ul
  String pem = "";
  unsigned long timeout = millis() + 30000;
  while (millis() < timeout) {
    if (Serial.available()) {
      String line = Serial.readStringUntil('\n');
      line.trim();
      if (line == "<<<END>>>") {
        break;
      }
      pem += line + "\n";
    }
    delay(1);
  }

  if (pem.length() == 0) {
    Serial.printf("ERR:%s:PEM gol sau timeout\n", key.c_str());
    return;
  }

  // Afișăm fingerprint pentru verificare vizuală
  printFingerprint(pem, key.c_str());

  // Stocăm criptat în NVS
  if (storeEncryptedStringToNVS(pem, key.c_str())) {
    Serial.printf("OK:%s\n", key.c_str());
  } else {
    Serial.printf("ERR:%s:Eroare la stocarea in NVS\n", key.c_str());
  }
}
