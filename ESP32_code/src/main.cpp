#include <Arduino.h>
#include <SPI.h>
#include <Adafruit_PN532.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <mbedtls/md.h>
#include <LiquidCrystal_I2C.h>
#include <Keypad.h>

// ----- Hardware Registry definitions (DOIT DevKit V1) ------
#include "soc/gpio_reg.h"
#include "soc/io_mux_reg.h"

// Registry Bitmask for Pin 5 (NFC Slave Select)
#define PN532_SS_BIT (1 << 5)

// ----- Pinout Mapping ------- 
// NFC (VSPI Bus)
#define PN532_SCK  (18)
#define PN532_MISO (19)
#define PN532_MOSI (23)
#define PN532_SS   (5)

// I2C LCD (Standard ESP32 I2C Pins)
#define SDA_PIN 21
#define SCL_PIN 22

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
LiquidCrystal_I2C lcd(0x27, 16, 2); 
Keypad keypad = Keypad(makeKeymap(keys), rowPins, colPins, ROWS, COLS);

// ---- Project Configuration -----
const char* ssid = "your_wifi_ssid";
const char* password = "your_wifi_password";
const char* gateway_url = "https://your-backend-ip/api/payments/authorize";
const char* K_USER = "cheie_secreta_utilizator_123";

// ----- 1. Registry Setup (Bare-Metal GPIO) -------
void setup_registru_hardware() {
  // Configure Pin 5 as a GPIO and enable output at registry level
  PIN_FUNC_SELECT(GPIO_PIN_MUX_REG[5], PIN_FUNC_GPIO);
  GPIO.enable_w1ts = PN532_SS_BIT; 
  GPIO.out_w1ts = PN532_SS_BIT; // Set High (Deselected)
}

// ----- 2. Security: HMAC-SHA256 calculation -------
String calculateHMAC(String data, String key) {
  byte hmacResult[32];
  mbedtls_md_context_t ctx;
  mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);
  mbedtls_md_hmac_starts(&ctx, (const unsigned char*)key.c_str(), key.length());
  mbedtls_md_hmac_update(&ctx, (const unsigned char*)data.c_str(), data.length());
  mbedtls_md_hmac_finish(&ctx, hmacResult);
  mbedtls_md_free(&ctx);

  String hash = "";
  for (int i = 0; i < 32; i++) {
    char str[3];
    sprintf(str, "%02x", (int)hmacResult[i]);
    hash += str;
  }
  return hash;
}

// ----- 3. Networking: Exponential Backoff (Cap 7.0) -------
void sendRequestWithBackoff(String payload, String idempotencyKey) {
  int max_retries = 3;
  int base_delay = 1000;

  for (int i = 0; i <= max_retries; i++) {
    HTTPClient http;
    http.begin(secureClient, gateway_url);
    http.addHeader("Content-Type", "application/json");
    http.addHeader("X-Idempotency-Key", idempotencyKey);

    int httpCode = http.POST(payload);
    if (httpCode == 200) {
      lcd.setCursor(0, 1);
      lcd.print("Approved!       ");
      http.end();
      return;
    } else {
      int wait = random(0, base_delay * (1 << i));
      lcd.setCursor(0, 1);
      lcd.print("Retry in "); lcd.print(wait / 1000); lcd.print("s");
      delay(wait);
    }
    http.end();
  }
  lcd.clear();
  lcd.print("System Error");
}

void setup() {
  Serial.begin(115200);
  
  setup_registru_hardware();

  lcd.init();
  lcd.backlight();
  lcd.print("Connecting...");

  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) delay(500);

  lcd.clear();
  lcd.print("WiFi Online");
  
  nfc.begin();
  nfc.SAMConfig();
  
  delay(1000);
  lcd.clear();
  lcd.print("Scan Phone/Card");
}

void loop() {
  char key = keypad.getKey();
  if (key) {
    Serial.print("Key pressed: "); Serial.println(key);
  }

  uint8_t success;
  uint8_t uid[] = {0, 0, 0, 0, 0, 0, 0};
  uint8_t uidLength;

  success = nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength);
  
  if (success) {
    lcd.clear();
    lcd.print("Card Found");
    
    uint8_t selectApp[] = {0x00, 0xA4, 0x04, 0x00, 0x07, 0xF1, 0xC7, 0x1B, 0x3B, 0x4E, 0x4B, 0x01};
    uint8_t response[255];
    uint8_t responseLength;

    GPIO.out_w1tc = PN532_SS_BIT;
    success = nfc.inDataExchange(selectApp, sizeof(selectApp), response, &responseLength);
    GPIO.out_w1ts = PN532_SS_BIT; 

    if (success && response[responseLength - 2] == 0x90) {
      lcd.setCursor(0, 1);
      lcd.print("Authorizing...");

      String nonce = String(random(0xFFFF), HEX);
      String timestamp = "2026-04-10T14:30:00Z";
      String payload_raw = "15000|RON|" + nonce + "|" + timestamp + "|1";
      String mac = calculateHMAC(payload_raw, K_USER);
      String uuid = String(random(0xFFFF), HEX) + "-4000-8000";

      JsonDocument doc;
      doc["amount"] = 15000; // 150.00 RON
      doc["currency"] = "RON";
      doc["nonce"] = nonce;
      doc["mac"] = mac;

      String json;
      serializeJson(doc, json);
      
      sendRequestWithBackoff(json, uuid);
      
      delay(3000);
      lcd.clear();
      lcd.print("Scan Phone/Card");
    } else {
      lcd.setCursor(0, 1);
      lcd.print("NFC Fail");
      delay(1000);
      lcd.clear();
      lcd.print("Scan Phone/Card");
    }
  }
  delay(200); 
}