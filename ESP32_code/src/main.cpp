#include <Arduino.h>
#include <SPI.h>
#include <Adafruit_PN532.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <LiquidCrystal_I2C.h>
#include <Keypad.h>
#include <time.h>

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
const char* gateway_url = "https://your-backend-ip/api/v1/payments/authorize";
const char* terminal_id = "POS-001";

// ----- 1. Registry Setup (Bare-Metal GPIO) -------
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

// ----- 3. Networking: Exponential Backoff (Cap 7.0) -------
void sendRequestWithBackoff(String payload, String idempotencyKey) {
  int max_retries = 3;
  int base_delay = 1000;

  for (int i = 0; i <= max_retries; i++) {
    HTTPClient http;
    http.begin(secureClient, gateway_url);
    http.addHeader("Content-Type", "application/json");
    http.addHeader("X-Idempotency-Key", idempotencyKey);
    http.addHeader("X-Terminal-Id", terminal_id);

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

  configTime(0, 0, "pool.ntp.org", "time.google.com");
  secureClient.setInsecure(); // development only

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

    if (success && responseLength >= 2 && response[responseLength - 2] == 0x90 && response[responseLength - 1] == 0x00) {
      String nonce = String(random(0xFFFF), HEX);
      String timestamp = getIsoTimestamp();
      String hcePayload = "15000|RON|" + nonce + "|" + timestamp;
      String hceCommand = String(hcePayload.length()) + "|" + hcePayload;

      uint8_t commandBuffer[128];
      hceCommand.getBytes(commandBuffer, sizeof(commandBuffer));

      GPIO.out_w1tc = PN532_SS_BIT;
      success = nfc.inDataExchange(commandBuffer, hceCommand.length(), response, &responseLength);
      GPIO.out_w1ts = PN532_SS_BIT; 

      if (success && responseLength >= 2 && response[responseLength - 2] == 0x90 && response[responseLength - 1] == 0x00) {
        int payloadLen = responseLength - 2;
        String hceResponse = String((char*)response, payloadLen);
        int firstSep = hceResponse.indexOf('|');
        int secondSep = hceResponse.indexOf('|', firstSep + 1);

        if (firstSep > 0 && secondSep > firstSep) {
          String dpan = hceResponse.substring(0, firstSep);
          String mac = hceResponse.substring(firstSep + 1, secondSep);
          int atc = hceResponse.substring(secondSep + 1).toInt();

          StaticJsonDocument<256> doc;
          doc["dpan"] = dpan;

          JsonObject transaction = doc.createNestedObject("transaction");
          transaction["amount"] = 15000;
          transaction["currency"] = "RON";
          transaction["pos_nonce"] = nonce;
          transaction["terminal_timestamp"] = timestamp;

          JsonObject cryptogram = doc.createNestedObject("cryptogram");
          cryptogram["mac"] = mac;
          cryptogram["atc"] = atc;

          String json;
          serializeJson(doc, json);

          String uuid = String(random(0xFFFF), HEX) + "-4000-8000";
          sendRequestWithBackoff(json, uuid);

          delay(3000);
          lcd.clear();
          lcd.print("Scan Phone/Card");
        } else {
          lcd.setCursor(0, 1);
          lcd.print("HCE Parse Err");
          delay(1000);
          lcd.clear();
          lcd.print("Scan Phone/Card");
        }
      } else {
        lcd.setCursor(0, 1);
        lcd.print("HCE Fail");
        delay(1000);
        lcd.clear();
        lcd.print("Scan Phone/Card");
      }
    } else {
      lcd.setCursor(0, 1);
      lcd.print("Select Fail");
      delay(1000);
      lcd.clear();
      lcd.print("Scan Phone/Card");
    }
  }
  delay(200); 
}