#include <Arduino.h>
#include <SPI.h>
#include<Adafruit_PN532.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <mbedtls/md.h>
// ----- Hardware Registry definition ------
#include "soc/gpio_reg.h"
#include "soc/io_mux_reg.h"
#define PN532_SS_BIT ( 1 << 5)
// ----- NFC Pinout ------- 
#define PN532_SCK (18)
#define PN532_MOSI (23)
#define PN532_MISO (19)
#define PN532_SS (5)

Adafruit_PN532 nfc(PN532_SS);
WiFiClientSecure secureClient;

//----Project Config-----

const char* ssid = "your_wifi_ssid";
const char* password = "your_wifi_password";
const char* gateway_url = "https://yout-backend-ip/api/payments/authorize";
const char* K_USER = "cheie_secreta_utilizator";

//-----Registry setup-------

void setup_registru_hardware(){
  PIN_FUNC_SELECT(GPIO_PIN_MUX_REG[5],PIN_FUNC_GPIO);
  GPIO.enable_w1ts = PN532_SS_BIT;
  GPIO.out_w1ts = PN532_SS_BIT;
}

String calculateHMAC(String data, String key){
  byte hmacResult[32];
  mbedtls_md_context_t ctx;
  mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);
  mbedtls_md_hmac_starts(&ctx, (const unsigned char*)key.c_str(),key.length());
  mbedtls_md_hmac_update(&ctx, (const unsigned char*) data.c_str(),data.length());
  mbedtls_md_hmac_finish(&ctx, hmacResult);
  mbedtls_md_free(&ctx);

  String hash = "";
  for(int i =0; i < 32; i++){
    char str[3];
    sprintf(str, "%02x", hmacResult[i]);
    hash += str;
  }
  return hash;
}

void sendRequestWithBackoff(String payload, String idempotencyKey){
  int max_retries = 3;
  int base_delay = 1000;

  for (int i =0; i<= max_retries; i++){
    HTTPClient http;
    http.begin(secureClient, gateway_url);
    http.addHeader("Content-Type", "application/json");
    http.addHeader("X-Idempotency-Key", idempotencyKey);

    int httpCode = http.POST(payload);
    if(httpCode == 200){
      Serial.println("Success");
      http.end();
      return;
    }else{
      int wait = random(0, base_delay * (1 << i));
      Serial.printf("Retrying in %d ms.../n",wait);
      delay(wait);
    }
    http.end();
  }
}

void setup() {
  Serial.begin(115200);
  setup_registru_hardware();

  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) delay(500);

  nfc.begin();
  nfc.SAMConfig();
  Serial.println("POS Ready");
} 

void loop() {
  uint8_t success;
  uint8_t uid[] = {0, 0, 0, 0, 0, 0, 0};
  uint8_t uidLength;

  success = nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength);
  if(success){
    uint8_t selectApp[] = {0x00, 0xA4, 0x04, 0x00, 0x07, 0xF1, 0xC7, 0x1B, 0x3B, 0x4E, 0x4B, 0x01};
    uint8_t response[255];
    uint8_t responseLength;

    GPIO.out_w1tc = PN532_SS_BIT;
    success = nfc.inDataExchange(selectApp, sizeof(selectApp), response, &responseLength);
    GPIO.out_w1ts = PN532_SS_BIT;

    if(success && response[responseLength-2] == 0x90){
      String nonce = String(random(0xFFFF),HEX);
      String timestamp = "2026-04-10T14:30:00Z";
      String payload_raw = "15000|RON|" + nonce + "|" + timestamp + "|1";
      String mac = calculateHMAC(payload_raw, K_USER);
      String uuid = String(random(0xFFFF), HEX) + "-4000-8000";

      JsonDocument doc;
      doc["amount"] = 15000;
      doc["currency"] = "RON";
      doc["nonce"] = nonce;
      doc["mac"] = mac;

      String json;
      serializeJson(doc, json);
      sendRequestWithBackoff(json, uuid);
    }
  }
  delay(500);
}