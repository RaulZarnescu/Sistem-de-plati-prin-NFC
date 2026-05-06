#include <Arduino.h>
#include <SPI.h>
#include<Adafruit_PN532.h>

#define PN532_SCK (18)
#define PN532_MOSI (23)
#define PN532_SS (5)
#define PN532_MISO (19)

Adafruit_PN532 nfc(PN532_SS);


void setup() {
  Serial.begin(115200);
  Serial.println("Initializing P532...");
  nfc.begin();

  uint32_t versiondata = nfc.getFirmwareVersion();
  if (!versiondata) {
    Serial.print("Didn't find PN53x board");
    while (1);
   }

   nfc.SAMConfig();
   Serial.println("PN532 initialized");
}

void loop() {
  uint8_t success;
  uint8_t uid[] = {0,0,0,0,0,0,0};
  uint8_t uidLength;

  success = nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength);

  if (success) {
    Serial.println("Found an ISO14443A card");
    nfc.PrintHex(uid, uidLength);
    Serial.println("Attempting to select Payment App....");

    uint8_t selectApp[] = {0x00, 0xA4, 0x04, 0x00, 0x07, 0xF1, 0x1B, 0x3B, 0x4E, 0x4B, 0x01};
    uint8_t response[255];
    uint8_t responseLength;

    success = nfc.inDataExchange(selectApp, sizeof(selectApp), response, &responseLength);

    if(success){
      if(response[responseLength - 2] == 0x90 && response[responseLength - 1] == 0x00){
        Serial.println("Payment App selected successfully!");
      } else {
        Serial.print("Failed to select Payment App.");
      }
    }

  }

  delay(1000);
}