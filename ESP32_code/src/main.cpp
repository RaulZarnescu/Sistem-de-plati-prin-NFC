#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <mbedtls/md.h>
#include <Adafruit_PN532.h>
#include <ArduinoJson.hpp>

#define PN532_SCK  (18)
#define PN532_MISO (19)
#define PN532_MOSI (23)
#define PN532_SS   (5)
Adafruit_PN532 nfc(PN532_SCK, PN532_MISO, PN532_MOSI, PN532_SS);

const char* test_client_cert = "-----BEGIN CERTIFICATE-----\n";
const char* test_client_key = "-----BEGIN PRIVATE KEY-----\n";
const char* test_ca_cert = "-----BEGIN CERTIFICATE-----\n";


// put function declarations here:
int myFunction(int, int);

void setup() {
  // put your setup code here, to run once:
  int result = myFunction(2, 3);
}

void loop() {
  // put your main code here, to run repeatedly:
}

// put function definitions here:
int myFunction(int x, int y) {
  return x + y;
}