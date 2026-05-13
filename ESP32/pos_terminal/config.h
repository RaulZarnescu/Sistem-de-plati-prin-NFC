#pragma once

// ============================================================
// config.h — Configurația terminalului POS ESP32
//
// Editează valorile de mai jos înainte să compilezi.
// NICIODATĂ nu urca acest fișier pe GitHub cu parole reale!
// ============================================================

// --- WiFi ---------------------------------------------------
#define WIFI_SSID       "NumeleReteleiTale"
#define WIFI_PASSWORD   "ParolaWiFi"

// --- Gateway ------------------------------------------------
// IP-ul calculatorului care rulează Docker Compose.
// Găsești IP-ul cu: ipconfig (Windows) sau ifconfig (Mac/Linux)
// ESP32 și calculatorul trebuie să fie în aceeași rețea WiFi!
#define GATEWAY_URL     "http://192.168.1.100:8001"

// --- Identitate terminal ------------------------------------
// Trebuie să coincidă cu un terminal ne-revocat din Redis.
// Același ID e folosit în header-ul X-Terminal-Id.
#define TERMINAL_ID     "POS-ESP32-001"

// --- Pini PN532 (I2C) ---------------------------------------
// SDA → GPIO 21 (implicit I2C pe ESP32)
// SCL → GPIO 22 (implicit I2C pe ESP32)
// IRQ → GPIO 4  (configurabil mai jos)
// RST → GPIO 5  (configurabil mai jos)
#define PN532_IRQ_PIN   4
#define PN532_RESET_PIN 5

// --- Sumă implicită de plată --------------------------------
// Valoarea afișată pe "ecranul" POS-ului (Serial Monitor în PoC).
// Producție: introdusă de comerciant pe tastatură numerică.
#define PAYMENT_AMOUNT_CENTS  5000    // 50.00 RON
#define PAYMENT_CURRENCY      "RON"
