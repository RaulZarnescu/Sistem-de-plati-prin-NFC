# Ghid Complet de Cablare Hardware - POS ESP32

Acest fișier reprezintă harta exactă a conexiunilor fizice dintre **ESP32** și toate componentele hardware ale POS-ului: **Display-ul TFT LCD (8-bit paralel)**, **Tastatura Matriceală 3x4**, **LED-ul de stare** și **Motorul Haptic**.

Urmează tabelele de mai jos pentru a te asigura că fiecare fir este conectat la pinul corect și înțelege rolul electronic al fiecărui pin pentru a preveni comportamentele nedorite (cum ar fi erorile de bootloop sau ecranele stinse).

---

## ⚠️ Pinii de Strapping ESP32 — Citește Înainte de Orice

ESP32 citește câțiva pini speciali **înainte de a executa orice cod**, imediat la power-on, pentru a decide cum să pornească. Dacă oricare dintre acești pini este tras la HIGH de un component extern în momentul alimentării, ESP32 poate porni în modul greșit sau poate configura flash-ul la tensiunea greșită — ducând la erori fatale și buclă de reset infinită.

| Pin GPIO | Rol la boot | Nivel SAFE la boot | Consecința nivelului GREȘIT |
| :--- | :--- | :--- | :--- |
| **GPIO 0** | Mod boot (NORMAL vs. DOWNLOAD) | **HIGH** = normal | LOW = intră în mod flash, nu pornește |
| **GPIO 2** | Condiție download mode | **LOW** (sau flotant) | — |
| **GPIO 5** | SPI boot timing (SDIO CLK) | **HIGH** | Modificare timing, rar critic |
| **GPIO 12** | Tensiunea flash SPI (**MTDI**) | **LOW** = 3.3V ✅ | **HIGH = flash la 1.8V → `invalid header: 0xffffffff` → bootloop** |
| **GPIO 15** | Activare log-uri boot pe UART | HIGH = log activ | LOW = fără log, bootează normal |

**Regula de aur:** Nu conecta niciodată un component care poate trage GPIO 12 la HIGH înainte sau în momentul pornirii ESP32.

---

## 1. Conexiunile de Alimentare (Cruciale)

Înainte de a conecta pinii de date, asigură-te că alimentarea este făcută corect. Folosirea unei singure surse prin cablul USB conectat la ESP32 este cea mai stabilă cale:

| Pin pe Display TFT | Pin pe ESP32 | Rol / Explicație | De ce am ales acest pin? |
| :--- | :--- | :--- | :--- |
| **5V** (sau **VCC**) | **5V** (sau **VIN** / **5V0**) | Alimentarea principală a ecranului | **Obligatoriu**: Ecranul are un regulator de tensiune local și leduri de iluminare (backlight) puternice care necesită 5V de la mufa USB a ESP32. Alimentarea la 3.3V nu va porni ecranul. |
| **GND** | **GND** (sau **G**) | Masa comună de referință | **Critic**: Fără o masă comună între ESP32 și ecran, semnalele digitale vor fi interpretate ca zgomot, iar bootloader-ul ESP32 se va bloca în mod repetat. |
| **LED** (sau **BL** / **backlight**) | **3.3V** sau **5V** | Alimentarea LED-urilor de iluminare din spate | **Obligatoriu pentru imagine vizibilă**: Shield-ul mcufriend are rezistențe limitatoare de curent integrate — conectează direct fără rezistență externă. Fără acest fir, ecranul rămâne complet negru chiar dacă firmware-ul rulează corect. |

---

## 2. Magistrala de Date & Control Display TFT (8-bit Paralel)

Biblioteca `MCUFRIEND_kbv` folosește o alocare hardware extrem de rapidă pe ESP32.

> **ATENȚIE CRITICĂ — GPIO 12 mutat pe GPIO 22:**
> Schema anterioară conecta `LCD_D0` la **GPIO 12**, care este pinul de strapping **MTDI** al ESP32.
> Controlerul ILI9325 poate ține pinii de date la HIGH în faza de inițializare la power-on —
> suficient ca ESP32 să citească MTDI=HIGH și să configureze flash-ul la 1.8V.
> Rezultat: `invalid header: 0xffffffff` + `RTCWDT_RTC_RESET` → buclă de reset infinită,
> backlight stins, firmware niciodată rulat.
> **GPIO 12 este acum mutat pe GPIO 22 (pin liber, fără funcții speciale).**

| Pin pe Ecran (Uno Shield) | Pin pe ESP32 (GPIO) | Rol Semnal | De ce acest pin și ce face? |
| :--- | :--- | :--- | :--- |
| **LCD_D0** | **GPIO 22** ⚠️ *(era GPIO 12 — mutat!)* | Bit de date 0 | **GPIO 22** este un pin standard fără rol de strapping și fără funcții interne speciale. GPIO 12 (fostul pin) este pinul MTDI de strapping și cauza directă a erorii `invalid header: 0xffffffff`. |
| **LCD_D1** | **GPIO 13** | Bit de date 1 | Port de date de viteză. |
| **LCD_D2** | **GPIO 26** | Bit de date 2 | Port de date de viteză. |
| **LCD_D3** | **GPIO 25** | Bit de date 3 | Port de date de viteză. |
| **LCD_D4** | **GPIO 17** | Bit de date 4 | Port de date de viteză. |
| **LCD_D5** | **GPIO 16** | Bit de date 5 | Port de date de viteză. |
| **LCD_D6** | **GPIO 27** | Bit de date 6 | Port de date de viteză. |
| **LCD_D7** | **GPIO 14** | Bit de date 7 | Port de date de viteză. Cel mai semnificativ bit. |
| **LCD_RS** (sau **CD**) | **GPIO 15** | Register Select / Command-Data | Indică ecranului dacă datele trimise sunt comenzi de configurare sau pixeli de desenat. *GPIO 15 este pin de strapping (controlează log-urile UART la boot) — nu cauzează bootloop, dar poate suprima mesajele Serial dacă este tras la LOW.* |
| **LCD_WR** | **GPIO 4** | Write Strobe | Pinul de tact pentru scriere. De fiecare dată când acest pin trece din HIGH în LOW, ecranul citește starea pinilor D0-D7. |
| **LCD_CS** | **GND** *(sau GPIO 33)* | Chip Select | Activează comunicația cu ecranul. Legat permanent la **GND** economisește pinul GPIO 33. |
| **LCD_RST** | **EN** (sau **GPIO 32**) | Hardware Reset | Resetează ecranul la pornire. Legat la pinul **EN / RST** al ESP32 pentru resetare automată la boot. |
| **LCD_RD** | **3.3V** *(sau GPIO 2)* | Read Strobe | Folosit doar când citim date din ecran. Deoarece noi doar scriem pe ecran, îl legăm permanent la **3.3V**. *Nu folosi GPIO 2 pentru LCD_RD dacă dorești să uploadezi firmware fără a deconecta firul (GPIO 2 trebuie să fie LOW în mod download).* |

### Configurarea bibliotecii MCUFRIEND_kbv pentru GPIO 22

Mutarea `LCD_D0` pe GPIO 22 necesită modificarea fișierului de pin-mapping din bibliotecă.
Localizează `MCUFRIEND_shield.h` (sau `pin_magic.h`) în folderul `.pio/libdeps/esp32dev/MCUFRIEND_kbv/`
și asigură-te că definiția pentru D0 pe ESP32 arată:

```cpp
// Modifică această linie în fișierul de configurare al bibliotecii:
// ÎNAINTE: #define LCD_D0  12
// DUPĂ:
#define LCD_D0  22
```

Alternativ, dacă biblioteca permite override în `platformio.ini`:
```ini
build_flags =
    -DLCD_D0=22
```

---

## 3. Tastatura Matriceală 3x4 (Remapată)

Tastatura a fost redusă la 3 coloane (fără tastele 'A'-'D' care nu sunt necesare) pentru a elibera pini și a fost mutată pe pini fără conflicte cu ecranul:

| Rând / Coloană Tastatură | Pin pe ESP32 (GPIO) | Direcție Semnal | Rol & Detalii Electronice |
| :--- | :--- | :--- | :--- |
| **Rândul 1** (Row 1) | **GPIO 34** | **Intrare (Input)** | Citește starea tastelor 1, 2, 3. *Necesită o rezistență externă de 10kΩ legată la 3.3V deoarece GPIO 34 este Input-only și nu are pull-up intern.* |
| **Rândul 2** (Row 2) | **GPIO 35** | **Intrare (Input)** | Citește tastele 4, 5, 6. *Necesită rezistență externă de 10kΩ legată la 3.3V.* |
| **Rândul 3** (Row 3) | **GPIO 36** | **Intrare (Input)** | Citește tastele 7, 8, 9. *Necesită rezistență externă de 10kΩ legată la 3.3V.* |
| **Rândul 4** (Row 4) | **GPIO 39** | **Intrare (Input)** | Citește tastele *, 0, #. *Necesită rezistență externă de 10kΩ legată la 3.3V.* |
| **Coloana 1** (Col 1) | **GPIO 19** | **Ieșire (Output)** | Controlează scanarea primei coloane (1, 4, 7, *). |
| **Coloana 2** (Col 2) | **GPIO 23** | **Ieșire (Output)** | Controlează scanarea coloanei a doua (2, 5, 8, 0). |
| **Coloana 3** (Col 3) | **GPIO 21** | **Ieșire (Output)** | Controlează scanarea coloanei a treia (3, 6, 9, #). |

---

## 4. Elementele de Feedback (LED și Haptic)

Mulate de pe pinii originali (GPIO 2 și 4) pentru a lăsa magistrala ecranului curată:

| Componentă | Pin pe ESP32 (GPIO) | Direcție Semnal | Rol |
| :--- | :--- | :--- | :--- |
| **LED_PIN** (Stare POS) | **GPIO 5** | Ieșire (Output) | LED-ul care clipește la pornire, conectare WiFi și confirmare tranzacții. |
| **HAPTIC_PIN** (Motor Vibrator) | **GPIO 18** | Ieșire (Output) | Declanșează vibrația dublă (pulsul haptic) atunci când o tranzacție este aprobată cu succes de server. |

> **Notă despre conflicte de pini PN532:** Codul conține `#define`-uri rămase din versiunea cu NFC (PN532_SS=5, PN532_SCK=18, PN532_MISO=19, PN532_MOSI=23) care se suprapun cu LED_PIN, HAPTIC_PIN și coloanele tastaturii. PN532 nefiind conectat fizic, conflictele sunt inactive. Totuși, biblioteca Adafruit_PN532 poate configura acele GPIO-uri la `setup()` — dacă observi comportament ciudat al tastaturii sau al LED-ului, dezactivează inițializarea PN532 din cod.

---

## 5. Ghid de Diagnostic Rapid (Probleme frecvente)

1. **`invalid header: 0xffffffff` + `RTCWDT_RTC_RESET` pe Serial (buclă de reset):**
   * **Cauza directă**: Un pin conectat la ecran ținea **GPIO 12** la nivel HIGH în momentul pornirii. GPIO 12 este pinul de strapping MTDI al ESP32 și setează tensiunea flash-ului SPI.
   * **Fix hardware imediat** (fără modificare de cod): Adaugă o rezistență de **10kΩ între GPIO 12 și GND**. Aceasta forțează GPIO 12 la LOW în fereastra de strapping, indiferent de ce face ecranul.
   * **Fix permanent**: Mută `LCD_D0` de pe GPIO 12 pe **GPIO 22** (vezi Secțiunea 2).

2. **Ecranul rămâne complet negru (fără lumină deloc):**
   * Verifică dacă pinul **`LED`** (sau `BL` / `backlight`) al ecranului este conectat la **3.3V** sau **5V** (vezi Secțiunea 1).
   * Verifică dacă pinul **`5V`** al ecranului primește curent direct din pinul **`5V`** sau **`VIN`** al ESP32.

3. **Placa ESP32 se resetează în buclă la boot (dar fără `0xffffffff`):**
   * Asigură-te că ai conectat firul de **`GND`** între cele două plăci.
   * Alimentează ecranul **după** ce ai pornit ESP32-ul (introducând cablul USB), nu înainte.

4. **Unele taste din aceeași coloană sau rând nu funcționează:**
   * Verifică rezistențele de pull-up de pe pinii rândurilor (GPIO 34, 35, 36, 39). Fără aceste rezistențe legate la 3.3V, pinii vor colecta zgomot electromagnetic și vor raporta apăsări false sau nu vor citi deloc tastele.

5. **LED-ul sau motorul haptic nu răspund / tastatura trimite valori greșite:**
   * Verifică dacă `nfc.begin()` sau echivalentul PN532 este apelat în `setup()` — biblioteca poate reconfigura GPIO 5, 18, 19, 23 ca pini SPI, suprascriind configurația tastaturii și feedback-ului. Comentează sau elimină inițializarea PN532 din cod.
