package com.example.sistemplatanfc.data

import android.content.Context
import android.util.Log
import com.example.sistemplatanfc.model.BankCard
import com.example.sistemplatanfc.security.KeystoreManager
import com.example.sistemplatanfc.security.SecureStorage

/**
 * Înrolează automat 3 carduri de test la primul start al aplicației.
 *
 * De ce există acest fișier?
 * Nu avem backend de enrollment disponibil, deci hardcodăm cardurile
 * care corespund datelor seed din baza de date TSP + băncile emitente.
 *
 * Carduri disponibile:
 *   BT   → DPAN 4000000000000001 (Visa,       last 4: 1111)
 *   BCR  → DPAN 5000000000000002 (Mastercard, last 4: 2222)
 *   ING  → DPAN 5000000000000003 (Mastercard, last 4: 3333)
 *
 * Cheile HMAC corespund cu ISSUING_BANK_HMAC_MASTER_KEY din .env al fiecărei bănci.
 * IMPORTANT: Acestea sunt chei de test — nu le folosi în producție!
 */
object DevCardSeeder {

    private const val TAG = "DevCardSeeder"
    private const val PREF_KEY_SEEDED = "dev_cards_seeded_v1"
    private const val PLAIN_PREFS = "plain_prefs"

    // ─── Date de test (sincronizate cu db/init/tsp/01_schema.sql și .env) ──────

    private data class SeedCard(
        val id: String,
        val bankName: String,
        val dpan: String,
        val hmacKeyHex: String,
        val cardType: String,
        val lastFour: String
    )

    private val TEST_CARDS = listOf(
        SeedCard(
            id          = "card_bt_001",
            bankName    = "Banca Transilvania",
            dpan        = "4000000000000001",
            // BANK_BT_HMAC_KEY din .env
            hmacKeyHex  = "6f8d2b9a1c4e7f3d5b0e8a4c2f1d9e7b5a3c8f0d4e2b1a9c7f6d5e4b3a2c1f0e",
            cardType    = "VISA",
            lastFour    = "1111"
        ),
        SeedCard(
            id          = "card_bcr_001",
            bankName    = "BCR",
            dpan        = "5000000000000002",
            // BANK_BCR_HMAC_KEY din .env
            hmacKeyHex  = "c98fcaa4e11fc749d19700af104603cec1b4f058bc85a46c734c81892d2caf3e",
            cardType    = "MASTERCARD",
            lastFour    = "2222"
        ),
        SeedCard(
            id          = "card_ing_001",
            bankName    = "ING Bank",
            dpan        = "5000000000000003",
            // BANK_ING_HMAC_KEY din .env
            hmacKeyHex  = "b700832facdf4074f2d8222d5d3916e87e3d728ca976f3f030f36653838e87f1",
            cardType    = "MASTERCARD",
            lastFour    = "3333"
        )
    )

    /**
     * Populează cardurile de test la fiecare pornire a aplicației.
     *
     * De ce la fiecare pornire?
     * CardManager._cards este o listă IN MEMORIE (mutableStateListOf).
     * Android poate opri procesul oricând → la repornire lista e goală.
     * SharedPreferences și Keystore sunt PERSISTENTE → le folosim doar
     * pentru operații costisitoare (import cheie) care nu trebuie repetate.
     *
     * Logica:
     *   1. Dacă cheia HMAC NU e în Keystore → o importăm (prima rulare)
     *   2. Dacă cardul NU e deja în CardManager → îl adăugăm (fiecare repornire)
     *
     * @param context  Context Android (Application sau Activity)
     */
    fun seed(context: Context) {
        val prefs = context.getSharedPreferences(PLAIN_PREFS, Context.MODE_PRIVATE)
        val keysImported = prefs.getBoolean(PREF_KEY_SEEDED, false)

        val secureStorage = SecureStorage.getInstance(context)

        // ID-urile cardurilor deja prezente în memorie — evităm duplicate
        val existingIds = CardManager.cards.map { it.id }.toSet()

        for (seed in TEST_CARDS) {
            try {
                // 1. Import cheie Keystore — DOAR dacă nu există deja (operație persistentă)
                if (!keysImported || !KeystoreManager.hasKey(seed.id)) {
                    KeystoreManager.importHmacKey(seed.id, seed.hmacKeyHex)
                    secureStorage.storeDpan(seed.id, seed.dpan)
                    Log.i(TAG, "Cheie importată în Keystore: ${seed.bankName}")
                }

                // 2. Adaugă în CardManager — LA FIECARE pornire (lista e in-memorie)
                if (seed.id !in existingIds) {
                    CardManager.addCard(
                        BankCard(
                            id        = seed.id,
                            bankName  = seed.bankName,
                            dpan      = seed.dpan,
                            secretKey = "",  // cheia e în Keystore, nu în BankCard
                            cardType  = seed.cardType,
                            lastFour  = seed.lastFour
                        )
                    )
                    Log.i(TAG, "Card adăugat în UI: ${seed.bankName} (****${seed.lastFour})")
                }

            } catch (e: Exception) {
                Log.e(TAG, "Eroare card ${seed.id}: ${e.message}", e)
            }
        }

        // Marchează că am importat cheile (Keystore — o singură dată)
        if (!keysImported) {
            prefs.edit().putBoolean(PREF_KEY_SEEDED, true).apply()
        }

        Log.i(TAG, "CardManager: ${CardManager.cards.size} carduri disponibile.")
    }

    /**
     * Resetează flag-ul de seeding (util pentru teste sau re-enrollare).
     * Apelează seed() după aceasta.
     */
    fun reset(context: Context) {
        val prefs = context.getSharedPreferences(PLAIN_PREFS, Context.MODE_PRIVATE)
        prefs.edit().remove(PREF_KEY_SEEDED).apply()
        Log.d(TAG, "Flag de seeding resetat.")
    }
}
