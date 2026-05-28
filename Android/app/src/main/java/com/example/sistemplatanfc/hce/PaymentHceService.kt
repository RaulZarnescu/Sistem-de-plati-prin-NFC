package com.example.sistemplatanfc.hce

import android.content.Context
import android.content.Intent
import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.example.sistemplatanfc.data.CardManager
import com.example.sistemplatanfc.model.BankCard
import com.example.sistemplatanfc.security.KeystoreManager
import com.example.sistemplatanfc.security.SecureStorage
import com.example.sistemplatanfc.ui.BiometricPaymentActivity
import com.example.sistemplatanfc.utils.CryptoUtils
import java.nio.charset.StandardCharsets

/**
 * Serviciu HCE (Host Card Emulation) — emulează un card de plată NFC.
 *
 * FIX #7: NFC_ENABLED = false pentru prezentare (modul PN532 defect temporar).
 *   Codul HCE rămâne complet și funcțional — se reactivează setând NFC_ENABLED = true.
 *
 * FIX #6: ATC schimbat din Int la Long (BIGINT / int64 conform spec).
 *
 * FIX #10: ATC stocat în EncryptedSharedPreferences (nu plain SharedPreferences).
 *   Previne manipularea ATC-ului pe telefoane rootate (replay attack).
 *
 * STATE MACHINE (4 stări):
 *
 *  STATE 1 — SELECT APPLICATION
 *    POS trimite APDU cu AID F1C71V3B4NK01.
 *    Android răspunde: 90 00.
 *
 *  STATE 2 — GET PROCESSING OPTIONS (PAYMENT REQUEST)
 *    POS trimite: amount_cents|currency|nonce|timestamp
 *    Android verifică dacă amount > biometric_threshold.
 *
 *  STATE 3 — CALCUL MAC (intern, 2-step)
 *    Session_Key = HMAC-SHA256(K_user, str(ATC))   ← K_user în Keystore
 *    MAC         = HMAC-SHA256(Session_Key, mac_input)
 *
 *  STATE 4 — RĂSPUNS FINAL
 *    Android trimite: dpan|atc|mac + 90 00
 */
class PaymentHceService : HostApduService() {

    /**
     * ATC persistent în EncryptedSharedPreferences.
     * FIX #6: Long în loc de Int (BIGINT).
     * FIX #10: EncryptedSharedPreferences în loc de plain SharedPreferences.
     */
    private var atc: Long
        get() = getEncryptedPrefs(this).getLong(KEY_ATC, System.currentTimeMillis())
        set(value) = getEncryptedPrefs(this).edit().putLong(KEY_ATC, value).apply()

    override fun processCommandApdu(commandApdu: ByteArray?, extras: Bundle?): ByteArray? {
        if (commandApdu == null) return STATUS_FAILED

        // FIX #7: NFC dezactivat — returnează SW 6A82 (File Not Found)
        // POS va anula APDU și nu va mai trimite comenzi suplimentare.
        if (!NFC_ENABLED) {
            Log.d(TAG, "NFC dezactivat (modul PN532 defect). Folosiți WiFi Direct.")
            return STATUS_FILE_NOT_FOUND
        }

        val hexCommand = commandApdu.toHex()
        Log.d(TAG, "APDU primit: $hexCommand")

        return when {
            // ── STATE 1: SELECT APPLICATION ────────────────────────────────────
            hexCommand.startsWith("00A40400") -> {
                Log.d(TAG, "STATE 1: SELECT AID acceptat")
                STATUS_SUCCESS
            }

            // ── STATE 2-4: PAYMENT REQUEST ──────────────────────────────────────
            hexCommand.startsWith("00A0") -> {
                handlePaymentRequest(commandApdu)
            }

            else -> {
                Log.w(TAG, "APDU necunoscut: $hexCommand")
                STATUS_FAILED
            }
        }
    }

    private fun handlePaymentRequest(commandApdu: ByteArray): ByteArray? {
        try {
            val activeCard = CardManager.getActiveCard()
            if (activeCard == null) {
                Log.e(TAG, "Niciun card activ!")
                return STATUS_NO_CARD
            }

            if (commandApdu.size < 6) return STATUS_FAILED
            val lc = commandApdu[4].toInt() and 0xFF
            if (commandApdu.size < (5 + lc)) return STATUS_FAILED

            val payload = String(commandApdu.copyOfRange(5, 5 + lc), StandardCharsets.UTF_8)
            val parts = payload.split("|")
            if (parts.size < 4) {
                Log.e(TAG, "Payload malformat: $payload")
                return STATUS_FAILED
            }

            val amountCents = parts[0].toLong()
            val currency    = parts[1]
            val nonce       = parts[2]
            val timestamp   = parts[3]

            Log.i(TAG, "STATE 2: amount=${amountCents}c currency=$currency nonce=$nonce")

            // FIX #6: ATC este Long
            val newAtc: Long = atc + 1L
            atc = newAtc

            val secureStorage = SecureStorage.getInstance(this)
            val threshold = secureStorage.getBiometricThresholdCents()

            if (amountCents > threshold) {
                Log.i(TAG, "Sumă ${amountCents}c > prag ${threshold}c → biometrie necesară")

                pendingData = PendingPayment(
                    card        = activeCard,
                    amountCents = amountCents,
                    currency    = currency,
                    nonce       = nonce,
                    timestamp   = timestamp,
                    atc         = newAtc,
                )
                pendingCallback = { response -> sendResponseApdu(response) }

                val intent = Intent(this, BiometricPaymentActivity::class.java).apply {
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
                    putExtra(BiometricPaymentActivity.EXTRA_AMOUNT_CENTS, amountCents)
                    putExtra(BiometricPaymentActivity.EXTRA_CURRENCY, currency)
                    putExtra(BiometricPaymentActivity.EXTRA_ATC, newAtc)
                }
                startActivity(intent)

                return null
            }

            return buildPaymentResponse(activeCard, amountCents, currency, nonce, timestamp, newAtc)

        } catch (e: Exception) {
            Log.e(TAG, "Eroare procesare plată NFC: ${e.message}", e)
            return STATUS_FAILED
        }
    }

    override fun onDeactivated(reason: Int) {
        Log.d(TAG, "Sesiune NFC închisă (reason=$reason)")
        if (reason == DEACTIVATION_LINK_LOSS) {
            pendingData = null
            pendingCallback = null
        }
    }

    companion object {
        private const val TAG        = "PaymentHceService"
        private const val PREFS_NAME = "hce_prefs_enc"  // redenumit față de "hce_prefs" plain
        private const val KEY_ATC    = "atc"

        /**
         * FIX #7: Flag pentru activarea/dezactivarea NFC HCE.
         *
         * false = prezentare (modul PN532 defect) — plata via WiFi Direct
         * true  = producție (modul NFC funcțional)
         *
         * Setați true când modulul NFC e reinstalat.
         */
        const val NFC_ENABLED = false

        val STATUS_SUCCESS        = byteArrayOf(0x90.toByte(), 0x00.toByte())
        val STATUS_FAILED         = byteArrayOf(0x6F.toByte(), 0x00.toByte())
        val STATUS_NO_CARD        = byteArrayOf(0x6A.toByte(), 0x82.toByte())
        val STATUS_FILE_NOT_FOUND = byteArrayOf(0x6A.toByte(), 0x82.toByte()) // SW 6A82

        @Volatile var pendingData: PendingPayment? = null
        @Volatile var pendingCallback: ((ByteArray) -> Unit)? = null

        data class PendingPayment(
            val card: BankCard,
            val amountCents: Long,          // FIX #6: Long
            val currency: String,
            val nonce: String,
            val timestamp: String,
            val atc: Long,                  // FIX #6: Long
        )

        /**
         * FIX #10: EncryptedSharedPreferences pentru ATC.
         * Previne manipularea contorului pe telefoane rootate.
         */
        fun getEncryptedPrefs(context: Context): android.content.SharedPreferences {
            return try {
                val masterKey = MasterKey.Builder(context)
                    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                    .build()
                EncryptedSharedPreferences.create(
                    context,
                    PREFS_NAME,
                    masterKey,
                    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
                )
            } catch (e: Exception) {
                // Fallback la plain prefs dacă EncryptedSharedPreferences eșuează (dispozitive vechi)
                Log.w(TAG, "EncryptedSharedPreferences indisponibil, fallback: ${e.message}")
                context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            }
        }

        /**
         * FIX #6: Incrementează ATC și returnează noua valoare ca Long.
         * Partajat cu fluxul WiFi Direct din WalletScreen.
         *
         * Strategia ATC:
         *   - Valoarea inițială = System.currentTimeMillis() / 1000 (timestamp Unix în secunde)
         *   - Incrementat cu +1 la fiecare tranzacție
         *   - Garantat crescător, compatibil cu BIGINT PostgreSQL
         */
        fun getAndIncrementAtc(context: Context): Long {
            val prefs = getEncryptedPrefs(context)
            val current = prefs.getLong(KEY_ATC, System.currentTimeMillis() / 1000L)
            val next = current + 1L
            prefs.edit().putLong(KEY_ATC, next).apply()
            return next
        }

        /**
         * Construiește răspunsul final NFC: DPAN|ATC|MAC + 9000.
         *
         * FIX #6: amountCents și atc sunt Long.
         */
        fun buildPaymentResponse(
            card: BankCard,
            amountCents: Long,
            currency: String,
            nonce: String,
            timestamp: String,
            atc: Long,
        ): ByteArray {
            val mac = if (KeystoreManager.hasKey(card.id)) {
                CryptoUtils.computeMacFromKeystore(
                    cardId            = card.id,
                    amountCents       = amountCents,
                    currency          = currency,
                    posNonce          = nonce,
                    terminalTimestamp = timestamp,
                    atc               = atc
                )
            } else {
                CryptoUtils.computeMac(
                    kUserHex          = card.secretKey,
                    amountCents       = amountCents,
                    currency          = currency,
                    posNonce          = nonce,
                    terminalTimestamp = timestamp,
                    atc               = atc
                )
            }

            Log.i(TAG, "STATE 3+4: DPAN=${card.dpan.take(8)}… ATC=$atc MAC=${mac.take(16)}…")

            val response = "${card.dpan}|$atc|$mac"
            return response.toByteArray(StandardCharsets.UTF_8) + STATUS_SUCCESS
        }
    }
}

private fun ByteArray.toHex() = joinToString("") { "%02X".format(it) }
