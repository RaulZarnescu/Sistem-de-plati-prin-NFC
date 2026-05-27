package com.example.sistemplatanfc.hce

import android.content.Context
import android.content.Intent
import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import android.util.Log
import androidx.core.content.edit
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
 *    (Dacă biometrie necesară: răspuns asincron via sendResponseApdu)
 */
class PaymentHceService : HostApduService() {

    /** ATC persistent în SharedPreferences — supraviețuiește restart app (anti Replay Attack) */
    private var atc: Int
        get() = getSharedPreferences(PREFS_NAME, MODE_PRIVATE).getInt(KEY_ATC, 0)
        set(value) = getSharedPreferences(PREFS_NAME, MODE_PRIVATE).edit { putInt(KEY_ATC, value) }

    override fun processCommandApdu(commandApdu: ByteArray?, extras: Bundle?): ByteArray? {
        if (commandApdu == null) return STATUS_FAILED

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
                // null = răspuns va veni asincron via sendResponseApdu (biometrie)
                // non-null = răspuns sincron imediat
            }

            else -> {
                Log.w(TAG, "APDU necunoscut: $hexCommand")
                STATUS_FAILED
            }
        }
    }

    /**
     * STATE 2: Parsează datele de plată, decide dacă biometria e necesară.
     * STATE 3: Calculează MAC (2-step HMAC cu cheie din Keystore).
     * STATE 4: Răspuns final dpan|atc|mac + 9000.
     *
     * Returnează null dacă biometria e necesară (răspuns asincron).
     */
    private fun handlePaymentRequest(commandApdu: ByteArray): ByteArray? {
        try {
            val activeCard = CardManager.getActiveCard()
            if (activeCard == null) {
                Log.e(TAG, "Niciun card activ!")
                return STATUS_NO_CARD
            }

            // Parsare APDU: CLA(1) INS(1) P1(1) P2(1) Lc(1) Data(Lc)
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
            val nonce       = parts[2]   // hex uppercase 8 chars — exact cum vine de la POS
            val timestamp   = parts[3]   // ISO 8601 UTC — exact cum vine de la POS

            Log.i(TAG, "STATE 2: amount=${amountCents}c currency=$currency nonce=$nonce")

            // Incrementăm ATC înainte de orice (anti replay)
            val newAtc = atc + 1
            atc = newAtc

            // ── STATE 2: Verificare prag biometric ────────────────────────────
            val secureStorage = SecureStorage.getInstance(this)
            val threshold = secureStorage.getBiometricThresholdCents()

            if (amountCents > threshold) {
                Log.i(TAG, "Sumă ${amountCents}c > prag ${threshold}c → biometrie necesară")

                // Salvăm datele pending pentru BiometricPaymentActivity
                pendingData = PendingPayment(
                    card       = activeCard,
                    amountCents = amountCents.toInt(),
                    currency   = currency,
                    nonce      = nonce,
                    timestamp  = timestamp,
                    atc        = newAtc,
                )
                pendingCallback = { response -> sendResponseApdu(response) }

                // Lansăm Activity pentru biometrie (async — returnăm null)
                val intent = Intent(this, BiometricPaymentActivity::class.java).apply {
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
                    putExtra(BiometricPaymentActivity.EXTRA_AMOUNT_CENTS, amountCents)
                    putExtra(BiometricPaymentActivity.EXTRA_CURRENCY, currency)
                    putExtra(BiometricPaymentActivity.EXTRA_ATC, newAtc)
                }
                startActivity(intent)

                return null  // Răspunsul va veni via sendResponseApdu din BiometricPaymentActivity
            }

            // ── STATE 3 + 4: Sumă sub prag — răspuns imediat ─────────────────
            return buildPaymentResponse(activeCard, amountCents.toInt(), currency, nonce, timestamp, newAtc)

        } catch (e: Exception) {
            Log.e(TAG, "Eroare procesare plată: ${e.message}", e)
            return STATUS_FAILED
        }
    }

    override fun onDeactivated(reason: Int) {
        Log.d(TAG, "Sesiune NFC închisă (reason=$reason)")
        // Curăță pending dacă sesiunea a expirat înainte ca biometria să fie completată
        if (reason == DEACTIVATION_LINK_LOSS) {
            pendingData = null
            pendingCallback = null
        }
    }

    companion object {
        private const val TAG        = "PaymentHceService"
        private const val PREFS_NAME = "hce_prefs"
        private const val KEY_ATC    = "atc"

        val STATUS_SUCCESS = byteArrayOf(0x90.toByte(), 0x00.toByte())
        val STATUS_FAILED  = byteArrayOf(0x6F.toByte(), 0x00.toByte())
        val STATUS_NO_CARD = byteArrayOf(0x6A.toByte(), 0x82.toByte())

        /** Date de plată pending (pentru fluxul cu biometrie async) */
        @Volatile var pendingData: PendingPayment? = null
        @Volatile var pendingCallback: ((ByteArray) -> Unit)? = null

        data class PendingPayment(
            val card: BankCard,
            val amountCents: Int,
            val currency: String,
            val nonce: String,
            val timestamp: String,
            val atc: Int,
        )

        /** Incrementează ATC și returnează noua valoare. Partajat cu WifiPaymentClient. */
        fun getAndIncrementAtc(context: Context): Int {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            val next = prefs.getInt(KEY_ATC, 0) + 1
            prefs.edit().putInt(KEY_ATC, next).apply()
            return next
        }

        /**
         * Construiește răspunsul final: DPAN|ATC|MAC + 9000.
         * Apelat atât sincron (sumă mică) cât și din BiometricPaymentActivity (sumă mare).
         */
        fun buildPaymentResponse(
            card: BankCard,
            amountCents: Int,
            currency: String,
            nonce: String,
            timestamp: String,
            atc: Int,
        ): ByteArray {
            // STATE 3: Calcul MAC 2-step (K_user din Keystore)
            val mac = if (KeystoreManager.hasKey(card.id)) {
                CryptoUtils.computeMacFromKeystore(
                    cardId = card.id,
                    amountCents = amountCents,
                    currency = currency,
                    posNonce = nonce,
                    terminalTimestamp = timestamp,
                    atc = atc
                )
            } else {
                // Fallback la secretKey din BankCard (compatibilitate backward)
                CryptoUtils.computeMac(
                    kUserHex = card.secretKey,
                    amountCents = amountCents,
                    currency = currency,
                    posNonce = nonce,
                    terminalTimestamp = timestamp,
                    atc = atc
                )
            }

            Log.i(TAG, "STATE 3+4: DPAN=${card.dpan.take(8)}… ATC=$atc MAC=${mac.take(16)}…")

            // STATE 4: Răspuns final
            val response = "${card.dpan}|$atc|$mac"
            return response.toByteArray(StandardCharsets.UTF_8) + STATUS_SUCCESS
        }
    }
}

private fun ByteArray.toHex() = joinToString("") { "%02X".format(it) }
