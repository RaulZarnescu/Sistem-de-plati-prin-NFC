package com.example.sistemplatanfc.security

import android.security.keystore.KeyProperties
import android.security.keystore.KeyProtection
import android.util.Log
import java.security.KeyStore
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/**
 * Gestionează stocarea cheilor criptografice în Android Hardware-Backed Keystore.
 *
 * K_user (hmac_key_hex) este importată în Keystore și NICIODATĂ extrasă în clar.
 * Operațiile HMAC se fac direct cu cheia din Keystore (hardware TEE unde e disponibil).
 *
 * Formula 2-step HMAC (aliniat cu backend Python shared/crypto_utils.py):
 *   Session_Key = HMAC-SHA256(K_user, str(ATC).encode("utf-8"))
 *   MAC         = HMAC-SHA256(Session_Key, mac_input.encode("utf-8"))
 *
 * FIX: ATC schimbat din Int la Long (BIGINT / int64 conform spec).
 */
object KeystoreManager {

    private const val TAG = "KeystoreManager"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val HMAC_KEY_PREFIX = "hce_hmac_"

    // ─── Import cheie HMAC din server în Keystore ──────────────────────────────

    /**
     * Importă K_user (hex string primit de la backend) în Android Keystore.
     * Pe dispozitive compatibile, cheia va fi protejată hardware (TEE/StrongBox).
     */
    fun importHmacKey(cardId: String, keyHex: String) {
        val keyBytes = hexToBytes(keyHex)
        val secretKeySpec = SecretKeySpec(keyBytes, "HmacSHA256")

        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)

        keyStore.setEntry(
            hmacAlias(cardId),
            KeyStore.SecretKeyEntry(secretKeySpec),
            KeyProtection.Builder(KeyProperties.PURPOSE_SIGN).build()
        )

        Log.i(TAG, "Cheie HMAC importată în Keystore pentru cardul $cardId")
    }

    // ─── Calcul MAC 2-step (K_user rămâne în Keystore) ─────────────────────────

    /**
     * Step 1: Session_Key = HMAC-SHA256(K_user, str(atc))  ← K_user rămâne în hardware
     * Step 2: MAC = HMAC-SHA256(Session_Key, mac_input)    ← în memorie, Session_Key șters după
     *
     * FIX: atc este Long (BIGINT) — corespunde specificației și PostgreSQL BIGINT.
     * str(atc) produce același string ca Python str(atc) pentru aceleași valori.
     */
    fun computeMac(
        cardId: String,
        amountCents: Long,
        currency: String,
        posNonce: String,
        terminalTimestamp: String,
        atc: Long
    ): String {
        // Step 1 — K_user în Keystore, sesiunea derivată în memorie
        val sessionKey = computeSessionKey(cardId, atc)

        // Step 2 — MAC final
        // Format identic cu Python: "{amount_cents}|{currency}|{pos_nonce}|{terminal_timestamp}|{atc}"
        val macInput = "$amountCents|$currency|$posNonce|$terminalTimestamp|$atc"
        val macBytes = hmacSha256(sessionKey, macInput.toByteArray(Charsets.UTF_8))

        // Șterge session_key din memorie imediat după use (best effort)
        sessionKey.fill(0)

        return macBytes.joinToString("") { "%02x".format(it) }
    }

    /**
     * Derivă Session_Key = HMAC-SHA256(K_user, str(ATC)) folosind cheia din Keystore.
     * K_user nu este niciodată accesibilă în afara Keystore.
     *
     * FIX: atc este Long.
     */
    fun computeSessionKey(cardId: String, atc: Long): ByteArray {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)

        val key: SecretKey = keyStore.getKey(hmacAlias(cardId), null) as? SecretKey
            ?: throw IllegalStateException("Cheia HMAC nu există în Keystore pentru cardul $cardId")

        val mac = Mac.getInstance("HmacSHA256")
        mac.init(key)
        // str(atc) — identic cu Python str(atc): număr decimal fără padding
        return mac.doFinal(atc.toString().toByteArray(Charsets.UTF_8))
    }

    // ─── Utilitare ─────────────────────────────────────────────────────────────

    fun hasKey(cardId: String): Boolean {
        return try {
            val ks = KeyStore.getInstance(ANDROID_KEYSTORE)
            ks.load(null)
            ks.containsAlias(hmacAlias(cardId))
        } catch (e: Exception) {
            false
        }
    }

    fun deleteKey(cardId: String) {
        try {
            val ks = KeyStore.getInstance(ANDROID_KEYSTORE)
            ks.load(null)
            ks.deleteEntry(hmacAlias(cardId))
            Log.i(TAG, "Cheie ștearsă pentru cardul $cardId")
        } catch (e: Exception) {
            Log.w(TAG, "Nu s-a putut șterge cheia: ${e.message}")
        }
    }

    private fun hmacAlias(cardId: String) = "$HMAC_KEY_PREFIX$cardId"

    fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    fun hexToBytes(hex: String): ByteArray {
        val clean = hex.replace(" ", "").replace("0x", "")
        return ByteArray(clean.length / 2) { i ->
            clean.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }
}
