package com.example.sistemplatanfc.utils

import com.example.sistemplatanfc.security.KeystoreManager
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object CryptoUtils {

    /**
     * Calcul MAC 2-step — FORMULA EXACTĂ AGREATĂ CU BACKEND-UL PYTHON:
     *
     *   Session_Key = HMAC-SHA256(K_user, str(ATC).encode("utf-8"))
     *   MAC_Input   = "{amount_cents}|{currency}|{nonce}|{timestamp}|{atc}"
     *   MAC         = HMAC-SHA256(Session_Key, MAC_Input.encode("utf-8")).hexdigest()
     *
     * Atenții:
     *   - amount_cents în CENȚI ca Long ("15000" nu "150.00")
     *   - nonce exact cum a venit de la POS (hex uppercase 8 chars)
     *   - timestamp exact cum a venit de la POS (ISO 8601 UTC)
     *   - atc = Transaction Counter ca Long (BIGINT — FIX față de Int anterior)
     *
     * Această versiune folosește K_user din parametru (pentru fallback/compatibilitate).
     * Preferă computeMacFromKeystore() când cheia e stocată în Keystore.
     *
     * FIX: amountCents și atc schimbate din Int la Long.
     */
    fun computeMac(
        kUserHex: String,
        amountCents: Long,
        currency: String,
        posNonce: String,
        terminalTimestamp: String,
        atc: Long
    ): String {
        // Step 1: Session_Key = HMAC-SHA256(K_user, str(ATC))
        val kUserBytes = KeystoreManager.hexToBytes(kUserHex)
        val sessionKey = hmacSha256(kUserBytes, atc.toString().toByteArray(Charsets.UTF_8))

        // Step 2: MAC = HMAC-SHA256(Session_Key, MAC_Input)
        val macInput = "$amountCents|$currency|$posNonce|$terminalTimestamp|$atc"
        val macBytes = hmacSha256(sessionKey, macInput.toByteArray(Charsets.UTF_8))

        sessionKey.fill(0) // Curăță session_key din memorie
        return macBytes.joinToString("") { "%02x".format(it) }
    }

    /**
     * Versiunea securizată: K_user rămâne în Android Hardware Keystore.
     * Se folosește în PaymentHceService și fluxul WiFi Direct.
     *
     * FIX: amountCents și atc schimbate din Int la Long.
     */
    fun computeMacFromKeystore(
        cardId: String,
        amountCents: Long,
        currency: String,
        posNonce: String,
        terminalTimestamp: String,
        atc: Long
    ): String {
        return KeystoreManager.computeMac(
            cardId = cardId,
            amountCents = amountCents,
            currency = currency,
            posNonce = posNonce,
            terminalTimestamp = terminalTimestamp,
            atc = atc
        )
    }

    fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    fun verifyMac(computedMac: String, receivedMac: String): Boolean {
        return MessageDigest.isEqual(
            computedMac.toByteArray(Charsets.UTF_8),
            receivedMac.toByteArray(Charsets.UTF_8)
        )
    }
}
