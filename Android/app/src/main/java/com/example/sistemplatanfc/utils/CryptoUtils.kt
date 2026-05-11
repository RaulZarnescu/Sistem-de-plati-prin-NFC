package com.example.sistemplatanfc.utils

import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object CryptoUtils {

    /**
     * Calculează semnătura HMAC-SHA256 exact ca în backend-ul Python.
     * Format: Amount_Cents | Currency | POS_Nonce | Terminal_Timestamp | ATC
     */
    fun computeMac(
        sessionKey: String, // Cheia hex primită de la backend
        amountCents: Int,
        currency: String,
        posNonce: String,
        terminalTimestamp: String,
        atc: Int
    ): String {
        val macInput = "$amountCents|$currency|$posNonce|$terminalTimestamp|$atc"
        val inputBytes = macInput.toByteArray(Charsets.UTF_8)
        val keyBytes = hexToBytes(sessionKey)

        val sha256HMAC = Mac.getInstance("HmacSHA256")
        val secretKey = SecretKeySpec(keyBytes, "HmacSHA256")
        sha256HMAC.init(secretKey)

        val hashBytes = sha256HMAC.doFinal(inputBytes)
        return hashBytes.joinToString("") { "%02x".format(it) }
    }

    private fun hexToBytes(hex: String): ByteArray {
        val result = ByteArray(hex.length / 2)
        for (i in hex.indices step 2) {
            result[i / 2] = hex.substring(i, i + 2).toInt(16).toByte()
        }
        return result
    }

    fun verifyMac(computedMac: String, receivedMac: String): Boolean {
        return MessageDigest.isEqual(
            computedMac.toByteArray(Charsets.UTF_8),
            receivedMac.toByteArray(Charsets.UTF_8)
        )
    }
}
