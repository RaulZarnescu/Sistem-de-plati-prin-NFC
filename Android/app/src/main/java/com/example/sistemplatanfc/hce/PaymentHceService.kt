package com.example.sistemplatanfc.hce

import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import android.util.Log
import com.example.sistemplatanfc.data.CardManager
import com.example.sistemplatanfc.utils.CryptoUtils
import java.nio.charset.StandardCharsets

class PaymentHceService : HostApduService() {

    private var atc = 0 // Application Transaction Counter

    override fun processCommandApdu(commandApdu: ByteArray?, extras: Bundle?): ByteArray {
        if (commandApdu == null) return STATUS_FAILED

        val hexCommand = bytesToHex(commandApdu)
        Log.d("HCE", "Comandă primită: $hexCommand")

        // 1. Verificăm dacă este comanda SELECT AID (prima etapă a plății)
        if (hexCommand.startsWith("00A40400")) {
            return STATUS_SUCCESS
        }

        // 2. Verificăm dacă este comanda de plată (simulată prin formatul nostru)
        // Format așteptat de la POS: [Data Length] + "AMOUNT|CURRENCY|NONCE|TIMESTAMP"
        try {
            val activeCard = CardManager.getActiveCard()
            if (activeCard == null) {
                Log.e("HCE", "Niciun card activ!")
                return STATUS_NO_CARD
            }

            // Extragem datele din APDU (ignorăm header-ul de 4 bytes dacă e cazul)
            val payload = String(commandApdu, StandardCharsets.UTF_8).substringAfter("|", "")
            if (payload.isEmpty()) return STATUS_FAILED

            val parts = payload.split("|")
            if (parts.size < 4) return STATUS_FAILED

            val amountCents = parts[0].toInt()
            val currency = parts[1]
            val nonce = parts[2]
            val timestamp = parts[3]
            
            atc++ // Incrementăm contorul de tranzacții

            // 3. Calculăm HMAC-ul folosind CryptoUtils (exact ca în backend)
            val hmac = CryptoUtils.computeMac(
                sessionKey = activeCard.secretKey,
                amountCents = amountCents,
                currency = currency,
                posNonce = nonce,
                terminalTimestamp = timestamp,
                atc = atc
            )

            Log.i("HCE", "Plată semnată: $hmac | ATC: $atc")

            // 4. Trimitem înapoi DPAN-ul + HMAC-ul + ATC către POS
            val response = "${activeCard.dpan}|$hmac|$atc"
            return response.toByteArray(StandardCharsets.UTF_8) + STATUS_SUCCESS

        } catch (e: Exception) {
            Log.e("HCE", "Eroare la procesare: ${e.message}")
            return STATUS_FAILED
        }
    }

    override fun onDeactivated(reason: Int) {
        Log.d("HCE", "Sesiune NFC închisă: $reason")
    }

    private fun bytesToHex(bytes: ByteArray): String {
        return bytes.joinToString("") { "%02X".format(it) }
    }

    companion object {
        private val STATUS_SUCCESS = byteArrayOf(0x90.toByte(), 0x00.toByte())
        private val STATUS_FAILED = byteArrayOf(0x6F.toByte(), 0x00.toByte())
        private val STATUS_NO_CARD = byteArrayOf(0x6A.toByte(), 0x82.toByte())
    }
}
