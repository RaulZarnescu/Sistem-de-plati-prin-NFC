package com.example.sistemplatanfc.hce

import android.content.Context
import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import android.util.Log
import com.example.sistemplatanfc.data.CardManager
import com.example.sistemplatanfc.utils.CryptoUtils
import java.nio.charset.StandardCharsets

class PaymentHceService : HostApduService() {

    // ATC persistent în SharedPreferences.
    // Anterior era o variabilă de clasă (private var atc = 0) care se reseta
    // la fiecare restart al serviciului HCE — permitea Replay Attacks după restart.
    // SharedPreferences supraviețuiește repornirii serviciului și a aplicației.
    private var atc: Int
        get() = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getInt(KEY_ATC, 0)
        set(value) = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit().putInt(KEY_ATC, value).apply()

    override fun processCommandApdu(commandApdu: ByteArray?, extras: Bundle?): ByteArray {
        if (commandApdu == null) return STATUS_FAILED

        val hexCommand = bytesToHex(commandApdu)
        Log.d("HCE", "Comandă primită: $hexCommand")

        // 1. SELECT AID — prima comandă trimisă de orice terminal NFC
        //    Format: 00 A4 04 00 [Lc] [AID bytes]
        //    AID-ul înregistrat în apduservice.xml: F1000000000001
        if (hexCommand.startsWith("00A40400")) {
            Log.d("HCE", "SELECT AID acceptat")
            return STATUS_SUCCESS
        }

        // 2. PAYMENT REQUEST — comanda proprie de plată (INS = A0)
        //    Format APDU: CLA(00) INS(A0) P1(00) P2(00) Lc(N) Data(N bytes)
        //    Data = "AMOUNT|CURRENCY|NONCE|TIMESTAMP" codificat UTF-8
        //    Exemplu: "15000|RON|A7F90B1C|2026-04-10T14:30:00Z"
        if (hexCommand.startsWith("00A0")) {
            return handlePaymentRequest(commandApdu)
        }

        Log.w("HCE", "Comandă APDU necunoscută: $hexCommand")
        return STATUS_FAILED
    }

    private fun handlePaymentRequest(commandApdu: ByteArray): ByteArray {
        try {
            val activeCard = CardManager.getActiveCard()
            if (activeCard == null) {
                Log.e("HCE", "Niciun card activ!")
                return STATUS_NO_CARD
            }

            // Structura APDU: CLA(1) INS(1) P1(1) P2(1) Lc(1) Data(Lc bytes)
            // Anterior, codul făcea String(commandApdu, UTF_8).substringAfter("|")
            // ceea ce converti bytes binari din header (CLA/INS/P1/P2) la UTF-8 → corupție date.
            // Fix: extragem explicit câmpul Data sărind peste cei 5 bytes de header.
            if (commandApdu.size < 6) {
                Log.e("HCE", "APDU prea scurt: ${commandApdu.size} bytes")
                return STATUS_FAILED
            }
            val lc = commandApdu[4].toInt() and 0xFF
            if (commandApdu.size < 5 + lc) {
                Log.e("HCE", "APDU trunchiat: declarat Lc=$lc, primit ${commandApdu.size - 5} bytes")
                return STATUS_FAILED
            }
            val dataBytes = commandApdu.copyOfRange(5, 5 + lc)
            val payload = String(dataBytes, StandardCharsets.UTF_8)

            val parts = payload.split("|")
            if (parts.size < 4) {
                Log.e("HCE", "Payload malformat (${parts.size} câmpuri): $payload")
                return STATUS_FAILED
            }

            val amountCents = parts[0].toInt()
            val currency    = parts[1]
            val nonce       = parts[2]
            val timestamp   = parts[3]

            // Incrementăm și persistăm ATC înainte de a calcula HMAC-ul
            val newAtc = atc + 1
            atc = newAtc

            // Calculăm HMAC-SHA256 — același algoritm ca în shared/crypto_utils.py
            val hmac = CryptoUtils.computeMac(
                sessionKey        = activeCard.secretKey,
                amountCents       = amountCents,
                currency          = currency,
                posNonce          = nonce,
                terminalTimestamp = timestamp,
                atc               = newAtc
            )

            Log.i("HCE", "Plată semnată: DPAN=${activeCard.dpan} ATC=$newAtc")

            // Răspuns către POS: DPAN|HMAC|ATC urmat de SW1SW2 (9000 = succes)
            val response = "${activeCard.dpan}|$hmac|$newAtc"
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
        private const val PREFS_NAME = "hce_prefs"
        private const val KEY_ATC    = "atc"

        private val STATUS_SUCCESS  = byteArrayOf(0x90.toByte(), 0x00.toByte())
        private val STATUS_FAILED   = byteArrayOf(0x6F.toByte(), 0x00.toByte())
        private val STATUS_NO_CARD  = byteArrayOf(0x6A.toByte(), 0x82.toByte())
    }
}
