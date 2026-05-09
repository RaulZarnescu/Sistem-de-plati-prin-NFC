package com.example.sistemplatanfc.hce

import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import android.util.Log
import com.example.sistemplatanfc.data.CardManager

class PaymentHceService : HostApduService() {

    override fun processCommandApdu(commandApdu: ByteArray?, extras: Bundle?): ByteArray {
        val activeCard = CardManager.getActiveCard()

        if (activeCard == null) {
            Log.e("HCE", "Niciun card activ selectat!")
            return byteArrayOf(0x6A.toByte(), 0x82.toByte()) // File not found / Card not found
        }

        Log.d("HCE", "Plată inițiată cu cardul: ${activeCard.bankName} (DPAN: ${activeCard.dpan})")

        // Aici va veni logica de generare a cryptogramei folosind activeCard.secretKey
        // Pentru PoC, returnăm un status de succes generat de cardul selectat
        return byteArrayOf(0x90.toByte(), 0x00.toByte())
    }

    override fun onDeactivated(reason: Int) {
        Log.d("HCE", "Sesiune NFC dezactivată (Motiv: $reason)")
    }
}
