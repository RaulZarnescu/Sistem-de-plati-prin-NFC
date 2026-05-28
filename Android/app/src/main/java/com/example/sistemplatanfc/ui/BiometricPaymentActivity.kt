package com.example.sistemplatanfc.ui

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.OnBackPressedCallback
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.core.graphics.toColorInt
import androidx.fragment.app.FragmentActivity
import com.example.sistemplatanfc.hce.PaymentHceService
import java.util.Locale

/**
 * Activity fullscreen pentru confirmarea biometrică a plăților NFC mari.
 *
 * Flux:
 *  1. HCE service detectează că suma > prag biometric
 *  2. Salvează datele de plată în PaymentHceService.pendingData
 *  3. Lansează acest Activity (FLAG_ACTIVITY_NEW_TASK)
 *  4. Activity afișează biometric prompt cu suma și moneda
 *  5. La success → calculează MAC → apelează pendingCallback → sendResponseApdu
 *  6. La eșec   → trimite STATUS_FAILED → POS vede tranzacție refuzată
 *
 * Seamănă cu Apple Pay: fullscreen, implicit (nu necesită deschiderea app-ului).
 */
class BiometricPaymentActivity : FragmentActivity() {

    companion object {
        const val EXTRA_AMOUNT_CENTS = "amount_cents"
        const val EXTRA_CURRENCY     = "currency"
        const val EXTRA_ATC          = "atc"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Fullscreen peste ecranul de blocare
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O_MR1) {
            setShowWhenLocked(true)
            setTurnScreenOn(true)
        } else {
            @Suppress("DEPRECATION")
            window.addFlags(
                WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED or
                WindowManager.LayoutParams.FLAG_TURN_SCREEN_ON,
            )
        }
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)

        window.statusBarColor = "#1C1B1A".toColorInt()

        onBackPressedDispatcher.addCallback(
            this,
            object : OnBackPressedCallback(enabled = true) {
                override fun handleOnBackPressed() {
                    // Blochează back — utilizatorul trebuie să folosească "Refuză" din promptul biometric
                }
            },
        )

        // FIX #6: amountCents este Long
        val amountCents: Long = intent.getLongExtra(EXTRA_AMOUNT_CENTS, 0L)
        val currency    = intent.getStringExtra(EXTRA_CURRENCY) ?: "RON"

        val amountDisplay = formatAmount(amountCents, currency)

        showBiometricPrompt(amountDisplay)
    }

    private fun showBiometricPrompt(amountDisplay: String) {
        val executor = ContextCompat.getMainExecutor(this)

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Confirmare Plată NFC")
            .setSubtitle(amountDisplay)
            .setDescription("Autorizează tranzacția cu amprenta")
            .setNegativeButtonText("Refuză")
            .build()

        val biometricPrompt = BiometricPrompt(
            this,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {

                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    deliverPaymentResponse(approved = true)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    deliverPaymentResponse(approved = false)
                }
            },
        )

        biometricPrompt.authenticate(promptInfo)
    }

    private fun deliverPaymentResponse(approved: Boolean) {
        val pending  = PaymentHceService.pendingData
        val callback = PaymentHceService.pendingCallback

        val response = if (approved && (pending != null)) {
            PaymentHceService.buildPaymentResponse(
                card        = pending.card,
                amountCents = pending.amountCents,
                currency    = pending.currency,
                nonce       = pending.nonce,
                timestamp   = pending.timestamp,
                atc         = pending.atc,
            )
        } else {
            PaymentHceService.STATUS_FAILED
        }

        callback?.invoke(response)

        // Curăță starea pending
        PaymentHceService.pendingData     = null
        PaymentHceService.pendingCallback = null

        finish()
    }

    private fun formatAmount(cents: Long, currency: String): String {
        val amount = cents / 100.0
        return when (currency.uppercase(Locale.ROOT)) {
            "RON" -> "%.2f RON".format(amount)
            "EUR" -> "%.2f EUR".format(amount)
            "USD" -> "$%.2f".format(amount)
            else  -> "%.2f $currency".format(amount)
        }
    }
}
