package com.example.sistemplatanfc.network

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.util.concurrent.TimeUnit

/**
 * WifiPaymentClient — Comunicare HTTP REST cu ESP32
 *
 * Înlocuiește implementarea WebSocket anterioară.
 * ESP32 expune HTTP REST, nu WebSocket.
 *
 * Arhitectură:
 *   GET  http://<ESP32>:<port>/payment-request
 *        → { "status": "IDLE" | "PENDING",
 *             "amount": <cenți>,
 *             "currency": "RON",
 *             "pos_nonce": "A1B2C3D4",
 *             "terminal_timestamp": "2026-05-28T10:00:00Z",
 *             "terminal_id": "POS-BUC-001" }
 *
 *   POST http://<ESP32>:<port>/payment-response
 *        ← { "dpan": "...", "atc": <int64>, "mac": "hex64" }
 *        → 200 OK  = tranzacție acceptată de ESP32 spre Gateway
 *           409 Conflict = nu există tranzacție activă
 *
 * Port implicit: 8088 (conform ESP32_PORT din .env)
 * Protocol: HTTP plain (nu HTTPS — ESP32 local, fără certificate)
 */
class WifiPaymentClient(
    private val posIp: String,
    private val posPort: Int = 8088
) {
    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(5, TimeUnit.SECONDS)
        .build()

    /**
     * Datele tranzacției primite de la ESP32 când status == PENDING.
     * Câmpurile sunt exact cum vin de la ESP32 — NU se modifică înainte de MAC.
     */
    data class PaymentRequestData(
        /** Suma în CENȚI (ex: 15000 = 150 RON) */
        val amountCents: Long,
        /** Codul monedei (ex: "RON") */
        val currency: String,
        /** Nonce hex uppercase 8 chars (ex: "A1B2C3D4") — exact cum vine */
        val posNonce: String,
        /** Timestamp ISO 8601 UTC (ex: "2026-05-28T10:00:00Z") — exact cum vine */
        val terminalTimestamp: String,
        /** ID terminal (ex: "POS-BUC-001") */
        val terminalId: String
    )

    /**
     * Polling GET /payment-request până ESP32 are o tranzacție PENDING.
     *
     * Comportament:
     *   status == "IDLE"    → ESP32 nu are tranzacție activă, continuă polling
     *   status == "PENDING" → returnează datele tranzacției
     *   timeout             → returnează null
     *   eroare rețea        → loghează și continuă polling (ESP32 poate fi momentan indisponibil)
     *
     * @param timeoutMs  Timeout total în milisecunde (default 30s)
     * @param intervalMs Interval între polling-uri (default 500ms)
     * @return           Datele tranzacției sau null la timeout
     */
    suspend fun pollPaymentRequest(
        timeoutMs: Long = 30_000L,
        intervalMs: Long = 500L
    ): PaymentRequestData? = withContext(Dispatchers.IO) {
        val deadline = System.currentTimeMillis() + timeoutMs

        while (System.currentTimeMillis() < deadline) {
            try {
                val response = client.newCall(
                    Request.Builder()
                        .url("http://$posIp:$posPort/payment-request")
                        .get()
                        .build()
                ).execute()

                if (response.code == 200) {
                    val body = response.body?.string()
                    if (!body.isNullOrBlank()) {
                        val json = JSONObject(body)

                        if (json.getString("status") == "PENDING") {
                            return@withContext PaymentRequestData(
                                amountCents       = json.getLong("amount"),
                                currency          = json.getString("currency"),
                                posNonce          = json.getString("pos_nonce"),
                                terminalTimestamp = json.getString("terminal_timestamp"),
                                terminalId        = json.optString("terminal_id", "POS-UNKNOWN")
                            )
                        }
                        // status == "IDLE" → nu e o eroare, ESP32 așteptă apropierea cardului
                        Log.v(TAG, "ESP32 IDLE — continuă polling")
                    }
                } else {
                    Log.w(TAG, "HTTP ${response.code} de la /payment-request")
                }
            } catch (e: Exception) {
                // ESP32 temporar indisponibil (WiFi Direct în formare, etc.) → continuă polling
                Log.w(TAG, "Polling error: ${e.message}")
            }

            delay(intervalMs)
        }

        Log.w(TAG, "Timeout polling după ${timeoutMs}ms")
        null
    }

    /**
     * Trimite răspunsul de plată (DPAN + ATC + MAC) la ESP32.
     * ESP32 construiește payload-ul complet și îl trimite la Gateway via mTLS.
     *
     * @param dpan  Device PAN (token-ul cardului)
     * @param atc   Application Transaction Counter (Long / int64)
     * @param mac   HMAC-SHA256 hex lowercase 64 chars
     * @return      true = ESP32 a acceptat și procesează spre Gateway
     *              false = eroare (409 Conflict sau eroare rețea)
     */
    suspend fun sendPaymentResponse(
        dpan: String,
        atc: Long,
        mac: String
    ): Boolean = withContext(Dispatchers.IO) {
        try {
            val body = JSONObject().apply {
                put("dpan", dpan)
                put("atc", atc)
                put("mac", mac)
            }.toString()

            val response = client.newCall(
                Request.Builder()
                    .url("http://$posIp:$posPort/payment-response")
                    .post(body.toRequestBody("application/json".toMediaType()))
                    .build()
            ).execute()

            when (response.code) {
                200 -> {
                    Log.i(TAG, "Răspuns plată acceptat de ESP32 (ATC=$atc)")
                    true
                }
                409 -> {
                    // Nu există tranzacție activă pe ESP32 (a expirat sau a fost anulată)
                    Log.e(TAG, "409: Nicio tranzacție activă pe ESP32")
                    false
                }
                else -> {
                    Log.e(TAG, "Eroare ${response.code}: ${response.body?.string()}")
                    false
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "sendPaymentResponse eroare rețea: $e")
            false
        }
    }

    /**
     * Anulează orice request HTTP în curs (apelat la cancel plată).
     */
    fun close() {
        try {
            client.dispatcher.cancelAll()
        } catch (e: Exception) {
            Log.w(TAG, "close() error: ${e.message}")
        }
    }

    companion object {
        private const val TAG = "WifiPaymentClient"
    }
}
