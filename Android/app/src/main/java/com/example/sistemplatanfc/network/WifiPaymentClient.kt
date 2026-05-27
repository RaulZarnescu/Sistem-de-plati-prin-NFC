package com.example.sistemplatanfc.network

import android.util.Log
import com.google.gson.Gson
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.receiveAsFlow
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import java.util.concurrent.TimeUnit

/**
 * Client WebSocket pentru comunicarea cu terminalul POS prin Wi-Fi.
 *
 * Protocol (JSON):
 *  POS → Phone : {"type":"REQUEST","amount_cents":1500,"currency":"RON","nonce":"A1B2C3D4","timestamp":"..."}
 *  Phone → POS : {"type":"RESPONSE","dpan":"...","atc":42,"mac":"..."}
 *  POS → Phone : {"type":"RESULT","status":"approved"} sau {"type":"RESULT","status":"declined","reason":"..."}
 */
class WifiPaymentClient(posIp: String, posPort: Int = 8090) {

    private val url = "ws://$posIp:$posPort/pay"
    private val gson = Gson()

    private val eventChannel = Channel<PaymentEvent>(Channel.BUFFERED)
    val events: Flow<PaymentEvent> = eventChannel.receiveAsFlow()

    private var webSocket: WebSocket? = null

    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(60, TimeUnit.SECONDS)
        .build()

    fun connect() {
        eventChannel.trySend(PaymentEvent.Connecting)
        val request = Request.Builder().url(url).build()
        webSocket = client.newWebSocket(
            request,
            object : WebSocketListener() {

                override fun onOpen(webSocket: WebSocket, response: Response) {
                    Log.d(TAG, "Conectat la POS: $url")
                    eventChannel.trySend(PaymentEvent.Connected)
                }

                override fun onMessage(webSocket: WebSocket, text: String) {
                Log.d(TAG, "Mesaj POS: $text")
                try {
                    @Suppress("UNCHECKED_CAST")
                    val msg = gson.fromJson(text, Map::class.java) as Map<String, Any>
                    when (msg["type"]) {
                        "REQUEST" -> eventChannel.trySend(
                            PaymentEvent.PaymentRequested(
                                amountCents = (msg["amount_cents"] as Double).toLong(),
                                currency    = msg["currency"] as String,
                                nonce       = msg["nonce"] as String,
                                timestamp   = msg["timestamp"] as String,
                            )
                        )
                        "RESULT" -> eventChannel.trySend(
                            PaymentEvent.PaymentResult(
                                approved = msg["status"] == "approved",
                                reason   = msg["reason"] as? String
                            )
                        )
                        else -> Log.w(TAG, "Tip mesaj necunoscut: ${msg["type"]}")
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Parsare mesaj eșuată: ${e.message}")
                    eventChannel.trySend(PaymentEvent.ConnectionError("Răspuns invalid de la POS"))
                }
            }

                override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                    Log.e(TAG, "Eroare WebSocket: ${t.message}")
                    eventChannel.trySend(PaymentEvent.ConnectionError(t.message ?: "Conexiune eșuată"))
                    eventChannel.close()
                }

                override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                    Log.d(TAG, "WebSocket închis: $reason")
                    eventChannel.close()
                }
            })
    }

    fun sendPaymentResponse(dpan: String, atc: Int, mac: String) {
        val msg = gson.toJson(mapOf("type" to "RESPONSE", "dpan" to dpan, "atc" to atc, "mac" to mac))
        webSocket?.send(msg)
        Log.d(TAG, "Răspuns plată trimis (ATC=$atc)")
    }

    fun close() {
        webSocket?.close(1000, "done")
        client.dispatcher.executorService.shutdown()
    }

    companion object {
        private const val TAG = "WifiPaymentClient"
    }
}

sealed class PaymentEvent {
    object Connecting : PaymentEvent()
    object Connected : PaymentEvent()
    data class PaymentRequested(
        val amountCents: Long,
        val currency: String,
        val nonce: String,
        val timestamp: String
    ) : PaymentEvent()
    data class PaymentResult(val approved: Boolean, val reason: String?) : PaymentEvent()
    data class ConnectionError(val message: String) : PaymentEvent()
}
