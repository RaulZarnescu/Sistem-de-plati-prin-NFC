package com.example.sistemplatanfc.network

import com.google.gson.annotations.SerializedName
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Header
import retrofit2.http.POST

interface CardApiService {

    // ─── Carduri ───────────────────────────────────────────────────────────────

    /**
     * Înrolare card nou.
     * Backend validează cardul, generează DPAN + K_user și returnează EnrollResponse.
     *
     * Endpoint pe nginx port 8443 (fără mTLS, cu JWT Bearer).
     * FIX: "api/v1/enroll" (nu "api/v1/cards/enroll" — 404 pe nginx)
     */
    @POST("api/v1/enroll")
    suspend fun enrollCard(@Body request: EnrollRequest): EnrollResponse

    // ─── Dashboard ─────────────────────────────────────────────────────────────

    @GET("api/v1/accounts/balance")
    suspend fun getBalance(@Header("X-DPAN") dpan: String): BalanceResponse

    @GET("api/v1/transactions/history")
    suspend fun getTransactionHistory(@Header("X-DPAN") dpan: String): List<TransactionItem>
}

// ─── Request/Response models ───────────────────────────────────────────────────

data class EnrollRequest(
    /** PAN-ul cardului fizic (16 cifre) */
    val pan: String,
    /** Luna expirării, 2 cifre (ex: "12") */
    @SerializedName("expiry_month") val expiryMonth: String,
    /** Anul expirării, 2 cifre (ex: "28" — NU "2028") */
    @SerializedName("expiry_year") val expiryYear: String,
    /** CVV în clar — backend face SHA256(pan+cvv) la recepție */
    val cvv: String,
    /** UUID persistent al telefonului */
    @SerializedName("device_id") val deviceId: String
)

/**
 * Răspunsul la înrolare.
 *
 * Backend returnează:
 *   - DPAN (tokenul de plată, specific dispozitivului)
 *   - K_user (hmac_key_hex): cheia HMAC pentru calculul MAC
 *   - jwt_token + jwt_expires_at: autentificare pentru endpoint-urile mobile
 *   - bank_public_key_pem_b64: cheia publică RSA a băncii (pentru PIN Block)
 *   - biometric_threshold_ron: pragul în RON peste care se cere biometrie
 *
 * CVV-ul NU este stocat niciodată pe server.
 */
data class EnrollResponse(
    /** DPAN (Device PAN) — tokenul de plată */
    val dpan: String,
    /** Cheia HMAC pentru calculul MAC (va fi stocată în Android Keystore) */
    @SerializedName("hmac_key_hex")
    val hmacKeyHex: String,
    /** JWT Bearer pentru autentificarea requesturilor Android */
    @SerializedName("jwt_token")
    val jwtToken: String,
    /** Data expirării JWT (ISO 8601, ex: "2026-08-26T10:00:00Z") */
    @SerializedName("jwt_expires_at")
    val jwtExpiresAt: String,
    /** Cheia publică RSA a băncii în format PEM, encodată Base64 */
    @SerializedName("bank_public_key_pem_b64")
    val bankPublicKeyPemB64: String? = null,
    /** Pragul în RON (nu cenți) peste care se cere confirmare biometrică */
    @SerializedName("biometric_threshold_ron")
    val biometricThresholdRon: Double = 100.0,
    /** Tip card (ex: "VISA", "MASTERCARD") */
    @SerializedName("card_type")
    val cardType: String = "VISA",
    /** Denumirea băncii emitente */
    @SerializedName("bank_name")
    val bankName: String = "Unknown Bank",
    /** Ultimele 4 cifre ale PAN-ului original (pentru afișare UI) */
    @SerializedName("last_four")
    val lastFour: String = "****",
    /** ID-ul intern al cardului tokenizat */
    val id: String = dpan
)

data class BalanceResponse(
    val balance: Double,
    val currency: String,
    val dpan: String
)

data class TransactionItem(
    val id: String,
    val amount: Double,
    val currency: String,
    val timestamp: String,
    @SerializedName("merchant_name") val merchantName: String,
    val status: String  // "approved", "declined", "pending"
)
