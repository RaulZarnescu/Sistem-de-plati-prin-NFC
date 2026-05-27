package com.example.sistemplatanfc.network

import com.example.sistemplatanfc.model.BankCard
import com.google.gson.annotations.SerializedName
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Header
import retrofit2.http.POST

interface CardApiService {

    // ─── Auth ──────────────────────────────────────────────────────────────────

    @POST("api/v1/auth/login")
    suspend fun login(@Body request: LoginRequest): LoginResponse

    // ─── Carduri ───────────────────────────────────────────────────────────────

    @GET("api/v1/cards")
    suspend fun getCards(): List<BankCard>

    /**
     * Înrolare card nou.
     * Backend validează cardul, generează DPAN + K_user și returnează EnrollResponse.
     */
    @POST("api/v1/cards/enroll")
    suspend fun enrollCard(@Body request: EnrollRequest): EnrollResponse

    // ─── Dashboard ─────────────────────────────────────────────────────────────

    @GET("api/v1/accounts/balance")
    suspend fun getBalance(@Header("X-DPAN") dpan: String): BalanceResponse

    @GET("api/v1/transactions/history")
    suspend fun getTransactionHistory(@Header("X-DPAN") dpan: String): List<TransactionItem>
}

// ─── Request/Response models ───────────────────────────────────────────────────

data class LoginRequest(
    val username: String,
    val pin: String
)

data class LoginResponse(
    val token: String
)

data class EnrollRequest(
    val pan: String,
    @SerializedName("expiry_month") val expiryMonth: String,
    @SerializedName("expiry_year") val expiryYear: String,
    val cvv: String,
    @SerializedName("device_id") val deviceId: String
)

/**
 * Răspunsul la înrolare.
 * Backend returnează DPAN, K_user (hmac_key_hex), pragul biometric și datele de afișare.
 * CVV-ul NU este stocat niciodată pe server.
 */
data class EnrollResponse(
    val id: String,
    val dpan: String,
    @SerializedName("hmac_key_hex") val hmacKeyHex: String,
    @SerializedName("bank_public_key_pem_b64") val bankPublicKeyPemB64: String? = null,
    @SerializedName("biometric_threshold_ron") val biometricThresholdRon: Double = 100.0,
    @SerializedName("card_type") val cardType: String = "VISA",
    @SerializedName("bank_name") val bankName: String = "Unknown Bank",
    @SerializedName("last_four") val lastFour: String
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
