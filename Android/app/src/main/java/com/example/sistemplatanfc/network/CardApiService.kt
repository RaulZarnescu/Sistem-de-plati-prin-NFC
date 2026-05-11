package com.example.sistemplatanfc.network

import com.example.sistemplatanfc.model.BankCard
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST

interface CardApiService {
    @POST("api/v1/auth/login")
    suspend fun login(@Body loginRequest: LoginRequest): LoginResponse

    @GET("api/v1/cards")
    suspend fun getCards(): List<BankCard>

    @POST("api/v1/cards/enroll")
    suspend fun enrollCard(@Body enrollRequest: EnrollRequest): BankCard
}

data class LoginRequest(val username: String, val pin: String)
data class LoginResponse(val token: String)

data class EnrollRequest(
    val pan: String,
    val expiryDate: String,
    val cvv: String
)
