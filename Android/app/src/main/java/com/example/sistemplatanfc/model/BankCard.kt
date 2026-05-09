package com.example.sistemplatanfc.model

/**
 * Reprezintă un card bancar virtual (Tokenizat) primit de la backend.
 */
data class BankCard(
    val id: String,
    val bankName: String,
    val dpan: String,      // Token-ul (Device PAN) folosit pentru plată
    val secretKey: String, // Cheia privată pentru generarea cryptogramelor (HMAC)
    val cardType: String,  // Ex: "VISA", "MASTERCARD"
    val lastFour: String,  // Ultimele 4 cifre pentru afișare în UI
    var isActive: Boolean = false
)
