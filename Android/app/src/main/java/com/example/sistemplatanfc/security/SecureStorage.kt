package com.example.sistemplatanfc.security

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.util.UUID

/**
 * Stocare securizată pentru date sensibile ale cardului:
 *   - DPAN (Device PAN — tokenul de plată)
 *   - Bank Public Key (pentru PIN Block, opțional)
 *   - Biometric Threshold (prag confirmare biometrică, în cenți)
 *   - Auth Token JWT + data expirării
 *   - Device ID
 *   - Server IP (IP-ul laptopului cu Docker)
 *   - POS IP (IP-ul ESP32)
 *
 * Folosește EncryptedSharedPreferences (AES-256-GCM), cu cheia de criptare
 * generată și protejată în Android Hardware-Backed Keystore.
 */
class SecureStorage(context: Context) {

    private val prefs: SharedPreferences
    private val plainPrefs: SharedPreferences

    init {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()

        prefs = EncryptedSharedPreferences.create(
            context,
            "secure_card_prefs",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )

        plainPrefs = context.getSharedPreferences("plain_prefs", Context.MODE_PRIVATE)
    }

    // ─── DPAN ──────────────────────────────────────────────────────────────────

    fun storeDpan(cardId: String, dpan: String) =
        prefs.edit().putString("dpan_$cardId", dpan).apply()

    fun getDpan(cardId: String): String? =
        prefs.getString("dpan_$cardId", null)

    fun deleteDpan(cardId: String) =
        prefs.edit().remove("dpan_$cardId").apply()

    // ─── Bank Public Key ───────────────────────────────────────────────────────

    fun storeBankPublicKey(cardId: String, pubKeyPemB64: String) =
        prefs.edit().putString("bank_pub_key_$cardId", pubKeyPemB64).apply()

    fun getBankPublicKey(cardId: String): String? =
        prefs.getString("bank_pub_key_$cardId", null)

    // ─── Biometric Threshold ──────────────────────────────────────────────────

    /**
     * Prag în CENȚI (ex: 10000 = 100 RON).
     * Tranzacțiile peste acest prag necesită confirmare biometrică.
     */
    fun storeBiometricThresholdCents(thresholdCents: Long) =
        plainPrefs.edit().putLong("biometric_threshold_cents", thresholdCents).apply()

    fun getBiometricThresholdCents(): Long =
        plainPrefs.getLong("biometric_threshold_cents", 10000L) // default: 100 RON

    // ─── Auth Token JWT ────────────────────────────────────────────────────────

    fun storeAuthToken(token: String) =
        prefs.edit().putString("auth_token", token).apply()

    fun getAuthToken(): String? =
        prefs.getString("auth_token", null)

    fun clearAuthToken() =
        prefs.edit().remove("auth_token").apply()

    fun isLoggedIn(): Boolean = getAuthToken() != null

    /**
     * FIX #4: Stochează data expirării JWT (ISO 8601).
     * Folosit pentru a detecta expirarea și a re-înrola cardului.
     */
    fun storeJwtExpiry(expiresAt: String) =
        prefs.edit().putString("jwt_expires_at", expiresAt).apply()

    fun getJwtExpiry(): String? =
        prefs.getString("jwt_expires_at", null)

    // ─── Device ID ────────────────────────────────────────────────────────────

    fun getDeviceId(): String {
        var deviceId = plainPrefs.getString("device_id", null)
        if (deviceId == null) {
            deviceId = UUID.randomUUID().toString()
            plainPrefs.edit().putString("device_id", deviceId).apply()
        }
        return deviceId
    }

    // ─── Server IP (laptop cu Docker) ─────────────────────────────────────────

    /**
     * FIX #5: IP-ul laptopului cu Docker (backend).
     * Configurat de utilizator la prima rulare sau din ecranul de setări.
     * Format: "192.168.X.Y" (fără port sau protocol)
     */
    fun storeServerIp(ip: String) =
        prefs.edit().putString("server_ip", ip).apply()

    fun getServerIp(): String? =
        prefs.getString("server_ip", null)

    // ─── POS IP (ESP32 — WiFi Direct) ─────────────────────────────────────────

    fun storePosIp(ip: String) = plainPrefs.edit().putString("pos_ip", ip).apply()
    fun getPosIp(): String? = plainPrefs.getString("pos_ip", null)

    // ─── Cleanup complet (logout) ──────────────────────────────────────────────

    fun clearAll() {
        prefs.edit().clear().apply()
    }

    companion object {
        @Volatile
        private var instance: SecureStorage? = null

        fun getInstance(context: Context): SecureStorage {
            return instance ?: synchronized(this) {
                instance ?: SecureStorage(context.applicationContext).also { instance = it }
            }
        }
    }
}
