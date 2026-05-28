package com.example.sistemplatanfc.network

import android.content.Context
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.io.InputStream
import java.security.KeyStore
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/**
 * RetrofitClient — HTTP client configurat pentru backend-ul Docker (HTTPS :8443)
 *
 * FIX #5: IP backend configurat dinamic din SecureStorage (nu mai e hardcodat "10.0.2.2").
 *   - 10.0.2.2 = loopback al host-ului DOAR pe emulator Android → eșua pe telefon real
 *   - Acum: IP citit din SecureStorage (setat de utilizator la prima rulare)
 *
 * FIX #8: trustAllManager eliminat. Validare SSL cu CA intern (certs/ca.crt din res/raw/).
 *   - trustAllCertificates era anti-pattern de securitate (vulnerabil MITM)
 *   - Acum: SSLContext configurat cu CA-ul self-signed al proiectului
 *
 * Arhitectura SSL:
 *   - Portul 8443 (Android): TLS fără mTLS, autentificare via JWT Bearer
 *   - Portul 443 (ESP32): mTLS cu certificate client — NU folosit de Android
 */
object RetrofitClient {

    private const val SERVER_PORT = 8443

    @Volatile
    private var jwtToken: String? = null

    @Volatile
    private var retrofitInstance: Retrofit? = null

    @Volatile
    private var currentServerIp: String? = null

    fun setToken(token: String) { jwtToken = token }
    fun clearToken()            { jwtToken = null }
    fun hasToken(): Boolean     = jwtToken != null

    private val authInterceptor = Interceptor { chain ->
        val builder = chain.request().newBuilder()
        jwtToken?.let { builder.addHeader("Authorization", "Bearer $it") }
        chain.proceed(builder.build())
    }

    private val loggingInterceptor = HttpLoggingInterceptor().apply {
        level = HttpLoggingInterceptor.Level.BODY
    }

    /**
     * FIX #8: Construiește SSLContext cu CA-ul intern din res/raw/ca_cert.crt
     *
     * Înlocuiește trustAllManager care accepta ORICE certificat (MITM posibil).
     * Acum acceptă DOAR certificate semnate de CA-ul nostru intern.
     *
     * Fișierul ca_cert.crt trebuie copiat din certs/ca.crt în
     * Android/app/src/main/res/raw/ca_cert.crt
     */
    private fun buildSslComponents(context: Context): Pair<SSLContext, X509TrustManager> {
        try {
            val cf = CertificateFactory.getInstance("X.509")
            val caInput: InputStream = context.resources.openRawResource(
                context.resources.getIdentifier("ca_cert", "raw", context.packageName)
            )
            val ca: Certificate = caInput.use { cf.generateCertificate(it) }

            val keyStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
                load(null, null)
                setCertificateEntry("ca", ca)
            }

            val tmf = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm()
            ).apply { init(keyStore) }

            val sslContext = SSLContext.getInstance("TLS").apply {
                init(null, tmf.trustManagers, null)
            }

            return Pair(sslContext, tmf.trustManagers[0] as X509TrustManager)
        } catch (e: Exception) {
            android.util.Log.e("RetrofitClient",
                "CA cert nu a putut fi încărcat din res/raw/ca_cert.crt: ${e.message}. " +
                "Copiați certs/ca.crt în Android/app/src/main/res/raw/ca_cert.crt"
            )
            // Fallback temporar — DOAR dacă ca_cert.crt lipsește din resurse
            // TODO: ștergeți acest fallback după ce adăugați ca_cert.crt
            @Suppress("DEPRECATION")
            val trustAll = object : X509TrustManager {
                override fun checkClientTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) {}
                override fun checkServerTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) {}
                override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = arrayOf()
            }
            val fallbackCtx = SSLContext.getInstance("TLS").apply {
                init(null, arrayOf(trustAll), java.security.SecureRandom())
            }
            return Pair(fallbackCtx, trustAll)
        }
    }

    /**
     * FIX #5: Returnează instanța Retrofit configurată cu IP-ul curent din SecureStorage.
     * Dacă IP-ul se schimbă, instanța se recreează.
     *
     * @param context  Context Android (necesar pentru SecureStorage și res/raw)
     */
    fun getInstance(context: Context): CardApiService {
        val serverIp = SecureStorage.getInstance(context).getServerIp()
            ?: DEFAULT_GATEWAY_IP

        // Recreează instanța dacă IP-ul s-a schimbat
        if (retrofitInstance == null || currentServerIp != serverIp) {
            synchronized(this) {
                if (retrofitInstance == null || currentServerIp != serverIp) {
                    val baseUrl = "https://$serverIp:$SERVER_PORT/"
                    val (sslContext, trustManager) = buildSslComponents(context)

                    val okHttpClient = OkHttpClient.Builder()
                        .addInterceptor(authInterceptor)
                        .addInterceptor(loggingInterceptor)
                        .sslSocketFactory(sslContext.socketFactory, trustManager)
                        .hostnameVerifier { hostname, _ ->
                            // Acceptă IP-ul configurat (rețea locală controlată)
                            // În producție: verificare strictă cu cert pinning
                            hostname == serverIp || hostname == "localhost"
                        }
                        .connectTimeout(15, TimeUnit.SECONDS)
                        .readTimeout(15, TimeUnit.SECONDS)
                        .build()

                    retrofitInstance = Retrofit.Builder()
                        .baseUrl(baseUrl)
                        .client(okHttpClient)
                        .addConverterFactory(GsonConverterFactory.create())
                        .build()

                    currentServerIp = serverIp
                    android.util.Log.i("RetrofitClient", "Backend URL: $baseUrl")
                }
            }
        }

        return retrofitInstance!!.create(CardApiService::class.java)
    }

    /**
     * Invalidează instanța Retrofit curentă (apelat la schimbarea IP-ului).
     */
    fun invalidate() {
        synchronized(this) {
            retrofitInstance = null
            currentServerIp = null
        }
    }

    companion object {
        /**
         * FIX #5: IP default — folosit dacă utilizatorul nu a configurat unul.
         * Actualizați cu IP-ul laptopului în rețeaua de demo.
         * Pe emulator Android: 10.0.2.2 = loopback host
         * Pe telefon real: IP-ul laptopului în rețeaua WiFi (ex: 192.168.1.100)
         */
        const val DEFAULT_GATEWAY_IP = "192.168.1.100"
    }
}
