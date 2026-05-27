package com.example.sistemplatanfc.network

import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

object RetrofitClient {

    /**
     * IP-ul laptop-ului cu serverul backend.
     * Schimbă SERVER_IP când ești pe WiFi real (ex: "192.168.1.100").
     * Pe emulator: 10.0.2.2 = localhost al computerului host.
     *
     * TODO: Mută în BuildConfig sau ecran de setări pentru flexibilitate.
     */
    private const val SERVER_IP   = "10.0.2.2"
    private const val SERVER_PORT = 8443
    private const val BASE_URL    = "https://$SERVER_IP:$SERVER_PORT/"

    @Volatile
    private var jwtToken: String? = null

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
     * TrustManager care acceptă certificate self-signed de pe serverul local.
     *
     * SECURITATE:
     *  ✅ OK pentru demo/cercetare pe rețea locală controlată (laptop ↔ telefon).
     *  ❌ NU folosiți în producție. Înlocuiți cu certificate pinning sau CA propriu.
     *
     * Alternativă fără trust-all: instalează CA-ul self-signed pe telefon
     * (Settings → Security → Install certificate) și folosește network_security_config.xml.
     */
    private val trustAllManager = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    }

    private val sslContext = SSLContext.getInstance("TLS").also {
        it.init(null, arrayOf<TrustManager>(trustAllManager), SecureRandom())
    }

    private val okHttpClient = OkHttpClient.Builder()
        .addInterceptor(authInterceptor)
        .addInterceptor(loggingInterceptor)
        .sslSocketFactory(sslContext.socketFactory, trustAllManager)
        .hostnameVerifier { _, _ -> true }
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .build()

    val instance: CardApiService by lazy {
        Retrofit.Builder()
            .baseUrl(BASE_URL)
            .client(okHttpClient)
            .addConverterFactory(GsonConverterFactory.create())
            .build()
            .create(CardApiService::class.java)
    }
}
