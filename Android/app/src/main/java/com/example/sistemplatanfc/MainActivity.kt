package com.example.sistemplatanfc

import android.os.Bundle
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.lazy.items as lazyItems
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.activity.compose.BackHandler
import androidx.compose.material3.LocalTextStyle
import androidx.core.graphics.toColorInt
import androidx.core.view.WindowInsetsControllerCompat
import kotlinx.coroutines.launch
import com.example.sistemplatanfc.data.CardManager
import com.example.sistemplatanfc.data.DevCardSeeder
import com.example.sistemplatanfc.hce.PaymentHceService
import com.example.sistemplatanfc.model.BankCard
import com.example.sistemplatanfc.network.EnrollRequest
import com.example.sistemplatanfc.network.LoginRequest
import com.example.sistemplatanfc.network.PaymentEvent
import com.example.sistemplatanfc.network.RetrofitClient
import com.example.sistemplatanfc.network.TransactionItem
import com.example.sistemplatanfc.network.WifiPaymentClient
import com.example.sistemplatanfc.security.KeystoreManager
import com.example.sistemplatanfc.security.SecureStorage
import com.example.sistemplatanfc.utils.BiometricHelper
import java.nio.charset.StandardCharsets

// ─── Culori globale ────────────────────────────────────────────────────────────

val AppBackground       = Color(0xFFE8E6DF)
val PrimaryText         = Color(0xFF1C1B1A)
val SecondaryText       = Color(0xFF4A4745)
val CardItemBackground  = Color(0xFFDED0BF).copy(alpha = 0.6f)
val DarkButtonBackground  = Color(0xFF2B2927)
val LightButtonBackground = Color(0xFFFFFFFF)

// ─── Fonturi globale ───────────────────────────────────────────────────────────

val TiemposHeadline = FontFamily(Font(R.font.test_tiempos_headline_regular, FontWeight.Normal))
val TiemposText     = FontFamily(Font(R.font.test_tiempos_text_regular,     FontWeight.Normal))
val Afacad          = FontFamily(Font(R.font.afacad_regular,                FontWeight.Normal))

// ─── Payment UI States ────────────────────────────────────────────────────────

sealed class PaymentUiState {
    object Idle : PaymentUiState()
    object EnterIp : PaymentUiState()
    object Connecting : PaymentUiState()
    object AwaitingRequest : PaymentUiState()
    data class ConfirmPayment(
        val amountCents: Long, val currency: String,
        val nonce: String, val timestamp: String
    ) : PaymentUiState()
    data class Processing(val amountCents: Long, val currency: String) : PaymentUiState()
    data class Result(val approved: Boolean, val reason: String?) : PaymentUiState()
    data class Error(val message: String) : PaymentUiState()
}

// ─── Activity ─────────────────────────────────────────────────────────────────

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        WindowInsetsControllerCompat(window, window.decorView).apply {
            isAppearanceLightStatusBars    = true
            isAppearanceLightNavigationBars = true
        }
        window.statusBarColor    = "#E8E6DF".toColorInt()
        window.navigationBarColor = "#E8E6DF".toColorInt()

        val secureStorage = SecureStorage.getInstance(this)

        // Restabileşte token-ul JWT în RetrofitClient (supravieţuieşte restart process)
        secureStorage.getAuthToken()?.let { RetrofitClient.setToken(it) }

        // Înrolează cardurile de test la primul start (fără backend de enrollment)
        DevCardSeeder.seed(this)

        val initialScreen = "wallet" // login eliminat — backend wallet indisponibil

        setContent {
            var currentScreen by remember { mutableStateOf(initialScreen) }

            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize(), color = AppBackground) {

                    // Ordinea stabileşte direcţia animaţiei slide
                    val screenOrder = listOf("login", "wallet", "dashboard", "cards", "addCard")

                    AnimatedContent(
                        targetState = currentScreen,
                        transitionSpec = {
                            val forward = screenOrder.indexOf(targetState) > screenOrder.indexOf(initialState)
                            if (forward) {
                                (slideInHorizontally(tween(350)) { it }  + fadeIn(tween(350))) togetherWith
                                (slideOutHorizontally(tween(350)) { -it } + fadeOut(tween(200)))
                            } else {
                                (slideInHorizontally(tween(350)) { -it } + fadeIn(tween(350))) togetherWith
                                (slideOutHorizontally(tween(350)) { it }  + fadeOut(tween(200)))
                            }
                        },
                        label = "screen_transition"
                    ) { screen ->
                        when (screen) {
                            "login" -> LoginScreen(
                                onLoginSuccess = { currentScreen = "wallet" }
                            )
                            "wallet" -> WalletScreen(
                                activity              = this@MainActivity,
                                onNavigateToCards     = { currentScreen = "cards" },
                                onNavigateToDashboard = { currentScreen = "dashboard" }
                            )
                            "dashboard" -> DashboardScreen(
                                onBack = { currentScreen = "wallet" }
                            )
                            "cards" -> CardsScreen(
                                activity  = this@MainActivity,
                                onBack    = { currentScreen = "wallet" },
                                onAddCard = { currentScreen = "addCard" }
                            )
                            "addCard" -> AddCardScreen(
                                onBack = { currentScreen = "cards" }
                            )
                        }
                    }
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LOGIN SCREEN
// ─────────────────────────────────────────────────────────────────────────────

@Composable
fun LoginScreen(onLoginSuccess: () -> Unit) {
    var username     by remember { mutableStateOf("") }
    var pin          by remember { mutableStateOf("") }
    var isLoading    by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }
    val scope        = rememberCoroutineScope()
    val context      = LocalContext.current
    val scrollState  = rememberScrollState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scrollState)
            .padding(horizontal = 28.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Spacer(modifier = Modifier.height(72.dp))

        Icon(
            painter           = painterResource(id = R.drawable.ic_phone_payment),
            contentDescription = null,
            modifier          = Modifier.size(54.dp),
            tint              = PrimaryText
        )

        Spacer(modifier = Modifier.height(20.dp))

        Text(
            text        = "Digital Wallet",
            fontFamily  = TiemposHeadline,
            fontSize    = 38.sp,
            fontWeight  = FontWeight.Normal,
            color       = PrimaryText,
            textAlign   = TextAlign.Center
        )

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text       = "Autentifică-te pentru a continua",
            fontFamily = TiemposText,
            fontSize   = 15.sp,
            color      = SecondaryText,
            textAlign  = TextAlign.Center
        )

        Spacer(modifier = Modifier.height(48.dp))

        OutlinedTextField(
            value         = username,
            onValueChange = { username = it.trim() },
            label         = { Text("Utilizator", fontFamily = Afacad) },
            placeholder   = { Text("username", fontFamily = Afacad) },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Text, imeAction = ImeAction.Next),
            singleLine    = true,
            modifier      = Modifier.fillMaxWidth(),
            colors        = cardFormColors(),
            textStyle     = LocalTextStyle.current.copy(fontFamily = Afacad)
        )

        Spacer(modifier = Modifier.height(12.dp))

        OutlinedTextField(
            value         = pin,
            onValueChange = { pin = it.filter { c -> c.isDigit() }.take(6) },
            label         = { Text("PIN", fontFamily = Afacad) },
            placeholder   = { Text("······", fontFamily = Afacad) },
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions      = KeyboardOptions(keyboardType = KeyboardType.NumberPassword, imeAction = ImeAction.Done),
            singleLine    = true,
            modifier      = Modifier.fillMaxWidth(),
            colors        = cardFormColors(),
            textStyle     = LocalTextStyle.current.copy(fontFamily = Afacad, letterSpacing = 4.sp)
        )

        errorMessage?.let { msg ->
            Spacer(modifier = Modifier.height(12.dp))
            Text(
                text       = msg,
                color      = Color(0xFFB00020),
                fontFamily = Afacad,
                fontSize   = 14.sp,
                textAlign  = TextAlign.Center,
                modifier   = Modifier.fillMaxWidth()
            )
        }

        Spacer(modifier = Modifier.height(32.dp))

        Button(
            onClick = {
                if (username.isBlank()) { errorMessage = "Introduceți utilizatorul."; return@Button }
                if (pin.length < 4)     { errorMessage = "PIN-ul trebuie să aibă minim 4 cifre."; return@Button }
                errorMessage = null
                isLoading    = true
                scope.launch {
                    try {
                        val resp = RetrofitClient.instance.login(LoginRequest(username, pin))
                        RetrofitClient.setToken(resp.token)
                        SecureStorage.getInstance(context).storeAuthToken(resp.token)
                        onLoginSuccess()
                    } catch (e: Exception) {
                        errorMessage = "Autentificare eșuată: ${e.message ?: "Verificați conexiunea."}"
                    } finally {
                        isLoading = false
                    }
                }
            },
            enabled  = !isLoading,
            colors   = ButtonDefaults.buttonColors(
                containerColor         = DarkButtonBackground,
                disabledContainerColor = DarkButtonBackground.copy(alpha = 0.5f)
            ),
            shape    = RoundedCornerShape(28.dp),
            modifier = Modifier
                .fillMaxWidth()
                .height(52.dp),
            contentPadding = PaddingValues(horizontal = 20.dp)
        ) {
            if (isLoading) {
                CircularProgressIndicator(color = Color.White, modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
            } else {
                Text(
                    text       = "Autentificare",
                    fontFamily = Afacad,
                    fontSize   = 16.sp,
                    fontWeight = FontWeight.Medium,
                    color      = Color.White
                )
            }
        }

        Spacer(modifier = Modifier.height(40.dp))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WALLET SCREEN
// ─────────────────────────────────────────────────────────────────────────────

@Composable
fun WalletScreen(
    activity: AppCompatActivity,
    onNavigateToCards: () -> Unit,
    onNavigateToDashboard: () -> Unit
) {
    val context       = LocalContext.current
    val secureStorage = remember { SecureStorage.getInstance(context) }
    val activeCard    = CardManager.cards.find { it.isActive }

    var paymentState  by remember { mutableStateOf<PaymentUiState>(PaymentUiState.Idle) }
    var paymentClient by remember { mutableStateOf<WifiPaymentClient?>(null) }
    var posIpInput    by remember { mutableStateOf(secureStorage.getPosIp() ?: "") }

    var balance      by remember { mutableStateOf<Double?>(null) }
    var currency     by remember { mutableStateOf("RON") }
    var isFetchingBalance by remember { mutableStateOf(false) }

    // Fetch balance when active card changes
    LaunchedEffect(activeCard) {
        val dpan = activeCard?.let { secureStorage.getDpan(it.id) } ?: activeCard?.dpan
        if (dpan != null) {
            isFetchingBalance = true
            try {
                val resp = RetrofitClient.instance.getBalance(dpan)
                balance = resp.balance
                currency = resp.currency
            } catch (e: Exception) {
                android.util.Log.e("Wallet", "Error fetching balance: ${e.message}")
            } finally {
                isFetchingBalance = false
            }
        } else {
            balance = null
        }
    }

    // Construiește și trimite răspunsul de plată către POS
    fun sendPaymentResponse(
        client: WifiPaymentClient,
        card: BankCard,
        amountCents: Long,
        currency: String,
        nonce: String,
        timestamp: String
    ) {
        val atc = PaymentHceService.getAndIncrementAtc(context)
        val responseBytes = PaymentHceService.buildPaymentResponse(
            card, amountCents.toInt(), currency, nonce, timestamp, atc
        )
        // responseBytes = "dpan|atc|mac" + [0x90, 0x00] → scoatem ultimii 2 bytes
        val responseStr = String(responseBytes, 0, responseBytes.size - 2, StandardCharsets.UTF_8)
        val parts = responseStr.split("|")
        client.sendPaymentResponse(dpan = parts[0], atc = parts[1].toInt(), mac = parts[2])
        paymentState = PaymentUiState.Processing(amountCents, currency)
    }

    fun cancelPayment() {
        paymentClient?.close()
        paymentClient = null
        paymentState  = PaymentUiState.Idle
    }

    // Colectează evenimentele WebSocket
    LaunchedEffect(paymentClient) {
        val client = paymentClient ?: return@LaunchedEffect
        try {
            client.events.collect { event ->
                when (event) {
                    PaymentEvent.Connecting      -> paymentState = PaymentUiState.Connecting
                    PaymentEvent.Connected       -> paymentState = PaymentUiState.AwaitingRequest
                    is PaymentEvent.PaymentRequested -> {
                        val card = CardManager.getActiveCard()
                        if (card == null) {
                            paymentState = PaymentUiState.Error("Niciun card activ")
                            client.close(); paymentClient = null; return@collect
                        }
                        val threshold = secureStorage.getBiometricThresholdCents()
                        if (event.amountCents > threshold) {
                            paymentState = PaymentUiState.ConfirmPayment(
                                event.amountCents, event.currency, event.nonce, event.timestamp
                            )
                        } else {
                            sendPaymentResponse(client, card, event.amountCents, event.currency, event.nonce, event.timestamp)
                        }
                    }
                    is PaymentEvent.PaymentResult -> {
                        paymentState = PaymentUiState.Result(event.approved, event.reason)
                        client.close(); paymentClient = null
                    }
                    is PaymentEvent.ConnectionError -> {
                        paymentState = PaymentUiState.Error(event.message)
                        client.close(); paymentClient = null
                    }
                }
            }
        } finally {
            client.close()
        }
    }

    // Lansează biometria când suma depășește pragul
    val confirmState = paymentState as? PaymentUiState.ConfirmPayment
    LaunchedEffect(confirmState) {
        val state  = confirmState ?: return@LaunchedEffect
        val client = paymentClient ?: return@LaunchedEffect
        val card   = CardManager.getActiveCard() ?: return@LaunchedEffect
        BiometricHelper.showBiometricPrompt(
            activity  = activity,
            onSuccess = {
                if (paymentClient != null) {
                    sendPaymentResponse(client, card, state.amountCents, state.currency, state.nonce, state.timestamp)
                }
            },
            onError = { error ->
                if (paymentClient != null) {
                    paymentState = PaymentUiState.Error("Biometrie eșuată: $error")
                    client.close(); paymentClient = null
                }
            }
        )
    }

    // ── UI ────────────────────────────────────────────────────────────────────
    Box(modifier = Modifier.fillMaxSize()) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 20.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Spacer(modifier = Modifier.height(16.dp))

            // ── Titlu + buton istoric ──────────────────────────────────────────
            Box(modifier = Modifier.fillMaxWidth()) {
                Text(
                    text       = "Digital Wallet",
                    fontFamily = TiemposHeadline,
                    fontSize   = 38.sp,
                    fontWeight = FontWeight.Normal,
                    color      = PrimaryText,
                    textAlign  = TextAlign.Center,
                    modifier   = Modifier
                        .fillMaxWidth()
                        .padding(bottom = 32.dp)
                )
                IconButton(
                    onClick  = onNavigateToDashboard,
                    modifier = Modifier
                        .align(Alignment.CenterEnd)
                        .padding(bottom = 28.dp)
                        .size(40.dp)
                ) {
                    Icon(
                        painter            = painterResource(id = R.drawable.ic_dashboard),
                        contentDescription = "Istoric",
                        tint               = SecondaryText,
                        modifier           = Modifier.size(22.dp)
                    )
                }
            }

            // ── Card activ ────────────────────────────────────────────────────
            activeCard?.let { card ->
                Card(
                    shape    = RoundedCornerShape(20.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .aspectRatio(1.586f),
                    elevation = CardDefaults.cardElevation(defaultElevation = 6.dp)
                ) {
                    Image(
                        painter            = painterResource(id = getCardDrawable(card.bankName)),
                        contentDescription = null,
                        modifier           = Modifier.fillMaxSize(),
                        contentScale       = ContentScale.FillBounds
                    )
                }

                Spacer(modifier = Modifier.height(18.dp))

                Button(
                    onClick = {
                        Toast.makeText(context, "Card: ${card.bankName} ···· ${card.lastFour}", Toast.LENGTH_SHORT).show()
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = LightButtonBackground),
                    shape  = RoundedCornerShape(50.dp),
                    elevation = ButtonDefaults.buttonElevation(0.dp, 0.dp, 0.dp, 0.dp),
                    contentPadding = PaddingValues(horizontal = 20.dp, vertical = 12.dp)
                ) {
                    Icon(
                        painter            = painterResource(id = R.drawable.ic_info),
                        contentDescription = null,
                        tint               = SecondaryText,
                        modifier           = Modifier.size(18.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text       = "Informatii Card",
                        color      = SecondaryText,
                        fontFamily = Afacad,
                        fontSize   = 16.sp,
                        fontWeight = FontWeight.Medium
                    )
                }

                Spacer(modifier = Modifier.height(24.dp))
                if (isFetchingBalance) {
                    CircularProgressIndicator(modifier = Modifier.size(28.dp), strokeWidth = 2.5.dp, color = PrimaryText)
                } else {
                    Text(
                        text       = if (balance != null) "%.2f %s".format(balance, currency) else "---",
                        fontFamily = TiemposHeadline,
                        fontSize   = 36.sp,
                        color      = PrimaryText
                    )
                    Text(
                        text       = "Sold disponibil",
                        fontFamily = Afacad,
                        fontSize   = 14.sp,
                        color      = SecondaryText
                    )
                }
            }

            Spacer(modifier = Modifier.weight(1f))

            // ── Buton Plătește ─────────────────────────────────────────────────
            if (activeCard != null) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Button(
                        onClick = {
                            if (secureStorage.getPosIp().isNullOrBlank()) {
                                paymentState = PaymentUiState.EnterIp
                            } else {
                                posIpInput = secureStorage.getPosIp()!!
                                val client = WifiPaymentClient(posIpInput)
                                paymentClient = client
                                client.connect()
                            }
                        },
                        enabled = (paymentState == PaymentUiState.Idle),
                        colors  = ButtonDefaults.buttonColors(containerColor = DarkButtonBackground),
                        shape   = RoundedCornerShape(28.dp),
                        modifier = Modifier
                            .weight(1f)
                            .height(56.dp),
                        contentPadding = PaddingValues(horizontal = 20.dp)
                    ) {
                        Icon(
                            painter            = painterResource(id = R.drawable.ic_phone_payment),
                            contentDescription = null,
                            tint               = Color.White,
                            modifier           = Modifier.size(22.dp)
                        )
                        Spacer(modifier = Modifier.width(10.dp))
                        Text(
                            text       = "Plătește",
                            fontFamily = Afacad,
                            fontSize   = 18.sp,
                            fontWeight = FontWeight.Medium,
                            color      = Color.White
                        )
                    }

                    IconButton(
                        onClick = { paymentState = PaymentUiState.EnterIp },
                        enabled = (paymentState == PaymentUiState.Idle),
                        modifier = Modifier
                            .size(56.dp)
                            .clip(RoundedCornerShape(28.dp))
                            .background(CardItemBackground)
                    ) {
                        Icon(
                            painter            = painterResource(id = R.drawable.ic_info),
                            contentDescription = "Setări IP",
                            tint               = PrimaryText,
                            modifier           = Modifier.size(20.dp)
                        )
                    }
                }
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text       = if (posIpInput.isNotBlank()) "IP POS: $posIpInput" else "Asigură-te că ești pe același Wi-Fi ca terminalul",
                    fontFamily = Afacad,
                    fontSize   = 13.sp,
                    color      = SecondaryText.copy(alpha = 0.7f),
                    textAlign  = TextAlign.Center
                )
            } else {
                Text(
                    text       = "Adaugă un card pentru a putea plăti",
                    fontFamily = TiemposText,
                    fontSize   = 15.sp,
                    color      = SecondaryText,
                    textAlign  = TextAlign.Center
                )
            }

            Spacer(modifier = Modifier.height(80.dp))
        }

        // ── Buton selectare card ───────────────────────────────────────────────
        Button(
            onClick = onNavigateToCards,
            colors  = ButtonDefaults.buttonColors(containerColor = DarkButtonBackground),
            shape   = RoundedCornerShape(28.dp),
            modifier = Modifier
                .align(Alignment.BottomEnd)
                .padding(end = 20.dp, bottom = 24.dp)
                .height(52.dp),
            contentPadding = PaddingValues(horizontal = 20.dp)
        ) {
            Icon(
                painter            = painterResource(id = R.drawable.ic_card_change),
                contentDescription = null,
                tint               = Color.White,
                modifier           = Modifier.size(20.dp)
            )
            Spacer(modifier = Modifier.width(10.dp))
            Text(
                text       = "Selecteaza Card",
                fontFamily = Afacad,
                fontSize   = 16.sp,
                fontWeight = FontWeight.Medium,
                color      = Color.White
            )
        }
    }

    // ── Dialoguri plată ───────────────────────────────────────────────────────
    when (val state = paymentState) {
        PaymentUiState.Idle -> Unit
        PaymentUiState.EnterIp -> IpEntryDialog(
            posIp       = posIpInput,
            onPosIpChange = { posIpInput = it },
            onConnect   = {
                if (posIpInput.isNotBlank()) {
                    secureStorage.storePosIp(posIpInput)
                    val client = WifiPaymentClient(posIpInput)
                    paymentClient = client
                    client.connect()
                }
            },
            onDismiss   = { paymentState = PaymentUiState.Idle }
        )
        else -> PaymentStatusDialog(state = state, onDismiss = { cancelPayment() })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PAYMENT DIALOGS
// ─────────────────────────────────────────────────────────────────────────────

@Composable
fun IpEntryDialog(
    posIp: String,
    onPosIpChange: (String) -> Unit,
    onConnect: () -> Unit,
    onDismiss: () -> Unit
) {
    Dialog(onDismissRequest = onDismiss) {
        Card(
            shape  = RoundedCornerShape(20.dp),
            colors = CardDefaults.cardColors(containerColor = AppBackground),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text(
                    text       = "Terminal POS",
                    fontFamily = TiemposHeadline,
                    fontSize   = 22.sp,
                    color      = PrimaryText
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text       = "Introdu IP-ul terminalului de plată",
                    fontFamily = Afacad,
                    fontSize   = 14.sp,
                    color      = SecondaryText,
                    textAlign  = TextAlign.Center
                )
                Spacer(modifier = Modifier.height(20.dp))
                OutlinedTextField(
                    value         = posIp,
                    onValueChange = onPosIpChange,
                    label         = { Text("IP Terminal", fontFamily = Afacad) },
                    placeholder   = { Text("192.168.1.100", fontFamily = Afacad) },
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.Uri,
                        imeAction    = ImeAction.Done
                    ),
                    singleLine  = true,
                    modifier    = Modifier.fillMaxWidth(),
                    colors      = cardFormColors(),
                    textStyle   = LocalTextStyle.current.copy(fontFamily = Afacad)
                )
                Spacer(modifier = Modifier.height(24.dp))
                Row(
                    modifier              = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    OutlinedButton(
                        onClick  = onDismiss,
                        shape    = RoundedCornerShape(28.dp),
                        modifier = Modifier.weight(1f).height(48.dp)
                    ) {
                        Text("Anulează", fontFamily = Afacad, fontSize = 15.sp, color = SecondaryText)
                    }
                    Button(
                        onClick  = onConnect,
                        enabled  = posIp.isNotBlank(),
                        colors   = ButtonDefaults.buttonColors(containerColor = DarkButtonBackground),
                        shape    = RoundedCornerShape(28.dp),
                        modifier = Modifier.weight(1f).height(48.dp)
                    ) {
                        Text("Conectare", fontFamily = Afacad, fontSize = 15.sp, color = Color.White)
                    }
                }
            }
        }
    }
}

@Composable
fun PaymentStatusDialog(state: PaymentUiState, onDismiss: () -> Unit) {
    Dialog(onDismissRequest = {
        // Permite dismiss doar la final (Result/Error)
        if (state is PaymentUiState.Result || state is PaymentUiState.Error) onDismiss()
    }) {
        Card(
            shape  = RoundedCornerShape(20.dp),
            colors = CardDefaults.cardColors(containerColor = AppBackground),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(28.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                when (state) {
                    PaymentUiState.Connecting -> {
                        CircularProgressIndicator(color = PrimaryText, modifier = Modifier.size(48.dp))
                        Text("Conectare la terminal...", fontFamily = TiemposText, fontSize = 16.sp, color = PrimaryText, textAlign = TextAlign.Center)
                        OutlinedButton(onClick = onDismiss, shape = RoundedCornerShape(28.dp)) {
                            Text("Anulează", fontFamily = Afacad, color = SecondaryText)
                        }
                    }
                    PaymentUiState.AwaitingRequest -> {
                        CircularProgressIndicator(color = PrimaryText, modifier = Modifier.size(48.dp))
                        Text("Așteptare cerere de plată...", fontFamily = TiemposText, fontSize = 16.sp, color = PrimaryText, textAlign = TextAlign.Center)
                        OutlinedButton(onClick = onDismiss, shape = RoundedCornerShape(28.dp)) {
                            Text("Anulează", fontFamily = Afacad, color = SecondaryText)
                        }
                    }
                    is PaymentUiState.ConfirmPayment -> {
                        CircularProgressIndicator(color = PrimaryText, modifier = Modifier.size(48.dp))
                        Text(
                            text = "%.2f %s".format(state.amountCents / 100.0, state.currency),
                            fontFamily = TiemposHeadline,
                            fontSize   = 32.sp,
                            color      = PrimaryText
                        )
                        Text("Verificare identitate...", fontFamily = TiemposText, fontSize = 15.sp, color = SecondaryText, textAlign = TextAlign.Center)
                    }
                    is PaymentUiState.Processing -> {
                        CircularProgressIndicator(color = PrimaryText, modifier = Modifier.size(48.dp))
                        Text(
                            text = "%.2f %s".format(state.amountCents / 100.0, state.currency),
                            fontFamily = TiemposHeadline,
                            fontSize   = 32.sp,
                            color      = PrimaryText
                        )
                        Text("Procesare plată...", fontFamily = TiemposText, fontSize = 15.sp, color = SecondaryText, textAlign = TextAlign.Center)
                    }
                    is PaymentUiState.Result -> {
                        val approved = state.approved
                        Icon(
                            painter            = painterResource(if (approved) R.drawable.ic_phone_payment else R.drawable.ic_info),
                            contentDescription = null,
                            tint               = if (approved) Color(0xFF2E7D32) else Color(0xFFB00020),
                            modifier           = Modifier.size(56.dp)
                        )
                        Text(
                            text       = if (approved) "Plată aprobată!" else "Plată refuzată",
                            fontFamily = TiemposHeadline,
                            fontSize   = 24.sp,
                            color      = if (approved) Color(0xFF2E7D32) else Color(0xFFB00020)
                        )
                        state.reason?.let {
                            Text(it, fontFamily = Afacad, fontSize = 14.sp, color = SecondaryText, textAlign = TextAlign.Center)
                        }
                        Button(
                            onClick  = onDismiss,
                            colors   = ButtonDefaults.buttonColors(containerColor = DarkButtonBackground),
                            shape    = RoundedCornerShape(28.dp),
                            modifier = Modifier.fillMaxWidth().height(48.dp)
                        ) {
                            Text("OK", fontFamily = Afacad, fontSize = 16.sp, color = Color.White)
                        }
                    }
                    is PaymentUiState.Error -> {
                        Icon(
                            painter            = painterResource(R.drawable.ic_info),
                            contentDescription = null,
                            tint               = Color(0xFFB00020),
                            modifier           = Modifier.size(48.dp)
                        )
                        Text("Eroare conexiune", fontFamily = TiemposHeadline, fontSize = 20.sp, color = PrimaryText)
                        Text(state.message, fontFamily = Afacad, fontSize = 14.sp, color = SecondaryText, textAlign = TextAlign.Center)
                        Button(
                            onClick  = onDismiss,
                            colors   = ButtonDefaults.buttonColors(containerColor = DarkButtonBackground),
                            shape    = RoundedCornerShape(28.dp),
                            modifier = Modifier.fillMaxWidth().height(48.dp)
                        ) {
                            Text("OK", fontFamily = Afacad, fontSize = 16.sp, color = Color.White)
                        }
                    }
                    else -> Unit
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DASHBOARD SCREEN
// ─────────────────────────────────────────────────────────────────────────────

@Composable
fun DashboardScreen(onBack: () -> Unit) {
    val context      = LocalContext.current
    val secureStorage = remember { SecureStorage.getInstance(context) }

    var balance      by remember { mutableStateOf<Double?>(null) }
    var currency     by remember { mutableStateOf("RON") }
    var transactions by remember { mutableStateOf<List<TransactionItem>>(emptyList()) }
    var isLoading    by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }

    BackHandler { onBack() }

    // Încarcă datele la prima afișare
    LaunchedEffect(Unit) {
        val activeCard = CardManager.cards.find { it.isActive }
        val dpan = activeCard?.let { secureStorage.getDpan(it.id) } ?: activeCard?.dpan
        if (dpan == null) {
            errorMessage = "Niciun card activ. Adaugă un card mai întâi."
            return@LaunchedEffect
        }
        isLoading = true
        try {
            val balResp = RetrofitClient.instance.getBalance(dpan)
            balance  = balResp.balance
            currency = balResp.currency
            transactions = RetrofitClient.instance.getTransactionHistory(dpan)
        } catch (e: Exception) {
            errorMessage = "Eroare încărcare date: ${e.message ?: "Verificați conexiunea."}"
        } finally {
            isLoading = false
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 20.dp)
    ) {
        Spacer(modifier = Modifier.height(16.dp))

        // ── Header ────────────────────────────────────────────────────────────
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
            IconButton(onClick = onBack, modifier = Modifier.size(40.dp)) {
                Icon(
                    painter            = painterResource(id = R.drawable.ic_back),
                    contentDescription = "Înapoi",
                    tint               = PrimaryText,
                    modifier           = Modifier.size(24.dp)
                )
            }
            Text(
                text       = "Cont",
                fontFamily = TiemposHeadline,
                fontSize   = 38.sp,
                fontWeight = FontWeight.Normal,
                color      = PrimaryText,
                textAlign  = TextAlign.Center,
                modifier   = Modifier
                    .weight(1f)
                    .padding(end = 40.dp)
            )
        }

        Spacer(modifier = Modifier.height(24.dp))

        if (isLoading) {
            Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                CircularProgressIndicator(color = PrimaryText, modifier = Modifier.size(40.dp))
            }
        } else if (errorMessage != null) {
            Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Text(
                    text       = errorMessage!!,
                    fontFamily = TiemposText,
                    fontSize   = 15.sp,
                    color      = SecondaryText,
                    textAlign  = TextAlign.Center
                )
            }
        } else {
            // ── Card sold ─────────────────────────────────────────────────────
            balance?.let { bal ->
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(20.dp))
                        .background(DarkButtonBackground)
                        .padding(horizontal = 24.dp, vertical = 22.dp)
                ) {
                    Column {
                        Text(
                            text       = "Sold disponibil",
                            fontFamily = Afacad,
                            fontSize   = 13.sp,
                            color      = Color.White.copy(alpha = 0.6f)
                        )
                        Spacer(modifier = Modifier.height(6.dp))
                        Text(
                            text       = "%.2f %s".format(bal, currency),
                            fontFamily = TiemposHeadline,
                            fontSize   = 32.sp,
                            fontWeight = FontWeight.Normal,
                            color      = Color.White
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(28.dp))

            // ── Titlu tranzacții ──────────────────────────────────────────────
            Text(
                text       = "Tranzacții recente",
                fontFamily = TiemposText,
                fontSize   = 16.sp,
                color      = SecondaryText,
                modifier   = Modifier.padding(bottom = 12.dp)
            )

            if (transactions.isEmpty()) {
                Box(
                    modifier          = Modifier.fillMaxWidth().padding(top = 40.dp),
                    contentAlignment  = Alignment.Center
                ) {
                    Text(
                        text       = "Nu există tranzacții.",
                        fontFamily = TiemposText,
                        fontSize   = 15.sp,
                        color      = SecondaryText.copy(alpha = 0.6f),
                        textAlign  = TextAlign.Center
                    )
                }
            } else {
                LazyColumn(
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                    modifier            = Modifier.fillMaxSize()
                ) {
                    lazyItems(transactions) { tx ->
                        TransactionRow(tx)
                    }
                    item { Spacer(modifier = Modifier.height(24.dp)) }
                }
            }
        }
    }
}

@Composable
fun TransactionRow(tx: TransactionItem) {
    val statusColor = when (tx.status.lowercase()) {
        "approved" -> Color(0xFF2E7D32)
        "declined" -> Color(0xFFB00020)
        else       -> SecondaryText
    }
    val statusLabel = when (tx.status.lowercase()) {
        "approved" -> "Aprobat"
        "declined" -> "Refuzat"
        else       -> "În procesare"
    }
    val sign = if (tx.status.lowercase() == "approved") "-" else ""

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(CardItemBackground)
            .padding(horizontal = 16.dp, vertical = 14.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment     = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text       = tx.merchantName,
                fontFamily = Afacad,
                fontSize   = 15.sp,
                fontWeight = FontWeight.Medium,
                color      = PrimaryText,
                maxLines   = 1
            )
            Spacer(modifier = Modifier.height(3.dp))
            Text(
                text       = formatTransactionDate(tx.timestamp),
                fontFamily = Afacad,
                fontSize   = 12.sp,
                color      = SecondaryText
            )
        }

        Column(horizontalAlignment = Alignment.End) {
            Text(
                text       = "$sign%.2f %s".format(tx.amount, tx.currency),
                fontFamily = Afacad,
                fontSize   = 15.sp,
                fontWeight = FontWeight.Medium,
                color      = PrimaryText
            )
            Spacer(modifier = Modifier.height(3.dp))
            Text(
                text       = statusLabel,
                fontFamily = Afacad,
                fontSize   = 12.sp,
                color      = statusColor
            )
        }
    }
}

/** Formatează ISO 8601 (ex: "2025-05-26T14:32:00Z") în "26 Mai 2025, 14:32" */
fun formatTransactionDate(iso: String): String {
    return try {
        val parts    = iso.substringBefore("T").split("-")
        val timePart = iso.substringAfter("T").take(5)
        val months   = listOf("","Ian","Feb","Mar","Apr","Mai","Iun","Iul","Aug","Sep","Oct","Nov","Dec")
        val m        = parts[1].toIntOrNull() ?: 0
        "${parts[2]} ${months.getOrElse(m) { parts[1] }} ${parts[0]}, $timePart"
    } catch (_: Exception) {
        iso
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CARDS SCREEN
// ─────────────────────────────────────────────────────────────────────────────

@Composable
fun CardsScreen(activity: AppCompatActivity, onBack: () -> Unit, onAddCard: () -> Unit) {
    val cards   = CardManager.cards
    val context = LocalContext.current

    BackHandler { onBack() }

    Box(modifier = Modifier.fillMaxSize()) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 20.dp)
        ) {
            Spacer(modifier = Modifier.height(16.dp))

            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
                IconButton(onClick = onBack, modifier = Modifier.size(40.dp)) {
                    Icon(
                        painter            = painterResource(id = R.drawable.ic_back),
                        contentDescription = "Înapoi",
                        tint               = PrimaryText,
                        modifier           = Modifier.size(24.dp)
                    )
                }
                Text(
                    text       = "Carduri",
                    fontFamily = TiemposHeadline,
                    fontSize   = 38.sp,
                    fontWeight = FontWeight.Normal,
                    color      = PrimaryText,
                    textAlign  = TextAlign.Center,
                    modifier   = Modifier
                        .weight(1f)
                        .padding(end = 40.dp)
                )
            }

            Spacer(modifier = Modifier.height(20.dp))

            Text(
                text       = "Selecteaza cardul dorit",
                fontFamily = TiemposText,
                fontSize   = 16.sp,
                color      = SecondaryText,
                modifier   = Modifier.padding(bottom = 16.dp)
            )

            LazyVerticalGrid(
                columns              = GridCells.Fixed(2),
                horizontalArrangement = Arrangement.spacedBy(14.dp),
                verticalArrangement  = Arrangement.spacedBy(14.dp),
                modifier             = Modifier.weight(1f)
            ) {
                items(cards) { card ->
                    CardItemNew(
                        card     = card,
                        isActive = card.isActive,
                        onClick  = {
                            BiometricHelper.showBiometricPrompt(
                                activity  = activity,
                                onSuccess = {
                                    CardManager.setActiveCard(card.id)
                                    onBack()
                                },
                                onError = { error ->
                                    Toast.makeText(context, "Eroare: $error", Toast.LENGTH_SHORT).show()
                                }
                            )
                        }
                    )
                }
            }

            Spacer(modifier = Modifier.height(80.dp))
        }

        Button(
            onClick = onAddCard,
            colors  = ButtonDefaults.buttonColors(containerColor = DarkButtonBackground),
            shape   = RoundedCornerShape(28.dp),
            modifier = Modifier
                .align(Alignment.BottomEnd)
                .padding(end = 20.dp, bottom = 24.dp)
                .height(52.dp),
            contentPadding = PaddingValues(horizontal = 20.dp)
        ) {
            Icon(
                painter            = painterResource(id = R.drawable.ic_add_card),
                contentDescription = null,
                tint               = Color.White,
                modifier           = Modifier.size(20.dp)
            )
            Spacer(modifier = Modifier.width(10.dp))
            Text(
                text       = "Adauga Card Nou",
                fontFamily = Afacad,
                fontSize   = 16.sp,
                fontWeight = FontWeight.Medium,
                color      = Color.White
            )
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CARD ITEM (grid)
// ─────────────────────────────────────────────────────────────────────────────

@Composable
fun CardItemNew(card: BankCard, isActive: Boolean, onClick: () -> Unit) {
    val interactionSource = remember { MutableInteractionSource() }
    val isPressed by interactionSource.collectIsPressedAsState()

    val scale by animateFloatAsState(
        targetValue  = if (isPressed) 0.95f else 1f,
        animationSpec = spring(dampingRatio = Spring.DampingRatioMediumBouncy, stiffness = Spring.StiffnessHigh),
        label        = "card_scale"
    )
    val bgColor by animateColorAsState(
        targetValue   = if (isActive) DarkButtonBackground else CardItemBackground,
        animationSpec = tween(300),
        label         = "card_bg"
    )
    val textColor by animateColorAsState(
        targetValue   = if (isActive) Color.White else PrimaryText,
        animationSpec = tween(300),
        label         = "card_text"
    )

    Column(
        modifier = Modifier
            .scale(scale)
            .clip(RoundedCornerShape(14.dp))
            .background(color = bgColor)
            .clickable(interactionSource = interactionSource, indication = null) { onClick() }
            .padding(10.dp)
    ) {
        Card(
            shape    = RoundedCornerShape(10.dp),
            modifier = Modifier
                .fillMaxWidth()
                .aspectRatio(1.586f),
            elevation = CardDefaults.cardElevation(defaultElevation = 3.dp)
        ) {
            Image(
                painter            = painterResource(id = getCardDrawable(card.bankName)),
                contentDescription = null,
                modifier           = Modifier.fillMaxSize(),
                contentScale       = ContentScale.FillBounds
            )
        }

        Spacer(modifier = Modifier.height(10.dp))

        Row(
            modifier              = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment     = Alignment.CenterVertically
        ) {
            Text(
                text       = "Card ${getShortBankName(card.bankName)}",
                color      = textColor,
                fontFamily = Afacad,
                fontSize   = 13.sp,
                fontWeight = FontWeight.Medium,
                maxLines   = 1
            )
            Text(
                text       = "···· ${card.lastFour}",
                color      = textColor,
                fontFamily = Afacad,
                fontSize   = 13.sp,
                maxLines   = 1
            )
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ADD CARD SCREEN
// ─────────────────────────────────────────────────────────────────────────────

@Composable
fun AddCardScreen(onBack: () -> Unit) {
    var panDigits      by remember { mutableStateOf("") }
    var expiryRaw      by remember { mutableStateOf("") }   // "MMYY"
    var cvv            by remember { mutableStateOf("") }
    var cardholderName by remember { mutableStateOf("") }
    var isLoading      by remember { mutableStateOf(false) }
    var errorMessage   by remember { mutableStateOf<String?>(null) }
    val scope          = rememberCoroutineScope()
    val scrollState    = rememberScrollState()
    val context        = LocalContext.current

    BackHandler { onBack() }

    val formattedPanDisplay = panDigits.chunked(4).joinToString(" ")
    val expiryDisplay = if (expiryRaw.length > 2) "${expiryRaw.take(2)}/${expiryRaw.drop(2)}" else expiryRaw

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scrollState)
            .padding(horizontal = 20.dp)
    ) {
        Spacer(modifier = Modifier.height(16.dp))

        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
            IconButton(onClick = onBack, modifier = Modifier.size(40.dp)) {
                Icon(
                    painter            = painterResource(R.drawable.ic_back),
                    contentDescription = "Înapoi",
                    tint               = PrimaryText,
                    modifier           = Modifier.size(24.dp)
                )
            }
            Text(
                text       = "Adauga Card",
                fontFamily = TiemposHeadline,
                fontSize   = 38.sp,
                fontWeight = FontWeight.Normal,
                color      = PrimaryText,
                textAlign  = TextAlign.Center,
                modifier   = Modifier
                    .weight(1f)
                    .padding(end = 40.dp)
            )
        }

        Spacer(modifier = Modifier.height(24.dp))

        CardPreviewWidget(panDigits = panDigits, expiry = expiryDisplay, cardholderName = cardholderName)

        Spacer(modifier = Modifier.height(28.dp))

        // ── PAN ───────────────────────────────────────────────────────────────
        OutlinedTextField(
            value         = formattedPanDisplay,
            onValueChange = { panDigits = it.filter { c -> c.isDigit() }.take(16) },
            label         = { Text("Numar card", fontFamily = Afacad) },
            placeholder   = { Text("1234 5678 9012 3456", fontFamily = Afacad) },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number, imeAction = ImeAction.Next),
            singleLine    = true,
            modifier      = Modifier.fillMaxWidth(),
            colors        = cardFormColors(),
            textStyle     = LocalTextStyle.current.copy(fontFamily = Afacad, letterSpacing = 2.sp)
        )

        Spacer(modifier = Modifier.height(12.dp))

        // ── Titular ───────────────────────────────────────────────────────────
        OutlinedTextField(
            value         = cardholderName,
            onValueChange = { cardholderName = it.uppercase().take(26) },
            label         = { Text("Titular card", fontFamily = Afacad) },
            placeholder   = { Text("PRENUME NUME", fontFamily = Afacad) },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Text, imeAction = ImeAction.Next),
            singleLine    = true,
            modifier      = Modifier.fillMaxWidth(),
            colors        = cardFormColors(),
            textStyle     = LocalTextStyle.current.copy(fontFamily = Afacad, letterSpacing = 1.sp)
        )

        Spacer(modifier = Modifier.height(12.dp))

        // ── Expirare + CVV ────────────────────────────────────────────────────
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            OutlinedTextField(
                value         = expiryDisplay,
                onValueChange = { expiryRaw = it.filter { c -> c.isDigit() }.take(4) },
                label         = { Text("Expirare", fontFamily = Afacad) },
                placeholder   = { Text("MM/YY", fontFamily = Afacad) },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number, imeAction = ImeAction.Next),
                singleLine    = true,
                modifier      = Modifier.weight(1f),
                colors        = cardFormColors(),
                textStyle     = LocalTextStyle.current.copy(fontFamily = Afacad)
            )
            OutlinedTextField(
                value         = cvv,
                onValueChange = { cvv = it.filter { c -> c.isDigit() }.take(4) },
                label         = { Text("CVV", fontFamily = Afacad) },
                placeholder   = { Text("···", fontFamily = Afacad) },
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions      = KeyboardOptions(keyboardType = KeyboardType.Number, imeAction = ImeAction.Done),
                singleLine    = true,
                modifier      = Modifier.weight(1f),
                colors        = cardFormColors(),
                textStyle     = LocalTextStyle.current.copy(fontFamily = Afacad)
            )
        }

        errorMessage?.let { msg ->
            Spacer(modifier = Modifier.height(12.dp))
            Text(text = msg, color = Color(0xFFB00020), fontFamily = Afacad, fontSize = 14.sp)
        }

        Spacer(modifier = Modifier.height(32.dp))

        // ── Buton înrolare ────────────────────────────────────────────────────
        Button(
            onClick = {
                if (panDigits.length < 16)  { errorMessage = "Numarul de card este incomplet."; return@Button }
                if (expiryRaw.length < 4)   { errorMessage = "Data expirarii este invalida."; return@Button }
                if (cvv.length < 3)         { errorMessage = "CVV-ul este invalid."; return@Button }
                errorMessage = null
                isLoading    = true
                scope.launch {
                    try {
                        val secureStorage = SecureStorage.getInstance(context)
                        val deviceId      = secureStorage.getDeviceId()

                        // expiryRaw = "MMYY" → expiryMonth = "MM", expiryYear = "20YY"
                        val expiryMonth = expiryRaw.take(2)
                        val expiryYear  = "20${expiryRaw.drop(2)}"

                        val enrolled = RetrofitClient.instance.enrollCard(
                            EnrollRequest(
                                pan         = panDigits,
                                expiryMonth = expiryMonth,
                                expiryYear  = expiryYear,
                                cvv         = cvv,
                                deviceId    = deviceId
                            )
                        )

                        // Stochează K_user în Android Hardware-Backed Keystore
                        KeystoreManager.importHmacKey(enrolled.id, enrolled.hmacKeyHex)

                        // Stochează DPAN în EncryptedSharedPreferences
                        secureStorage.storeDpan(enrolled.id, enrolled.dpan)

                        // Stochează pragul biometric (RON → cenți)
                        secureStorage.storeBiometricThresholdCents(
                            (enrolled.biometricThresholdRon * 100).toLong()
                        )

                        // Salvează cheia publică a băncii (opțional, pentru verificări viitoare)
                        enrolled.bankPublicKeyPemB64?.let {
                            secureStorage.storeBankPublicKey(enrolled.id, it)
                        }

                        // Creează BankCard și adaugă în CardManager
                        val bankCard = BankCard(
                            id        = enrolled.id,
                            bankName  = enrolled.bankName,
                            dpan      = enrolled.dpan,
                            secretKey = enrolled.hmacKeyHex,   // fallback dacă Keystore nu e disponibil
                            cardType  = enrolled.cardType,
                            lastFour  = enrolled.lastFour
                        )
                        CardManager.addCard(bankCard)

                        onBack()
                    } catch (e: Exception) {
                        errorMessage = "Eroare server: ${e.message ?: "Verificati conexiunea."}"
                    } finally {
                        isLoading = false
                    }
                }
            },
            enabled  = !isLoading,
            colors   = ButtonDefaults.buttonColors(
                containerColor         = DarkButtonBackground,
                disabledContainerColor = DarkButtonBackground.copy(alpha = 0.5f)
            ),
            shape    = RoundedCornerShape(28.dp),
            modifier = Modifier
                .fillMaxWidth()
                .height(52.dp),
            contentPadding = PaddingValues(horizontal = 20.dp)
        ) {
            if (isLoading) {
                CircularProgressIndicator(color = Color.White, modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
            } else {
                Icon(
                    painter            = painterResource(R.drawable.ic_add_card),
                    contentDescription = null,
                    tint               = Color.White,
                    modifier           = Modifier.size(20.dp)
                )
                Spacer(modifier = Modifier.width(10.dp))
                Text(
                    text       = "Adauga Card",
                    fontFamily = Afacad,
                    fontSize   = 16.sp,
                    fontWeight = FontWeight.Medium,
                    color      = Color.White
                )
            }
        }

        Spacer(modifier = Modifier.height(32.dp))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CARD PREVIEW WIDGET
// ─────────────────────────────────────────────────────────────────────────────

@Composable
fun CardPreviewWidget(panDigits: String, expiry: String, cardholderName: String) {
    val prefix2  = panDigits.take(2).toIntOrNull() ?: 0
    val cardType = when {
        panDigits.startsWith("4") -> "VISA"
        prefix2 in 51..55         -> "MASTERCARD"
        else                      -> null
    }

    val cardColorStart by animateColorAsState(
        targetValue = when {
            panDigits.startsWith("4") -> Color(0xFF1565C0)
            prefix2 in 51..55         -> Color(0xFF212121)
            else                      -> Color(0xFF374151)
        },
        animationSpec = tween(600), label = "card_color_start"
    )
    val cardColorEnd by animateColorAsState(
        targetValue = when {
            panDigits.startsWith("4") -> Color(0xFF0D47A1)
            prefix2 in 51..55         -> Color(0xFF424242)
            else                      -> Color(0xFF1F2937)
        },
        animationSpec = tween(600), label = "card_color_end"
    )

    val displayPan = buildString {
        for (i in 0..15) {
            if (i > 0 && i % 4 == 0) append(' ')
            append(panDigits.getOrNull(i) ?: '·')
        }
    }

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .aspectRatio(1.586f)
            .clip(RoundedCornerShape(16.dp))
            .background(Brush.linearGradient(listOf(cardColorStart, cardColorEnd)))
            .padding(horizontal = 20.dp, vertical = 18.dp)
    ) {
        cardType?.let {
            Text(
                text       = it,
                color      = Color.White,
                fontFamily = Afacad,
                fontSize   = 15.sp,
                fontWeight = FontWeight.Bold,
                modifier   = Modifier.align(Alignment.TopEnd)
            )
        }

        Text(
            text        = displayPan,
            color       = Color.White,
            fontFamily  = Afacad,
            fontSize    = 19.sp,
            letterSpacing = 2.sp,
            modifier    = Modifier.align(Alignment.Center)
        )

        Row(
            modifier              = Modifier.fillMaxWidth().align(Alignment.BottomCenter),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment     = Alignment.Bottom
        ) {
            Column {
                Text(text = "TITULAR", color = Color.White.copy(alpha = 0.6f), fontFamily = Afacad, fontSize = 9.sp)
                Text(
                    text       = cardholderName.ifEmpty { "TITULAR" }.take(22),
                    color      = Color.White,
                    fontFamily = Afacad,
                    fontSize   = 13.sp,
                    fontWeight = FontWeight.Medium
                )
            }
            Column(horizontalAlignment = Alignment.End) {
                Text(text = "EXPIRA", color = Color.White.copy(alpha = 0.6f), fontFamily = Afacad, fontSize = 9.sp)
                Text(
                    text       = expiry.ifEmpty { "MM/YY" },
                    color      = Color.White,
                    fontFamily = Afacad,
                    fontSize   = 13.sp,
                    fontWeight = FontWeight.Medium
                )
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────────────

@Composable
fun cardFormColors() = OutlinedTextFieldDefaults.colors(
    focusedBorderColor    = PrimaryText,
    unfocusedBorderColor  = SecondaryText.copy(alpha = 0.35f),
    focusedLabelColor     = PrimaryText,
    unfocusedLabelColor   = SecondaryText,
    cursorColor           = PrimaryText,
    focusedTextColor      = PrimaryText,
    unfocusedTextColor    = PrimaryText,
    focusedContainerColor   = Color.Transparent,
    unfocusedContainerColor = Color.Transparent
)

fun getShortBankName(bankName: String): String = when {
    bankName.contains("Transilvania", true) -> "BT"
    bankName.contains("ING", true)          -> "ING"
    bankName.contains("UniCredit", true)    -> "Unicredit"
    bankName.contains("BRD", true)          -> "BRD"
    bankName.contains("BCR", true)          -> "BCR"
    else                                    -> bankName.split(" ").first()
}

fun getCardDrawable(bankName: String): Int = when {
    bankName.contains("Transilvania", true) -> R.drawable.card_bt
    bankName.contains("ING", true)          -> R.drawable.card_ing
    bankName.contains("UniCredit", true)    -> R.drawable.card_unicredit
    else                                    -> R.drawable.card_bt
}
