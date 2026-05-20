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
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.graphics.Brush
import androidx.compose.material3.LocalTextStyle
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.core.graphics.toColorInt
import androidx.core.view.WindowInsetsControllerCompat
import kotlinx.coroutines.launch
import com.example.sistemplatanfc.data.CardManager
import com.example.sistemplatanfc.model.BankCard
import com.example.sistemplatanfc.network.EnrollRequest
import com.example.sistemplatanfc.network.RetrofitClient
import com.example.sistemplatanfc.utils.BiometricHelper

val AppBackground = Color(0xFFE8E6DF)
val PrimaryText = Color(0xFF1C1B1A)
val SecondaryText = Color(0xFF4A4745)
val CardItemBackground = Color(0xFFDED0BF).copy(alpha = 0.6f)
val DarkButtonBackground = Color(0xFF2B2927)
val LightButtonBackground = Color(0xFFFFFFFF)

val TiemposHeadline = FontFamily(
    Font(R.font.test_tiempos_headline_regular, FontWeight.Normal),
)
val TiemposText = FontFamily(
    Font(R.font.test_tiempos_text_regular, FontWeight.Normal)
)
val Afacad = FontFamily(
    Font(R.font.afacad_regular, FontWeight.Normal)
)

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        WindowInsetsControllerCompat(window, window.decorView).apply {
            isAppearanceLightStatusBars = true
            isAppearanceLightNavigationBars = true
        }
        window.statusBarColor = "#E8E6DF".toColorInt()
        window.navigationBarColor = "#E8E6DF".toColorInt()

        if (CardManager.cards.isEmpty()) {
            CardManager.addCard(BankCard("1", "Banca Transilvania", "4000000000000001",
                "6f8d2b9a1c4e7f3d5b0e8a4c2f1d9e7b5a3c8f0d4e2b1a9c7f6d5e4b3a2c1f0e", "VISA", "1234", true))
            CardManager.addCard(BankCard("2", "BRD", "5000000000000002",
                "c98fcaa4e11fc749d19700af104603cec1b4f058bc85a46c734c81892d2caf3e", "VISA", "5142"))
            CardManager.addCard(BankCard("3", "ING Bank", "5000000000000003",
                "c98fcaa4e11fc749d19700af104603cec1b4f058bc85a46c734c81892d2caf3e", "MASTERCARD", "1234"))
            CardManager.addCard(BankCard("4", "UniCredit Bank", "5000000000000004",
                "c98fcaa4e11fc749d19700af104603cec1b4f058bc85a46c734c81892d2caf3e", "MASTERCARD", "1234"))
        }

        setContent {
            var currentScreen by remember { mutableStateOf("wallet") }

            MaterialTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = AppBackground
                ) {
                    val screenOrder = listOf("wallet", "cards", "addCard")
                    AnimatedContent(
                        targetState = currentScreen,
                        transitionSpec = {
                            val forward = screenOrder.indexOf(targetState) > screenOrder.indexOf(initialState)
                            if (forward) {
                                (slideInHorizontally(tween(350)) { it } + fadeIn(tween(350))) togetherWith
                                        (slideOutHorizontally(tween(350)) { -it } + fadeOut(tween(200)))
                            } else {
                                (slideInHorizontally(tween(350)) { -it } + fadeIn(tween(350))) togetherWith
                                        (slideOutHorizontally(tween(350)) { it } + fadeOut(tween(200)))
                            }
                        },
                        label = "screen_transition"
                    ) { screen ->
                        when (screen) {
                            "wallet" -> WalletScreen(
                                onNavigateToCards = { currentScreen = "cards" }
                            )
                            "cards" -> CardsScreen(
                                activity = this@MainActivity,
                                onBack = { currentScreen = "wallet" },
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

@Composable
fun WalletScreen(onNavigateToCards: () -> Unit) {
    val context = LocalContext.current
    val activeCard = CardManager.cards.find { it.isActive }

    Box(modifier = Modifier.fillMaxSize()) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 20.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Spacer(modifier = Modifier.height(16.dp))

            Text(
                text = "Digital Wallet",
                fontFamily = TiemposHeadline,
                fontSize = 38.sp,
                fontWeight = FontWeight.Normal,
                color = PrimaryText,
                textAlign = TextAlign.Center,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 32.dp)
            )

            activeCard?.let { card ->
                Card(
                    shape = RoundedCornerShape(20.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .aspectRatio(1.586f),
                    elevation = CardDefaults.cardElevation(defaultElevation = 6.dp)
                ) {
                    Image(
                        painter = painterResource(id = getCardDrawable(card.bankName)),
                        contentDescription = null,
                        modifier = Modifier.fillMaxSize(),
                        contentScale = ContentScale.FillBounds
                    )
                }

                Spacer(modifier = Modifier.height(18.dp))

                Button(
                    onClick = {
                        Toast.makeText(context, "Informatii card: ${card.bankName}", Toast.LENGTH_SHORT).show()
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = LightButtonBackground),
                    shape = RoundedCornerShape(50.dp),
                    elevation = ButtonDefaults.buttonElevation(
                        defaultElevation = 0.dp,
                        pressedElevation = 0.dp,
                        focusedElevation = 0.dp,
                        hoveredElevation = 0.dp
                    ),
                    contentPadding = PaddingValues(horizontal = 20.dp, vertical = 12.dp)
                ) {
                    Icon(
                        painter = painterResource(id = R.drawable.ic_info),
                        contentDescription = null,
                        tint = SecondaryText,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "Informatii Card",
                        color = SecondaryText,
                        fontFamily = Afacad,
                        fontSize = 16.sp,
                        fontWeight = FontWeight.Medium
                    )
                }
            }

            Spacer(modifier = Modifier.weight(0.6f))

            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(
                    painter = painterResource(id = R.drawable.ic_phone_payment),
                    contentDescription = null,
                    modifier = Modifier.size(56.dp),
                    tint = PrimaryText
                )

                Spacer(modifier = Modifier.height(14.dp))

                Text(
                    text = "Apropie telefonul de terminalul de plată\npentru a iniția tranzacția",
                    fontFamily = TiemposText,
                    fontSize = 15.sp,
                    textAlign = TextAlign.Center,
                    color = SecondaryText,
                    lineHeight = 22.sp
                )
            }

            Spacer(modifier = Modifier.weight(1.4f))
        }

        Button(
            onClick = onNavigateToCards,
            colors = ButtonDefaults.buttonColors(containerColor = DarkButtonBackground),
            shape = RoundedCornerShape(28.dp),
            modifier = Modifier
                .align(Alignment.BottomEnd)
                .padding(end = 20.dp, bottom = 24.dp)
                .height(52.dp),
            contentPadding = PaddingValues(horizontal = 20.dp)
        ) {
            Icon(
                painter = painterResource(id = R.drawable.ic_card_change),
                contentDescription = null,
                tint = Color.White,
                modifier = Modifier.size(20.dp)
            )
            Spacer(modifier = Modifier.width(10.dp))
            Text(
                text = "Selecteaza Card",
                fontFamily = Afacad,
                fontSize = 16.sp,
                fontWeight = FontWeight.Medium,
                color = Color.White
            )
        }
    }
}

@Composable
fun CardsScreen(activity: AppCompatActivity, onBack: () -> Unit, onAddCard: () -> Unit) {
    val cards = CardManager.cards
    val context = LocalContext.current

    BackHandler { onBack() }

    Box(modifier = Modifier.fillMaxSize()) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 20.dp)
        ) {
            Spacer(modifier = Modifier.height(16.dp))

            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth()
            ) {
                IconButton(
                    onClick = onBack,
                    modifier = Modifier.size(40.dp)
                ) {
                    Icon(
                        painter = painterResource(id = R.drawable.ic_back),
                        contentDescription = "Inapoi",
                        tint = PrimaryText,
                        modifier = Modifier.size(24.dp)
                    )
                }

                Text(
                    text = "Carduri",
                    fontFamily = TiemposHeadline,
                    fontSize = 38.sp,
                    fontWeight = FontWeight.Normal,
                    color = PrimaryText,
                    textAlign = TextAlign.Center,
                    modifier = Modifier
                        .weight(1f)
                        .padding(end = 40.dp)
                )
            }

            Spacer(modifier = Modifier.height(20.dp))

            Text(
                text = "Selecteaza cardul dorit",
                fontFamily = TiemposText,
                fontSize = 16.sp,
                color = SecondaryText,
                modifier = Modifier.padding(bottom = 16.dp)
            )

            LazyVerticalGrid(
                columns = GridCells.Fixed(2),
                horizontalArrangement = Arrangement.spacedBy(14.dp),
                verticalArrangement = Arrangement.spacedBy(14.dp),
                modifier = Modifier.weight(1f)
            ) {
                items(cards) { card ->
                    CardItemNew(
                        card = card,
                        isActive = card.isActive,
                        onClick = {
                            BiometricHelper.showBiometricPrompt(
                                activity = activity,
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
            colors = ButtonDefaults.buttonColors(containerColor = DarkButtonBackground),
            shape = RoundedCornerShape(28.dp),
            modifier = Modifier
                .align(Alignment.BottomEnd)
                .padding(end = 20.dp, bottom = 24.dp)
                .height(52.dp),
            contentPadding = PaddingValues(horizontal = 20.dp)
        ) {
            Icon(
                painter = painterResource(id = R.drawable.ic_add_card),
                contentDescription = null,
                tint = Color.White,
                modifier = Modifier.size(20.dp)
            )
            Spacer(modifier = Modifier.width(10.dp))
            Text(
                text = "Adauga Card Nou",
                fontFamily = Afacad,
                fontSize = 16.sp,
                fontWeight = FontWeight.Medium,
                color = Color.White
            )
        }
    }
}

@Composable
fun CardItemNew(card: BankCard, isActive: Boolean, onClick: () -> Unit) {
    val interactionSource = remember { MutableInteractionSource() }
    val isPressed by interactionSource.collectIsPressedAsState()

    val scale by animateFloatAsState(
        targetValue = if (isPressed) 0.95f else 1f,
        animationSpec = spring(
            dampingRatio = Spring.DampingRatioMediumBouncy,
            stiffness = Spring.StiffnessHigh
        ),
        label = "card_scale"
    )

    val bgColor by animateColorAsState(
        targetValue = if (isActive) DarkButtonBackground else CardItemBackground,
        animationSpec = tween(durationMillis = 300),
        label = "card_bg"
    )

    val textColor by animateColorAsState(
        targetValue = if (isActive) Color.White else PrimaryText,
        animationSpec = tween(durationMillis = 300),
        label = "card_text"
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
            shape = RoundedCornerShape(10.dp),
            modifier = Modifier
                .fillMaxWidth()
                .aspectRatio(1.586f),
            elevation = CardDefaults.cardElevation(defaultElevation = 3.dp)
        ) {
            Image(
                painter = painterResource(id = getCardDrawable(card.bankName)),
                contentDescription = null,
                modifier = Modifier.fillMaxSize(),
                contentScale = ContentScale.FillBounds
            )
        }

        Spacer(modifier = Modifier.height(10.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "Card ${getShortBankName(card.bankName)}",
                color = textColor,
                fontFamily = Afacad,
                fontSize = 13.sp,
                fontWeight = FontWeight.Medium,
                maxLines = 1
            )
            Text(
                text = "···· ${card.lastFour}",
                color = textColor,
                fontFamily = Afacad,
                fontSize = 13.sp,
                maxLines = 1
            )
        }
    }
}

fun getShortBankName(bankName: String): String {
    return when {
        bankName.contains("Transilvania", true) -> "BT"
        bankName.contains("ING", true) -> "ING"
        bankName.contains("UniCredit", true) -> "Unicredit"
        bankName.contains("BRD", true) -> "BRD"
        bankName.contains("BCR", true) -> "BCR"
        else -> bankName.split(" ").first()
    }
}

fun getCardDrawable(bankName: String): Int {
    return when {
        bankName.contains("Transilvania", true) -> R.drawable.card_bt
        bankName.contains("ING", true) -> R.drawable.card_ing
        bankName.contains("UniCredit", true) -> R.drawable.card_unicredit
        else -> R.drawable.card_bt
    }
}

// ─────────────────────────────────────────────
// Add Card Screen
// ─────────────────────────────────────────────

@Composable
fun AddCardScreen(onBack: () -> Unit) {
    var panDigits by remember { mutableStateOf("") }
    var expiryRaw by remember { mutableStateOf("") }
    var cvv by remember { mutableStateOf("") }
    var cardholderName by remember { mutableStateOf("") }
    var isLoading by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    val scrollState = rememberScrollState()

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

        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth()
        ) {
            IconButton(onClick = onBack, modifier = Modifier.size(40.dp)) {
                Icon(
                    painter = painterResource(R.drawable.ic_back),
                    contentDescription = "Inapoi",
                    tint = PrimaryText,
                    modifier = Modifier.size(24.dp)
                )
            }
            Text(
                text = "Adauga Card",
                fontFamily = TiemposHeadline,
                fontSize = 38.sp,
                fontWeight = FontWeight.Normal,
                color = PrimaryText,
                textAlign = TextAlign.Center,
                modifier = Modifier
                    .weight(1f)
                    .padding(end = 40.dp)
            )
        }

        Spacer(modifier = Modifier.height(24.dp))

        CardPreviewWidget(
            panDigits = panDigits,
            expiry = expiryDisplay,
            cardholderName = cardholderName
        )

        Spacer(modifier = Modifier.height(28.dp))

        OutlinedTextField(
            value = formattedPanDisplay,
            onValueChange = { newVal ->
                panDigits = newVal.filter { it.isDigit() }.take(16)
            },
            label = { Text("Numar card", fontFamily = Afacad) },
            placeholder = { Text("1234 5678 9012 3456", fontFamily = Afacad) },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number, imeAction = ImeAction.Next),
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
            colors = cardFormColors(),
            textStyle = LocalTextStyle.current.copy(fontFamily = Afacad, letterSpacing = 2.sp)
        )

        Spacer(modifier = Modifier.height(12.dp))

        OutlinedTextField(
            value = cardholderName,
            onValueChange = { cardholderName = it.uppercase().take(26) },
            label = { Text("Titular card", fontFamily = Afacad) },
            placeholder = { Text("PRENUME NUME", fontFamily = Afacad) },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Text, imeAction = ImeAction.Next),
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
            colors = cardFormColors(),
            textStyle = LocalTextStyle.current.copy(fontFamily = Afacad, letterSpacing = 1.sp)
        )

        Spacer(modifier = Modifier.height(12.dp))

        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            OutlinedTextField(
                value = expiryDisplay,
                onValueChange = { newVal ->
                    expiryRaw = newVal.filter { it.isDigit() }.take(4)
                },
                label = { Text("Expirare", fontFamily = Afacad) },
                placeholder = { Text("MM/YY", fontFamily = Afacad) },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number, imeAction = ImeAction.Next),
                singleLine = true,
                modifier = Modifier.weight(1f),
                colors = cardFormColors(),
                textStyle = LocalTextStyle.current.copy(fontFamily = Afacad)
            )
            OutlinedTextField(
                value = cvv,
                onValueChange = { cvv = it.filter { c -> c.isDigit() }.take(4) },
                label = { Text("CVV", fontFamily = Afacad) },
                placeholder = { Text("···", fontFamily = Afacad) },
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number, imeAction = ImeAction.Done),
                singleLine = true,
                modifier = Modifier.weight(1f),
                colors = cardFormColors(),
                textStyle = LocalTextStyle.current.copy(fontFamily = Afacad)
            )
        }

        errorMessage?.let { msg ->
            Spacer(modifier = Modifier.height(12.dp))
            Text(
                text = msg,
                color = Color(0xFFB00020),
                fontFamily = Afacad,
                fontSize = 14.sp
            )
        }

        Spacer(modifier = Modifier.height(32.dp))

        Button(
            onClick = {
                if (panDigits.length < 16) { errorMessage = "Numarul de card este incomplet."; return@Button }
                if (expiryRaw.length < 4) { errorMessage = "Data expirarii este invalida."; return@Button }
                if (cvv.length < 3) { errorMessage = "CVV-ul este invalid."; return@Button }
                errorMessage = null
                isLoading = true
                scope.launch {
                    try {
                        val enrolled = RetrofitClient.instance.enrollCard(
                            EnrollRequest(pan = panDigits, expiryDate = expiryDisplay, cvv = cvv)
                        )
                        CardManager.addCard(enrolled)
                        onBack()
                    } catch (e: Exception) {
                        errorMessage = "Eroare server: ${e.message ?: "Verificati conexiunea."}"
                    } finally {
                        isLoading = false
                    }
                }
            },
            enabled = !isLoading,
            colors = ButtonDefaults.buttonColors(
                containerColor = DarkButtonBackground,
                disabledContainerColor = DarkButtonBackground.copy(alpha = 0.5f)
            ),
            shape = RoundedCornerShape(28.dp),
            modifier = Modifier
                .fillMaxWidth()
                .height(52.dp),
            contentPadding = PaddingValues(horizontal = 20.dp)
        ) {
            if (isLoading) {
                CircularProgressIndicator(
                    color = Color.White,
                    modifier = Modifier.size(20.dp),
                    strokeWidth = 2.dp
                )
            } else {
                Icon(
                    painter = painterResource(R.drawable.ic_add_card),
                    contentDescription = null,
                    tint = Color.White,
                    modifier = Modifier.size(20.dp)
                )
                Spacer(modifier = Modifier.width(10.dp))
                Text(
                    text = "Adauga Card",
                    fontFamily = Afacad,
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Medium,
                    color = Color.White
                )
            }
        }

        Spacer(modifier = Modifier.height(32.dp))
    }
}

@Composable
fun cardFormColors() = OutlinedTextFieldDefaults.colors(
    focusedBorderColor = PrimaryText,
    unfocusedBorderColor = SecondaryText.copy(alpha = 0.35f),
    focusedLabelColor = PrimaryText,
    unfocusedLabelColor = SecondaryText,
    cursorColor = PrimaryText,
    focusedTextColor = PrimaryText,
    unfocusedTextColor = PrimaryText,
    focusedContainerColor = Color.Transparent,
    unfocusedContainerColor = Color.Transparent
)

@Composable
fun CardPreviewWidget(panDigits: String, expiry: String, cardholderName: String) {
    val prefix2 = panDigits.take(2).toIntOrNull() ?: 0
    val cardType = when {
        panDigits.startsWith("4") -> "VISA"
        prefix2 in 51..55 -> "MASTERCARD"
        else -> null
    }

    val cardColorStart by animateColorAsState(
        targetValue = when {
            panDigits.startsWith("4") -> Color(0xFF1565C0)
            prefix2 in 51..55 -> Color(0xFF212121)
            else -> Color(0xFF374151)
        },
        animationSpec = tween(600),
        label = "card_color_start"
    )
    val cardColorEnd by animateColorAsState(
        targetValue = when {
            panDigits.startsWith("4") -> Color(0xFF0D47A1)
            prefix2 in 51..55 -> Color(0xFF424242)
            else -> Color(0xFF1F2937)
        },
        animationSpec = tween(600),
        label = "card_color_end"
    )

    val displayPan = buildString {
        for (i in 0..15) {
            if (i > 0 && i % 4 == 0) append(' ')
            val ch = panDigits.getOrNull(i)
            append(ch ?: '·')
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
                text = it,
                color = Color.White,
                fontFamily = Afacad,
                fontSize = 15.sp,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.align(Alignment.TopEnd)
            )
        }

        Text(
            text = displayPan,
            color = Color.White,
            fontFamily = Afacad,
            fontSize = 19.sp,
            letterSpacing = 2.sp,
            modifier = Modifier.align(Alignment.Center)
        )

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .align(Alignment.BottomCenter),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.Bottom
        ) {
            Column {
                Text(
                    text = "TITULAR",
                    color = Color.White.copy(alpha = 0.6f),
                    fontFamily = Afacad,
                    fontSize = 9.sp
                )
                Text(
                    text = cardholderName.ifEmpty { "TITULAR" }.take(22),
                    color = Color.White,
                    fontFamily = Afacad,
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Medium
                )
            }
            Column(horizontalAlignment = Alignment.End) {
                Text(
                    text = "EXPIRA",
                    color = Color.White.copy(alpha = 0.6f),
                    fontFamily = Afacad,
                    fontSize = 9.sp
                )
                Text(
                    text = expiry.ifEmpty { "MM/YY" },
                    color = Color.White,
                    fontFamily = Afacad,
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Medium
                )
            }
        }
    }
}
