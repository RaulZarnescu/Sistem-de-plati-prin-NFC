package com.example.sistemplatanfc

import android.os.Bundle
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
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
import com.example.sistemplatanfc.data.CardManager
import com.example.sistemplatanfc.model.BankCard
import com.example.sistemplatanfc.utils.BiometricHelper

// Culori conform specificațiilor
val AppBackground = Color(0xFFE9E7E0)
val PrimaryText = Color(0xFF000000)
val SecondaryText = Color(0xFF373434)
val CardItemBackground = Color(0xFFDFD0BF).copy(alpha = 0.57f)
val DarkButtonBackground = Color(0xFF373434)
val LightButtonBackground = Color(0xFFFFFFFF)

// Fonturi personalizate
val TiemposHeadline = FontFamily(
    Font(R.font.tiempos_headline_bold, FontWeight.Bold)
)
val TiemposText = FontFamily(
    Font(R.font.tiempos_text_regular, FontWeight.Normal)
)
val Afacad = FontFamily(
    Font(R.font.afacad_regular, FontWeight.Normal)
)

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Simulare date dacă lista este goală
        if (CardManager.cards.isEmpty()) {
            CardManager.addCard(BankCard("1", "Banca Transilvania", "4000000000000001",
                "6f8d2b9a1c4e7f3d5b0e8a4c2f1d9e7b5a3c8f0d4e2b1a9c7f6d5e4b3a2c1f0e", "VISA", "1234", true))
            CardManager.addCard(BankCard("2", "BCR", "5000000000000002",
                "c98fcaa4e11fc749d19700af104603cec1b4f058bc85a46c734c81892d2caf3e", "MASTERCARD", "5142"))
            CardManager.addCard(BankCard("3", "ING Bank", "5000000000000003",
                "c98fcaa4e11fc749d19700af104603cec1b4f058bc85a46c734c81892d2caf3e", "MASTERCARD", "1234"))
            CardManager.addCard(BankCard("4", "UniCredit Bank", "5000000000000004",
                "c98fcaa4e11fc749d19700af104603cec1b4f058bc85a46c734c81892d2caf3e", "MASTERCARD", "1234"))
        }

        setContent {
            var currentScreen by remember { mutableStateOf("wallet") }
            
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize(), color = AppBackground) {
                    when (currentScreen) {
                        "wallet" -> WalletScreen(
                            activity = this,
                            onNavigateToCards = { currentScreen = "cards" }
                        )
                        "cards" -> CardsScreen(
                            activity = this,
                            onBack = { currentScreen = "wallet" }
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun WalletScreen(activity: AppCompatActivity, onNavigateToCards: () -> Unit) {
    val context = LocalContext.current
    val activeCard = CardManager.cards.find { it.isActive }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Spacer(modifier = Modifier.height(40.dp))
        
        Text(
            text = "Digital Wallet",
            fontFamily = TiemposHeadline,
            fontSize = 42.sp, // Ajustat pentru a se potrivi
            color = PrimaryText,
            modifier = Modifier.padding(bottom = 32.dp)
        )

        activeCard?.let { card ->
            Card(
                shape = RoundedCornerShape(24.dp),
                modifier = Modifier
                    .fillMaxWidth(0.9f)
                    .aspectRatio(1.586f),
                elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
            ) {
                Box {
                    Image(
                        painter = painterResource(id = getCardDrawable(card.bankName)),
                        contentDescription = null,
                        modifier = Modifier.fillMaxSize(),
                        contentScale = ContentScale.FillBounds
                    )
                }
            }
            
            Spacer(modifier = Modifier.height(24.dp))
            
            Button(
                onClick = { Toast.makeText(context, "Informații card: ${card.bankName}", Toast.LENGTH_SHORT).show() },
                colors = ButtonDefaults.buttonColors(containerColor = LightButtonBackground),
                shape = RoundedCornerShape(20.dp),
                elevation = ButtonDefaults.buttonElevation(defaultElevation = 2.dp)
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        painter = painterResource(id = R.drawable.ic_info),
                        contentDescription = null,
                        tint = SecondaryText,
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "Informatii Card",
                        color = SecondaryText,
                        fontFamily = Afacad,
                        fontSize = 16.sp
                    )
                }
            }
        }

        Spacer(modifier = Modifier.weight(1f))

        Image(
            painter = painterResource(id = R.drawable.ic_phone_payment),
            contentDescription = null,
            modifier = Modifier.size(100.dp)
        )

        Spacer(modifier = Modifier.height(24.dp))

        Text(
            text = "Apropie telefonul de terminalul de plată pentru a iniția tranzacția",
            fontFamily = TiemposText,
            fontSize = 18.sp,
            textAlign = TextAlign.Center,
            color = SecondaryText,
            modifier = Modifier.padding(horizontal = 24.dp)
        )

        Spacer(modifier = Modifier.weight(1.2f))

        Box(modifier = Modifier.fillMaxWidth().padding(bottom = 16.dp), contentAlignment = Alignment.BottomEnd) {
            Button(
                onClick = onNavigateToCards,
                colors = ButtonDefaults.buttonColors(containerColor = DarkButtonBackground),
                shape = RoundedCornerShape(24.dp),
                modifier = Modifier.height(56.dp)
            ) {
                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(horizontal = 8.dp)) {
                    Icon(
                        painter = painterResource(id = R.drawable.ic_card_change),
                        contentDescription = null,
                        tint = Color.White
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "Selecteaza Card",
                        fontFamily = Afacad,
                        fontSize = 16.sp,
                        color = Color.White
                    )
                }
            }
        }
    }
}

@Composable
fun CardsScreen(activity: AppCompatActivity, onBack: () -> Unit) {
    val cards = CardManager.cards
    val context = LocalContext.current

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        Spacer(modifier = Modifier.height(40.dp))
        
        Text(
            text = "Carduri",
            fontFamily = TiemposHeadline,
            fontSize = 42.sp,
            color = PrimaryText,
            modifier = Modifier.align(Alignment.CenterHorizontally)
        )

        Spacer(modifier = Modifier.height(32.dp))

        Text(
            text = "Selecteaza cardul dorit",
            fontFamily = TiemposText,
            fontSize = 18.sp,
            color = SecondaryText,
            modifier = Modifier.padding(bottom = 16.dp)
        )

        LazyVerticalGrid(
            columns = GridCells.Fixed(2),
            horizontalArrangement = Arrangement.spacedBy(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
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

        Box(modifier = Modifier.fillMaxWidth().padding(bottom = 16.dp), contentAlignment = Alignment.BottomEnd) {
            Button(
                onClick = { Toast.makeText(context, "Meniu Adăugare Card (În curând)", Toast.LENGTH_SHORT).show() },
                colors = ButtonDefaults.buttonColors(containerColor = DarkButtonBackground),
                shape = RoundedCornerShape(24.dp),
                modifier = Modifier.height(56.dp)
            ) {
                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(horizontal = 8.dp)) {
                    Icon(
                        painter = painterResource(id = R.drawable.ic_add_card),
                        contentDescription = null,
                        tint = Color.White
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "Adauga Card Nou",
                        fontFamily = Afacad,
                        fontSize = 16.sp,
                        color = Color.White
                    )
                }
            }
        }
    }
}

@Composable
fun CardItemNew(card: BankCard, isActive: Boolean, onClick: () -> Unit) {
    Column(
        modifier = Modifier
            .background(
                color = if (isActive) DarkButtonBackground else CardItemBackground,
                shape = RoundedCornerShape(12.dp)
            )
            .clickable { onClick() }
            .padding(8.dp)
    ) {
        Card(
            shape = RoundedCornerShape(8.dp),
            modifier = Modifier
                .fillMaxWidth()
                .aspectRatio(1.586f),
            elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
        ) {
            Image(
                painter = painterResource(id = getCardDrawable(card.bankName)),
                contentDescription = null,
                modifier = Modifier.fillMaxSize(),
                contentScale = ContentScale.FillBounds
            )
        }
        
        Spacer(modifier = Modifier.height(8.dp))
        
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "Card ${card.bankName.split(" ").first()}",
                color = if (isActive) Color.White else PrimaryText,
                fontFamily = Afacad,
                fontSize = 13.sp,
                maxLines = 1
            )
            Text(
                text = ".... ${card.lastFour}",
                color = if (isActive) Color.White else PrimaryText,
                fontFamily = Afacad,
                fontSize = 13.sp,
                maxLines = 1
            )
        }
    }
}

fun getCardDrawable(bankName: String): Int {
    return when {
        bankName.contains("Transilvania", true) -> R.drawable.card_bt
        bankName.contains("ING", true) -> R.drawable.card_ing
        bankName.contains("UniCredit", true) -> R.drawable.card_unicredit
        else -> R.drawable.card_bt // Fallback
    }
}
