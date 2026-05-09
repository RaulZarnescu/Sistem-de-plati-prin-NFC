package com.example.sistemplatanfc

import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.sistemplatanfc.data.CardManager
import com.example.sistemplatanfc.model.BankCard

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        if (CardManager.cards.isEmpty()) {
            CardManager.addCard(BankCard("1", "Banca Transilvania", "4111********1234", "key_bt", "VISA", "1234"))
            CardManager.addCard(BankCard("2", "BCR", "5222********5678", "key_bcr", "MASTERCARD", "5678"))
            CardManager.addCard(BankCard("3", "ING Bank", "4912********9012", "key_ing", "VISA", "9012"))
        }

        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    WalletScreen()
                }
            }
        }
    }
}

@Composable
fun WalletScreen() {
    val cards = CardManager.cards
    val activeCard = cards.find { it.isActive }
    val context = LocalContext.current

    Scaffold(
        floatingActionButton = {
            FloatingActionButton(
                onClick = { 
                    Toast.makeText(context, "Meniu Adăugare Card (În curând)", Toast.LENGTH_SHORT).show()
                },
                containerColor = MaterialTheme.colorScheme.primary
            ) {
                Icon(Icons.Default.Add, contentDescription = "Adaugă Card")
            }
        }
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(text = "Portofel Digital NFC", fontSize = 24.sp, fontWeight = FontWeight.Bold, modifier = Modifier.padding(bottom = 24.dp))

            Text(text = "Selectează cardul pentru plată:", fontSize = 16.sp, modifier = Modifier.align(Alignment.Start).padding(bottom = 8.dp))

            LazyColumn(verticalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.weight(1f)) {
                items(cards, key = { it.id }) { card ->
                    CardItem(
                        card = card,
                        isSelected = card.isActive,
                        onSelect = {
                            CardManager.setActiveCard(card.id)
                        }
                    )
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            if (activeCard != null) {
                Card(colors = CardDefaults.cardColors(containerColor = Color(0xFFE8F5E9)), modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text(text = "Card Activ: ${activeCard.bankName}", fontWeight = FontWeight.Bold, color = Color(0xFF2E7D32))
                        Text(text = "Apropie telefonul de POS pentru a plăti", fontSize = 14.sp)
                    }
                }
            }
        }
    }
}

@Composable
fun CardItem(card: BankCard, isSelected: Boolean, onSelect: () -> Unit) {
    Card(
        shape = RoundedCornerShape(12.dp),
        elevation = CardDefaults.cardElevation(defaultElevation = if (isSelected) 8.dp else 2.dp),
        modifier = Modifier.fillMaxWidth().height(100.dp).clickable { onSelect() },
        colors = CardDefaults.cardColors(containerColor = if (isSelected) Color(0xFFBBDEFB) else Color.White)
    ) {
        Row(modifier = Modifier.padding(16.dp).fillMaxSize(), verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f)) {
                Text(text = card.bankName, fontWeight = FontWeight.Bold, fontSize = 18.sp)
                Text(text = "${card.cardType} **** ${card.lastFour}", fontSize = 14.sp, color = Color.Gray)
            }
            RadioButton(selected = isSelected, onClick = null)
        }
    }
}
