package com.example.sistemplatanfc.data

import androidx.compose.runtime.mutableStateListOf
import com.example.sistemplatanfc.model.BankCard

/**
 * Singleton care gestionează cardurile înrolate în aplicație.
 * Folosește mutableStateListOf pentru ca UI-ul Compose să reacționeze automat la schimbări.
 */
object CardManager {
    private val _cards = mutableStateListOf<BankCard>()
    val cards: List<BankCard> get() = _cards

    fun addCard(card: BankCard) {
        if (_cards.isEmpty()) card.isActive = true
        _cards.add(card)
    }

    fun getActiveCard(): BankCard? {
        return _cards.find { it.isActive }
    }

    fun setActiveCard(cardId: String) {
        for (i in _cards.indices) {
            val card = _cards[i]
            _cards[i] = card.copy(isActive = (card.id == cardId))
        }
    }
}
