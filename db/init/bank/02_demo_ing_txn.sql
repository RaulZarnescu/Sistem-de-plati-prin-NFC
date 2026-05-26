-- ============================================================
-- 02_demo_ing_txn.sql — Tranzacții istorice demo pentru bank_ing
--
-- NOTĂ TEHNICĂ: Docker execută automat fișierele .sql din
-- docker-entrypoint-initdb.d ca postgres user pe baza de date postgres.
-- \connect bank_ing redirecționează execuția la baza de date corectă.
\connect bank_ing
--
-- Aplicat de 02_demo_transactions.sh DOAR pe baza de date bank_ing.
-- Conține scenariul 3 de demo:
--   SC3 — Amount Deviation / Anomalie sumă (PAN: 5200828282828210)
--
-- ⚠️  IMPORTANT PENTRU PREZENTARE:
-- Aceste tranzacții din DB sunt context vizual (pgAdmin, dashboard).
-- Amount Deviation din Fraud Engine se bazează pe Redis List (amounts:PAN).
-- Pentru a DECLANȘA live, trimiteți mai întâi 6 tranzacții normale
-- (30-90 RON), apoi tranzacția de 4500 RON (vezi docs/DEMO_SCENARIOS.md SC3).
--
-- Formula: media istorică ≈ 4417 cenți
-- Tranzacția de 450000 cenți = ~101x media → N2 sigmoid ≈ 0.98
-- Amount contribution ≈ 40 × 0.98 ≈ 39.2 puncte → Step-Up
-- ============================================================

-- ──────────────────────────────────────────────────────────
-- SCENARIUL 3 — Amount Deviation (anomalie sumă)
-- PAN: 5200828282828210 (ING, Luhn-valid)
-- Istoric normal pe 20 zile (30-90 RON), apoi anomalie 4500 RON
--
-- SCENARIUL 3: Amount deviation — media istorică ~4417 cenți
-- Tranzacția de 450000 cenți (4500 RON) = ~100x media
-- N2 sigmoid ≈ 0.98 → amount_contribution ≈ 39 puncte → Step-Up
-- ──────────────────────────────────────────────────────────

INSERT INTO transactions
    (transaction_id, pan, amount, currency, status, risk_score, terminal_id, bank, created_at)
VALUES
    -- Ziua -20: Cumpărături Lidl — 32 RON (comportament normal)
    ('TXN-DEMO-SC3-01', '5200828282828210',   3200, 'RON', 'APPROVED', 0,
     'POS-LIDL-001', 'ING', NOW() - INTERVAL '20 days'),

    -- Ziua -18: Cumpărături Lidl — 41 RON (normal)
    ('TXN-DEMO-SC3-02', '5200828282828210',   4100, 'RON', 'APPROVED', 2,
     'POS-LIDL-001', 'ING', NOW() - INTERVAL '18 days'),

    -- Ziua -15: Taxi București — 28 RON (normal)
    ('TXN-DEMO-SC3-03', '5200828282828210',   2800, 'RON', 'APPROVED', 0,
     'POS-TAXI-BUC-001', 'ING', NOW() - INTERVAL '15 days'),

    -- Ziua -12: Restaurant — 89 RON (normal, suma mai mare dar consistentă)
    ('TXN-DEMO-SC3-04', '5200828282828210',   8900, 'RON', 'APPROVED', 3,
     'POS-RESTAURANT-001', 'ING', NOW() - INTERVAL '12 days'),

    -- Ziua -8: Supermarket — 56 RON (normal)
    ('TXN-DEMO-SC3-05', '5200828282828210',   5600, 'RON', 'APPROVED', 1,
     'POS-SUPERMARKET-001', 'ING', NOW() - INTERVAL '8 days'),

    -- Ziua -5: Farmacie — 19 RON (normal, suma mică)
    ('TXN-DEMO-SC3-06', '5200828282828210',   1900, 'RON', 'APPROVED', 0,
     'POS-FARMACIE-001', 'ING', NOW() - INTERVAL '5 days'),

    -- Ziua -2: Electronice — 4500 RON = ~101x media istorică!
    -- Fraud Engine: N2=0.98 → amount_contribution≈39 → CHALLENGE_REQUIRED
    ('TXN-DEMO-SC3-07', '5200828282828210', 450000, 'RON', 'CHALLENGE_REQUIRED', 58,
     'POS-ELECTRONICE-001', 'ING', NOW() - INTERVAL '2 days')

ON CONFLICT (transaction_id) DO NOTHING;
