-- ============================================================
-- 02_demo_bt_txn.sql — Tranzacții istorice demo pentru bank_bt
--
-- NOTĂ TEHNICĂ: Docker execută automat fișierele .sql din
-- docker-entrypoint-initdb.d ca postgres user pe baza de date postgres.
-- \connect bank_bt redirecționează execuția la baza de date corectă.
\connect bank_bt
--
-- Aplicat de 02_demo_transactions.sh DOAR pe baza de date bank_bt.
-- Conține 2 scenarii de demo:
--   SC1 — Happy Path Normal (PAN: 4000001111111118)
--   SC4 — Sold Insuficient  (PAN: 4000002222222224)
--
-- Tranzacțiile sunt inserate direct — NU declanșează deducerea
-- soldului (aceasta se face prin fluxul real de autorizare).
-- Soldul semințelor reflectă starea curentă după tranzacțiile istorice.
--
-- ON CONFLICT DO NOTHING — idempotent, sigur la re-aplicare.
-- ============================================================

-- ──────────────────────────────────────────────────────────
-- SCENARIUL 1 — Happy Path Normal
-- PAN: 4000001111111118 (BT, Luhn-valid)
-- 10 tranzacții APPROVED distribuite pe 30 zile
-- Comercianți reali București — pentru demo realist
-- ──────────────────────────────────────────────────────────

INSERT INTO transactions
    (transaction_id, pan, amount, currency, status, risk_score, terminal_id, bank, created_at)
VALUES
    -- Ziua -30: Cumpărături Kaufland
    ('TXN-DEMO-SC1-01', '4000001111111118',  8750, 'RON', 'APPROVED',  0,
     'POS-KAUFLAND-BUC-001', 'BT', NOW() - INTERVAL '30 days'),

    -- Ziua -27: Alimentare combustibil OMV Pipera
    ('TXN-DEMO-SC1-02', '4000001111111118', 32000, 'RON', 'APPROVED',  5,
     'POS-OMV-PIPERA-001', 'BT', NOW() - INTERVAL '27 days'),

    -- Ziua -24: Fast food McDonald's
    ('TXN-DEMO-SC1-03', '4000001111111118',  4500, 'RON', 'APPROVED',  0,
     'POS-MCDONALDS-BUC-001', 'BT', NOW() - INTERVAL '24 days'),

    -- Ziua -21: Cafea Starbucks
    ('TXN-DEMO-SC1-04', '4000001111111118',  2800, 'RON', 'APPROVED',  3,
     'POS-STARBUCKS-001', 'BT', NOW() - INTERVAL '21 days'),

    -- Ziua -18: Supermarket Mega Image
    ('TXN-DEMO-SC1-05', '4000001111111118', 15600, 'RON', 'APPROVED',  8,
     'POS-MEGA-IMAGE-001', 'BT', NOW() - INTERVAL '18 days'),

    -- Ziua -14: Hypermarket Carrefour
    ('TXN-DEMO-SC1-06', '4000001111111118', 23400, 'RON', 'APPROVED',  5,
     'POS-CARREFOUR-001', 'BT', NOW() - INTERVAL '14 days'),

    -- Ziua -10: Supermarket Penny
    ('TXN-DEMO-SC1-07', '4000001111111118',  9800, 'RON', 'APPROVED',  2,
     'POS-PENNY-001', 'BT', NOW() - INTERVAL '10 days'),

    -- Ziua -7: Supermarket Profi
    ('TXN-DEMO-SC1-08', '4000001111111118',  6700, 'RON', 'APPROVED',  0,
     'POS-PROFI-001', 'BT', NOW() - INTERVAL '7 days'),

    -- Ziua -4: Îmbrăcăminte H&M (sumă mai mare — risk ușor crescut)
    ('TXN-DEMO-SC1-09', '4000001111111118', 18900, 'RON', 'APPROVED',  7,
     'POS-H-AND-M-001', 'BT', NOW() - INTERVAL '4 days'),

    -- Ziua -2: IKEA — tranzacție mare, risk 12 (sub pragul step-up=40)
    ('TXN-DEMO-SC1-10', '4000001111111118', 45600, 'RON', 'APPROVED', 12,
     'POS-IKEA-001', 'BT', NOW() - INTERVAL '2 days')

ON CONFLICT (transaction_id) DO NOTHING;


-- ──────────────────────────────────────────────────────────
-- SCENARIUL 4 — Sold Insuficient
-- PAN: 4000002222222224 (BT, Luhn-valid, sold: 5000 = 50 RON)
-- 3 tentative DECLINED — toate depășesc soldul disponibil
--
-- SCENARIUL 4: Sold insuficient — cont cu 50 RON
-- Toate tranzacțiile refuzate cu INSUFFICIENT_FUNDS
-- ──────────────────────────────────────────────────────────

INSERT INTO transactions
    (transaction_id, pan, amount, currency, status, risk_score, terminal_id, bank, created_at)
VALUES
    -- Tentativă retragere ATM 100 RON — refuzată
    ('TXN-DEMO-SC4-01', '4000002222222224', 10000, 'RON', 'DECLINED', 0,
     'POS-ATM-001', 'BT', NOW() - INTERVAL '3 days'),

    -- Tentativă plată Kaufland 75 RON — refuzată
    ('TXN-DEMO-SC4-02', '4000002222222224',  7500, 'RON', 'DECLINED', 0,
     'POS-KAUFLAND-001', 'BT', NOW() - INTERVAL '2 days'),

    -- Tentativă combustibil OMV 55 RON — refuzată
    ('TXN-DEMO-SC4-03', '4000002222222224',  5500, 'RON', 'DECLINED', 0,
     'POS-OMV-001', 'BT', NOW() - INTERVAL '1 day')

ON CONFLICT (transaction_id) DO NOTHING;
