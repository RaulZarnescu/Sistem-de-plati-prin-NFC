-- ============================================================
-- 02_demo_bcr_txn.sql — Tranzacții istorice demo pentru bank_bcr
--
-- NOTĂ TEHNICĂ: Docker execută automat fișierele .sql din
-- docker-entrypoint-initdb.d ca postgres user pe baza de date postgres.
-- \connect bank_bcr redirecționează execuția la baza de date corectă.
\connect bank_bcr
--
-- Aplicat de 02_demo_transactions.sh DOAR pe baza de date bank_bcr.
-- Conține scenariul 2 de demo:
--   SC2 — Velocity Fraud Detection (PAN: 5105105105105100)
--
-- ⚠️  IMPORTANT PENTRU PREZENTARE:
-- Aceste tranzacții din DB sunt context vizual (pgAdmin, dashboard).
-- Fraud Engine-ul din Redis NU e pre-populat de seed data —
-- pentru a DECLANȘA live fraud detection, trimiteți 6+ request-uri
-- în fereastra de 10 minute (vezi docs/DEMO_SCENARIOS.md SC2).
-- ============================================================

-- ──────────────────────────────────────────────────────────
-- SCENARIUL 2 — Velocity Fraud Detection
-- PAN: 5105105105105100 (BCR, Luhn-valid)
-- 8 tranzacții la interval de 2 minute — acum 5 zile
-- Risk score escaladează: 0 → 6 → 12 → 45 → 57 → 78 → 85 → 91
--
-- SCENARIUL 2: Velocity fraud — risk score escaladează
-- de la 0 la 91 în 14 minute din cauza frecvenței ridicate
-- ──────────────────────────────────────────────────────────

INSERT INTO transactions
    (transaction_id, pan, amount, currency, status, risk_score, terminal_id, bank, created_at)
VALUES
    -- T+0min: Prima tranzacție — APPROVED (fără istoric velocity)
    ('TXN-DEMO-SC2-01', '5105105105105100', 5000, 'RON', 'APPROVED',  0,
     'POS-ONLINE-SHOP-001', 'BCR',
     NOW() - INTERVAL '5 days'),

    -- T+2min: A doua — APPROVED (velocity ușor crescut)
    ('TXN-DEMO-SC2-02', '5105105105105100', 5000, 'RON', 'APPROVED',  6,
     'POS-ONLINE-SHOP-002', 'BCR',
     NOW() - INTERVAL '5 days' + INTERVAL '2 minutes'),

    -- T+4min: A treia — APPROVED (velocity crescând)
    ('TXN-DEMO-SC2-03', '5105105105105100', 5000, 'RON', 'APPROVED', 12,
     'POS-ONLINE-SHOP-003', 'BCR',
     NOW() - INTERVAL '5 days' + INTERVAL '4 minutes'),

    -- T+6min: A patra — CHALLENGE_REQUIRED (risk >= 40)
    ('TXN-DEMO-SC2-04', '5105105105105100', 5000, 'RON', 'CHALLENGE_REQUIRED', 45,
     'POS-ONLINE-SHOP-004', 'BCR',
     NOW() - INTERVAL '5 days' + INTERVAL '6 minutes'),

    -- T+8min: A cincea — CHALLENGE_REQUIRED (risk 57)
    ('TXN-DEMO-SC2-05', '5105105105105100', 5000, 'RON', 'CHALLENGE_REQUIRED', 57,
     'POS-ONLINE-SHOP-005', 'BCR',
     NOW() - INTERVAL '5 days' + INTERVAL '8 minutes'),

    -- T+10min: A șasea — DECLINED (risk >= 75)
    ('TXN-DEMO-SC2-06', '5105105105105100', 5000, 'RON', 'DECLINED', 78,
     'POS-ONLINE-SHOP-006', 'BCR',
     NOW() - INTERVAL '5 days' + INTERVAL '10 minutes'),

    -- T+12min: A șaptea — DECLINED (risk 85)
    ('TXN-DEMO-SC2-07', '5105105105105100', 5000, 'RON', 'DECLINED', 85,
     'POS-ONLINE-SHOP-007', 'BCR',
     NOW() - INTERVAL '5 days' + INTERVAL '12 minutes'),

    -- T+14min: A opta — DECLINED (risk maxim 91)
    ('TXN-DEMO-SC2-08', '5105105105105100', 5000, 'RON', 'DECLINED', 91,
     'POS-ONLINE-SHOP-008', 'BCR',
     NOW() - INTERVAL '5 days' + INTERVAL '14 minutes')

ON CONFLICT (transaction_id) DO NOTHING;
