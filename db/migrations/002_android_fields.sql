-- ============================================================
-- Migrare 002: Câmpuri Android (exp_month, exp_year, cvv_hash)
-- Aplicabilă pe: bank_bt, bank_bcr, bank_ing
--
-- Idempotentă — ADD COLUMN IF NOT EXISTS nu eșuează dacă
-- coloanele există deja.
--
-- Aplică via apply_002.sh sau manual:
--   docker exec nfc-postgres-bank psql -U bank_bt -d bank_bt -f /tmp/002.sql
-- ============================================================

-- 1. Adaugă coloanele noi (idempotent)
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS exp_month VARCHAR(2)  DEFAULT '12';
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS exp_year  VARCHAR(4)  DEFAULT '28';
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS cvv_hash  VARCHAR(64);

-- 2. Actualizează seed data cu exp_month, exp_year și cvv_hash corecte
--    cvv_hash = SHA256(pan || '123')  — CVV de test: 123 pentru toate
--    PCI-DSS: CVV NICIODATĂ stocat plain text

UPDATE accounts SET
    exp_month = '12',
    exp_year  = '28',
    cvv_hash  = '30bc5c317cc09eda99bc6c0333feaeb7f7aa2f13d35172d66fde4ee589de6d54'
WHERE pan = '4000001111111111';

UPDATE accounts SET
    exp_month = '10',
    exp_year  = '27',
    cvv_hash  = '83f8a3cef153030b926e5f96b0b20cb60a4783bc72473c3926ec3fb9c1c29522'
WHERE pan = '5000002222222222';

UPDATE accounts SET
    exp_month = '06',
    exp_year  = '29',
    cvv_hash  = '13e7e32081bd408620a7ccfcb45521ac5c7049bc08954c3812ee23ab201b3469'
WHERE pan = '5111113333333333';

UPDATE accounts SET
    exp_month = '12',
    exp_year  = '28',
    cvv_hash  = 'a322ea28be32888af1341a48f1076124c50fb792eaf56042311d01d847da5ba9'
WHERE pan = '4222222222222222';
