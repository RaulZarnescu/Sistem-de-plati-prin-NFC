CREATE TABLE IF NOT EXISTS tokens (
    dpan        VARCHAR(32)  PRIMARY KEY,
    pan         VARCHAR(19)  NOT NULL,
    exp_month   VARCHAR(2)   NOT NULL,
    exp_year    VARCHAR(4)   NOT NULL,
    risk_level  INTEGER      NOT NULL DEFAULT 0
);

-- Seed data — înlocuiește TOKEN_VAULT din cod
INSERT INTO tokens (dpan, pan, exp_month, exp_year, risk_level) VALUES
    ('4000000000000001', '4000001111111111', '12', '28', 0),    -- BT
    ('5000000000000002', '5000002222222222', '10', '27', 0),    -- BCR
    ('5000000000000003', '5111113333333333', '06', '29', 0),    -- ING Bank (PAN nou 511111...)
    ('TEST-STEP-UP-001', '4222222222222222', '12', '28', 55),
    ('TEST-DECLINE-001', '4444444444444444', '12', '28', 90)
ON CONFLICT (dpan) DO NOTHING;

INSERT INTO tokens (dpan, pan, exp_month, exp_year, risk_level) VALUES
    ('TEST-STEP-UP-BT', '4000001111111111', '12', '28', 55)
ON CONFLICT (dpan) DO NOTHING;

-- TASK 3: Token status și device binding
ALTER TABLE tokens ADD COLUMN IF NOT EXISTS
    status VARCHAR(10) NOT NULL DEFAULT 'ACTIVE';
ALTER TABLE tokens ADD COLUMN IF NOT EXISTS
    device_id VARCHAR(64);
ALTER TABLE tokens ADD COLUMN IF NOT EXISTS
    enrolled_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE INDEX IF NOT EXISTS idx_tokens_status ON tokens(status);
CREATE INDEX IF NOT EXISTS idx_tokens_pan ON tokens(pan);

-- TC-13 seed — card expirat pentru testul de expirare (exp_year='20' = 2020)
INSERT INTO tokens (dpan, pan, exp_month, exp_year, risk_level) VALUES
    ('TEST-EXPIRED-001', '4000009999999999', '01', '20', 0)
ON CONFLICT (dpan) DO NOTHING;

-- TASK 7: Audit trail enrollments
CREATE TABLE IF NOT EXISTS enrollments (
    id          SERIAL          PRIMARY KEY,
    dpan        VARCHAR(32)     NOT NULL,
    pan_masked  VARCHAR(19)     NOT NULL,
    device_id   VARCHAR(64),
    bank_id     VARCHAR(10)     NOT NULL,
    enrolled_at TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    status      VARCHAR(10)     NOT NULL DEFAULT 'ACTIVE',
    ip_address  VARCHAR(45),
    CONSTRAINT fk_dpan FOREIGN KEY (dpan)
        REFERENCES tokens(dpan) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_enrollments_dpan
    ON enrollments(dpan);
CREATE INDEX IF NOT EXISTS idx_enrollments_enrolled_at
    ON enrollments(enrolled_at DESC);