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