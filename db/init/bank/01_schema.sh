#!/bin/bash
set -e

BASE="/docker-entrypoint-initdb.d"

# --- Schema + conturi seed (aplicat la toate 3 bănci) ---
for DB in "bank_bt" "bank_bcr" "bank_ing"; do
    echo "Applying schema to $DB..."
    psql -v ON_ERROR_STOP=1 --username "$DB" --dbname "$DB" \
        < "${BASE}/01_schema.sql.template"
done

# --- Tranzacții istorice demo (per bancă) ---
# Aceste fișiere sunt executate și direct de Docker ca .sql (cu \connect),
# dar le aplicăm explicit și aici pentru a garanta ordinea corectă.
echo "Applying BT demo transactions (SC1 + SC4)..."
psql -v ON_ERROR_STOP=1 --username "bank_bt" --dbname "bank_bt" \
    < "${BASE}/02_demo_bt_txn.sql"

echo "Applying BCR demo transactions (SC2 Velocity)..."
psql -v ON_ERROR_STOP=1 --username "bank_bcr" --dbname "bank_bcr" \
    < "${BASE}/02_demo_bcr_txn.sql"

echo "Applying ING demo transactions (SC3 Amount Deviation)..."
psql -v ON_ERROR_STOP=1 --username "bank_ing" --dbname "bank_ing" \
    < "${BASE}/02_demo_ing_txn.sql"

echo "=== Schema + seed complet pe toate 3 bănci ==="
