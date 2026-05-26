#!/bin/bash
# ============================================================
# apply_002.sh — Aplică migrarea 002 pe toate băncile
#
# Rulează dacă ai deja volume PostgreSQL existente
# (docker-entrypoint-initdb.d nu mai rulează pe volume existente).
#
# Utilizare:
#   chmod +x db/migrations/apply_002.sh
#   ./db/migrations/apply_002.sh
# ============================================================

set -e

MIGRATION="$(dirname "$0")/002_android_fields.sql"
CONTAINER="nfc-postgres-bank"

echo "=== Migrare 002: câmpuri Android ==="
echo "Container: $CONTAINER"
echo "Fișier:    $MIGRATION"
echo ""

# Copiează fișierul SQL în container
docker cp "$MIGRATION" "$CONTAINER:/tmp/002_android_fields.sql"

for DB in bank_bt bank_bcr bank_ing; do
    echo "--- Aplicare pe $DB ---"
    docker exec "$CONTAINER" \
        psql -U "$DB" -d "$DB" \
        -f /tmp/002_android_fields.sql \
        --set ON_ERROR_STOP=1
    echo "    ✓ $DB migrat cu succes"
done

echo ""
echo "=== Migrare 002 completă ==="
