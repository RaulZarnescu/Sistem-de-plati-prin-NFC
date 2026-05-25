#!/bin/bash
set -e

for DB in "bank_bt" "bank_bcr" "bank_ing"; do
    echo "Applying schema to $DB..."
    psql -v ON_ERROR_STOP=1 --username "$DB" --dbname "$DB" < /docker-entrypoint-initdb.d/01_schema.sql.template
done
