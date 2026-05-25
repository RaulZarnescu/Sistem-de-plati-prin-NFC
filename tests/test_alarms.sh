#!/bin/bash

echo "========================================="
echo "   TESTARE ALERTE GRAFANA (Prometheus)   "
echo "========================================="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_PATH="$SCRIPT_DIR/trigger_alerts.py"

echo -e "\n[1] Declansare Alerta: Crypto Brute Force"
echo "Se trimit 100 de cereri cu MAC invalid pentru a genera o rata mare de 400 Bad Request..."
python3 "$SCRIPT_PATH" crypto
echo "Asteptam 5 secunde pentru colectarea metricilor..."
sleep 5

echo -e "\n[2] Declansare Alerta: Error Rate 5xx"
echo "Oprim Redis temporar pentru a forta Gateway-ul sa intre in Fail-Closed (503)..."
docker stop nfc-redis-master > /dev/null
sleep 2
python3 "$SCRIPT_PATH" 5xx
echo "Repornim Redis..."
docker start nfc-redis-master > /dev/null
echo "Asteptam 5 secunde pentru colectarea metricilor..."
sleep 5

echo -e "\n[3] Declansare Alerta: SLA Breach p95"
echo "Trimitem un burst extrem de 500 de cereri paralele pentru a degrada performanta..."
python3 "$SCRIPT_PATH" sla
echo "Asteptam 5 secunde pentru colectarea metricilor..."
sleep 5

echo -e "\nToate scenariile au fost executate!"
echo "Verifica Grafana (http://localhost:3000) la sectiunea de Alerte."
