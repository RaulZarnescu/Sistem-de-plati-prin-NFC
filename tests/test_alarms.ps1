Write-Host "========================================="
Write-Host "   TESTARE ALERTE GRAFANA (Prometheus)   "
Write-Host "========================================="

$ScriptPath = "$PSScriptRoot\trigger_alerts.py"

Write-Host "`n[1] Declansare Alerta: Crypto Brute Force"
Write-Host "Se trimit 100 de cereri cu MAC invalid pentru a genera o rata mare de 400 Bad Request..."
python $ScriptPath crypto
Write-Host "Asteptam 5 secunde pentru colectarea metricilor..."
Start-Sleep -Seconds 5

Write-Host "`n[2] Declansare Alerta: Error Rate 5xx"
Write-Host "Oprim Redis temporar pentru a forta Gateway-ul sa intre in Fail-Closed (503)..."
docker stop nfc-redis-master | Out-Null
Start-Sleep -Seconds 2
python $ScriptPath 5xx
Write-Host "Repornim Redis..."
docker start nfc-redis-master | Out-Null
Write-Host "Asteptam 5 secunde pentru colectarea metricilor..."
Start-Sleep -Seconds 5

Write-Host "`n[3] Declansare Alerta: SLA Breach p95"
Write-Host "Trimitem un burst extrem de 500 de cereri paralele pentru a degrada performanta..."
python $ScriptPath sla
Write-Host "Asteptam 5 secunde pentru colectarea metricilor..."
Start-Sleep -Seconds 5

Write-Host "`nToate scenariile au fost executate!"
Write-Host "Verifica Grafana (http://localhost:3000) la sectiunea de Alerte."
