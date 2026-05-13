$ErrorActionPreference = "Stop"

Write-Host "=== TEST REDIS FAILOVER ==="

Write-Host "1. Oprire Redis..."
docker stop nfc-redis-master | Out-Null
Start-Sleep -Seconds 2

Write-Host "2. Trimitere request către Gateway..."
$body = '{"dpan": "4000000000000001", "transaction": {"amount": 1000, "currency": "RON", "pos_nonce": "failover-nonce", "terminal_timestamp": "2026-05-13T10:00:00Z"}, "cryptogram": {"atc": 9999, "mac": "dummy"}}'

try {
    $r = Invoke-RestMethod -Uri http://localhost:8001/api/v1/payments/authorize -Method Post -ContentType 'application/json' -Headers @{'X-Idempotency-Key'='failover-test'; 'X-Terminal-Id'='POS-A'} -Body $body
    Write-Host "FAIL: Gateway a returnat HTTP 200, desi Redis este picat!"
} catch {
    $code = $_.Exception.Response.StatusCode.value__
    $stream = $_.Exception.Response.GetResponseStream()
    $detail = (New-Object System.IO.StreamReader($stream)).ReadToEnd()
    
    if ($code -eq 503) {
        Write-Host "PASS: Gateway a returnat corect HTTP 503 Service Unavailable."
        Write-Host "Response body: $detail"
    } else {
        Write-Host "FAIL: Gateway a returnat HTTP $code în loc de 503."
        Write-Host "Response body: $detail"
    }
}

Write-Host "3. Repornire Redis..."
docker start nfc-redis-master | Out-Null
Start-Sleep -Seconds 3

Write-Host "4. Testare recovery..."
try {
    $r = Invoke-RestMethod -Uri http://localhost:8001/health
    Write-Host "PASS: Gateway si-a revenit."
} catch {
    Write-Host "FAIL: Gateway nu a putut sa revina dupa restart."
}
