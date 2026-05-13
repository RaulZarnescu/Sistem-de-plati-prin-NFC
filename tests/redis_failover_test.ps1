# ============================================================
# redis_failover_test.ps1 — TC-12: Fail-Closed Redis
#
# Validează comportamentul fail-closed al Gateway-ului:
# dacă Redis este INDISPONIBIL LA STARTUP, Gateway-ul trebuie
# să returneze 503 IDEMPOTENCY_STORE_DOWN pentru orice cerere.
#
# Rulare (din rădăcina proiectului):
#   .\tests\redis_failover_test.ps1
#
# Precondții:
#   - docker compose up -d (toate serviciile rulează)
#   - Containerele se numesc: nfc-gateway, nfc-redis-master
#     (verifică cu: docker ps --format "{{.Names}}")
#
# NOTĂ DE ARHITECTURĂ (limitare PoC):
#   Testul acoperă scenariul "Redis down la startup" → redis_client = None.
#   Dacă Redis pică DUPĂ startup, redis_client există (nu e None), iar
#   operațiile Redis aruncă ConnectionError → HTTP 500 (neacoperit de TC-12).
#   Producție: adaugă try/except în jurul fiecărui redis_client.get/set.
# ============================================================

param(
    [string]$GatewayUrl = "http://localhost:$($env:GATEWAY_PORT ?? '8001')",
    [string]$GatewayContainer = "nfc-gateway",
    [string]$RedisContainer   = "nfc-redis-master"
)

$ErrorActionPreference = "Continue"
$tc12_passed = $false

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  TC-12: Fail-Closed Redis" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Gateway URL : $GatewayUrl"
Write-Host "  Gateway     : $GatewayContainer"
Write-Host "  Redis       : $RedisContainer"
Write-Host ""

# ---- Helper: print step ----
function Step([int]$n, [int]$total, [string]$msg) {
    Write-Host "[$n/$total] $msg" -ForegroundColor Yellow
}

# ---- [1/5] Verificare containere active ----
Step 1 5 "Verificare containere active..."
$running = docker ps --format "{{.Names}}" 2>$null
if ($running -notcontains $GatewayContainer) {
    Write-Host "  EROARE: Containerul '$GatewayContainer' nu rulează. Rulează 'docker compose up -d'." -ForegroundColor Red
    exit 1
}
if ($running -notcontains $RedisContainer) {
    Write-Host "  EROARE: Containerul '$RedisContainer' nu rulează. Rulează 'docker compose up -d'." -ForegroundColor Red
    exit 1
}
Write-Host "  OK  Gateway=$GatewayContainer  Redis=$RedisContainer" -ForegroundColor Green

# ---- [2/5] Oprire Redis ----
Step 2 5 "Oprire Redis ($RedisContainer)..."
docker stop $RedisContainer | Out-Null
if (-not $?) {
    Write-Host "  EROARE: Nu s-a putut opri Redis!" -ForegroundColor Red
    exit 1
}
Write-Host "  OK  Redis oprit" -ForegroundColor Green

# ---- [3/5] Restart Gateway (fara Redis disponibil la startup) ----
Step 3 5 "Restart Gateway (se porneste fara Redis → redis_client = None)..."
docker restart $GatewayContainer | Out-Null
if (-not $?) {
    Write-Host "  EROARE: Nu s-a putut reporni Gateway!" -ForegroundColor Red
    # Restaurare inainte de a iesi
    docker start $RedisContainer | Out-Null
    exit 1
}
Write-Host "  Astept 4s pentru FastAPI readiness..." -ForegroundColor DarkGray
Start-Sleep -Seconds 4
Write-Host "  OK  Gateway repornit (Redis absent la startup)" -ForegroundColor Green

# ---- [4/5] Cerere de test → astepta 503 ----
Step 4 5 "Cerere de autorizare → astept 503 IDEMPOTENCY_STORE_DOWN..."

$idempKey  = "TC12-$(Get-Random -Maximum 999999)"
$timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")

$bodyObj = @{
    dpan        = "4000000000000001"
    transaction = @{
        amount             = 5000
        currency           = "RON"
        pos_nonce          = "TC12AAAA"
        terminal_timestamp = $timestamp
    }
    cryptogram  = @{ mac = "fakemac"; atc = 999 }
}
$bodyJson = $bodyObj | ConvertTo-Json -Depth 5

$headers = @{
    "X-Idempotency-Key" = $idempKey
    "X-Terminal-Id"     = "POS-TC12-TEST"
    "Content-Type"      = "application/json"
}

try {
    # Invoke-WebRequest aruncă exceptie pentru 4xx/5xx → folosim -ErrorAction Stop
    $resp = Invoke-WebRequest `
        -Uri "$GatewayUrl/api/v1/payments/authorize" `
        -Method POST `
        -Headers $headers `
        -Body $bodyJson `
        -ErrorAction Stop

    # Daca ajungem aici → am primit 2xx → FAIL
    Write-Host "  ESEC: HTTP $($resp.StatusCode) — asteptam 503!" -ForegroundColor Red
    $tc12_passed = $false

} catch {
    $statusCode = $null
    if ($_.Exception.Response) {
        $statusCode = [int]$_.Exception.Response.StatusCode
    }

    if ($statusCode -eq 503) {
        # Verificam si error_code din body
        $respBody = $null
        try {
            $rawStream = $_.Exception.Response.GetResponseStream()
            $reader    = New-Object System.IO.StreamReader($rawStream)
            $rawJson   = $reader.ReadToEnd()
            $respBody  = $rawJson | ConvertFrom-Json
        } catch { }

        $errorCode = $respBody.detail.error_code
        if ($errorCode -eq "IDEMPOTENCY_STORE_DOWN") {
            Write-Host "  PASSED  HTTP 503, error_code=IDEMPOTENCY_STORE_DOWN" -ForegroundColor Green
            $tc12_passed = $true
        } else {
            Write-Host "  ESEC: HTTP 503 dar error_code='$errorCode' (asteptam IDEMPOTENCY_STORE_DOWN)" -ForegroundColor Red
            $tc12_passed = $false
        }
    } else {
        Write-Host "  ESEC: HTTP $statusCode — asteptam 503! (detalii: $($_.Exception.Message))" -ForegroundColor Red
        $tc12_passed = $false
    }
}

# ---- [5/5] Restaurare ----
Step 5 5 "Restaurare Redis si Gateway la starea initiala..."
docker start $RedisContainer | Out-Null
Write-Host "  Astept 2s pentru Redis readiness..." -ForegroundColor DarkGray
Start-Sleep -Seconds 2
docker restart $GatewayContainer | Out-Null
Write-Host "  Astept 4s pentru Gateway readiness..." -ForegroundColor DarkGray
Start-Sleep -Seconds 4
Write-Host "  OK  Sistem restaurat" -ForegroundColor Green

# ---- Rezultat final ----
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
if ($tc12_passed) {
    Write-Host "  REZULTAT TC-12: PASSED" -ForegroundColor Green
} else {
    Write-Host "  REZULTAT TC-12: FAILED" -ForegroundColor Red
}
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

exit $(if ($tc12_passed) { 0 } else { 1 })
