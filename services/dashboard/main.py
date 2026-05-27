# dashboard/main.py
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from datetime import datetime, timezone
from dotenv import load_dotenv
from pydantic import BaseModel
from typing import List
import os
import httpx

load_dotenv()

app = FastAPI(title="NFC dashboard")

from prometheus_fastapi_instrumentator import Instrumentator
Instrumentator().instrument(app).expose(app)

ESP32_BASE_URL = f"http://{os.getenv('ESP32_HOST', 'localhost')}:{os.getenv('ESP32_PORT', '8088')}"

PRODUCTS = [
    {"id": 1, "name": "Cafea Espresso",  "price_ron": 12.50, "emoji": "☕"},
    {"id": 2, "name": "Sandwich Pui",    "price_ron": 18.00, "emoji": "🥪"},
    {"id": 3, "name": "Apă Plată 0.5L",  "price_ron":  4.50, "emoji": "💧"},
    {"id": 4, "name": "Suc Portocale",   "price_ron":  8.00, "emoji": "🍊"},
    {"id": 5, "name": "Croissant",       "price_ron":  9.50, "emoji": "🥐"},
    {"id": 6, "name": "Salată Caesar",   "price_ron": 22.00, "emoji": "🥗"},
]


class OrderItem(BaseModel):
    product_id: int
    quantity: int


class POSInitiateRequest(BaseModel):
    items: List[OrderItem]


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "dashboard",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


# ── Pages ─────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    return HTMLResponse(content=DASHBOARD_HTML)


@app.get("/pos", response_class=HTMLResponse)
async def pos_page():
    return HTMLResponse(content=POS_HTML)


# ── POS API ───────────────────────────────────────────────────────────────────

@app.get("/api/pos/esp32-status")
async def esp32_status():
    try:
        async with httpx.AsyncClient(timeout=1.0) as client:
            r = await client.get(f"{ESP32_BASE_URL}/payment-request")
        return {
            "status": "online",
            "esp32_state": r.json().get("status", "UNKNOWN")
        }
    except Exception:
        return {"status": "offline"}


@app.post("/api/pos/initiate")
async def pos_initiate(request: POSInitiateRequest):
    amount_cents = 0
    items_detail = []

    for item in request.items:
        if item.product_id < 1 or item.product_id > len(PRODUCTS):
            return JSONResponse(
                status_code=422,
                content={"error": f"Produs invalid: {item.product_id}"}
            )
        product = PRODUCTS[item.product_id - 1]
        amount_cents += int(round(product["price_ron"] * 100)) * item.quantity
        items_detail.append({
            "name": product["name"],
            "quantity": item.quantity,
            "price_ron": product["price_ron"],
            "subtotal_ron": product["price_ron"] * item.quantity
        })

    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.post(
                f"{ESP32_BASE_URL}/initiate-transaction",
                json={"amount_cents": amount_cents, "items": items_detail}
            )
        if resp.status_code == 409:
            return JSONResponse(
                status_code=409,
                content={"error": "Tranzacție deja în curs",
                         "hint": "Așteptați finalizarea tranzacției curente"}
            )
    except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError):
        return JSONResponse(
            status_code=503,
            content={
                "error": "ESP32 indisponibil",
                "hint": "Verifică că simulatorul ESP32 rulează"
            }
        )

    return {
        "status": "initiated",
        "amount_cents": amount_cents,
        "amount_ron": amount_cents / 100,
        "items": items_detail
    }


@app.get("/api/pos/status")
async def pos_status():
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            r = await client.get(f"{ESP32_BASE_URL}/payment-request")
        data = r.json()
        esp32_state = data.get("status", "IDLE")

        if esp32_state == "PENDING":
            return {"status": "WAITING_FOR_PHONE"}

        if esp32_state == "PROCESSING":
            return {"status": "PROCESSING"}

        if esp32_state == "CHALLENGE_REQUIRED":
            return {"status": "CHALLENGE_REQUIRED"}

        if esp32_state == "RESULT":
            result = data.get("result", {})
            if result and result.get("status") in ("APPROVED", "DECLINED"):
                return result
            return {"status": "IDLE"}

        # IDLE — check last result
        try:
            async with httpx.AsyncClient(timeout=2.0) as client2:
                tr = await client2.get(f"{ESP32_BASE_URL}/transaction-result")
            tr_data = tr.json()
            if tr_data.get("status") not in ("no_result", "IDLE", None):
                return tr_data
        except Exception:
            pass

        return {"status": "IDLE"}

    except Exception:
        return {"status": "ESP32_OFFLINE"}


# ── HTML: Overview dashboard ───────────────────────────────────────────────────

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="ro">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>NFC Payment — Dashboard</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d1117;color:#e6edf3;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;padding:32px}
h1{color:#58a6ff;font-size:24px;margin-bottom:6px}
.subtitle{color:#8b949e;margin-bottom:32px;font-size:14px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:16px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;
      display:flex;align-items:center;gap:16px;transition:border-color .2s,box-shadow .2s}
.card:hover{border-color:#58a6ff;box-shadow:0 0 0 1px #58a6ff22}
.card-icon{font-size:28px}
.service-name{font-weight:600;color:#e6edf3;margin-bottom:4px}
.service-meta{font-size:12px;color:#8b949e}
</style>
</head>
<body>
<h1>🏦 NFC Payment System</h1>
<p class="subtitle">Dashboard de monitorizare și management</p>
<div class="grid">
  <div class="card" onclick="window.location='/pos'" style="cursor:pointer;border-color:#58a6ff">
    <div class="card-icon">🏪</div>
    <div>
      <div class="service-name">Casa de Marcat</div>
      <div class="service-meta">Demo POS Terminal</div>
    </div>
  </div>
</div>
</body>
</html>"""


# ── HTML: POS Terminal ────────────────────────────────────────────────────────

POS_HTML = """<!DOCTYPE html>
<html lang="ro">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Casa de Marcat | NFC Demo</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d1117;color:#e6edf3;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
     height:100vh;display:flex;flex-direction:column;overflow:hidden}

/* Header */
.hdr{background:#161b22;border-bottom:1px solid #30363d;padding:12px 20px;
     display:flex;align-items:center;justify-content:space-between;flex-shrink:0}
.hdr-left{display:flex;align-items:center;gap:14px}
.back{color:#58a6ff;text-decoration:none;font-size:13px}
.back:hover{text-decoration:underline}
.hdr h1{font-size:16px;font-weight:600}
.esp-status{display:flex;align-items:center;gap:7px;font-size:12px;color:#8b949e}
.dot{width:9px;height:9px;border-radius:50%;background:#444;flex-shrink:0}
.dot.on{background:#00ff88}
.dot.off{background:#ff4444}

/* Layout */
.main{flex:1;display:grid;grid-template-columns:1fr 370px;overflow:hidden}

/* Products */
.prod-panel{padding:16px;overflow-y:auto;border-right:1px solid #30363d}
.panel-lbl{font-size:11px;font-weight:600;color:#8b949e;text-transform:uppercase;
           letter-spacing:1px;margin-bottom:12px}
.prod-list{display:flex;flex-direction:column;gap:7px}
.prod-item{background:#161b22;border:1px solid #30363d;border-radius:7px;
           padding:12px 14px;display:flex;align-items:center;justify-content:space-between;
           transition:border-color .15s}
.prod-item:hover{border-color:#58a6ff}
.prod-info{display:flex;align-items:center;gap:11px}
.prod-emoji{font-size:20px}
.prod-name{font-size:14px;font-weight:500}
.prod-price{font-size:12px;color:#8b949e;margin-top:2px}
.btn-add{background:#1f6feb;color:#fff;border:none;border-radius:5px;
         width:30px;height:30px;font-size:18px;cursor:pointer;
         display:flex;align-items:center;justify-content:center;flex-shrink:0;
         transition:background .15s}
.btn-add:hover{background:#388bfd}

/* Receipt */
.rec-panel{padding:16px;display:flex;flex-direction:column;overflow-y:auto}
.rec-tbl{width:100%;border-collapse:collapse;margin-bottom:6px}
.rec-tbl th{font-size:10px;color:#8b949e;text-transform:uppercase;
            text-align:left;padding:3px 0;border-bottom:1px solid #30363d}
.rec-tbl th:last-child,.rec-tbl td:last-child{text-align:right}
.rec-tbl td{padding:7px 0;font-size:13px;border-bottom:1px solid #21262d}
.rec-empty{color:#8b949e;font-size:13px;text-align:center;padding:20px 0}
.rec-total{display:flex;justify-content:space-between;align-items:baseline;
           padding:10px 0;border-top:2px solid #30363d;margin-top:3px}
.tot-lbl{color:#8b949e;font-size:13px;font-weight:600}
.tot-val{color:#58a6ff;font-size:20px;font-weight:700}
.btn-clear{background:none;border:1px solid #30363d;border-radius:5px;
           color:#8b949e;padding:7px;cursor:pointer;font-size:12px;
           margin-top:10px;width:100%;transition:border-color .15s,color .15s}
.btn-clear:hover{border-color:#ff4444;color:#ff4444}

/* Checkout */
.checkout{margin-top:14px}
.btn-pay{background:#238636;border:none;border-radius:7px;color:#fff;
         font-size:17px;font-weight:700;padding:16px;width:100%;cursor:pointer;
         transition:background .15s;display:flex;flex-direction:column;align-items:center;gap:3px}
.btn-pay:hover:not(:disabled){background:#2ea043}
.btn-pay:disabled{background:#21262d;color:#8b949e;cursor:not-allowed}
.btn-pay-sub{font-size:13px;font-weight:400;opacity:.9}

/* Status */
.status-box{margin-top:14px;padding:13px;border-radius:7px;border:1px solid #30363d;
            font-size:14px;display:none}
.status-box.vis{display:block}
.st-wait{border-color:#ffaa00;background:rgba(255,170,0,.06)}
.st-proc{border-color:#58a6ff;background:rgba(88,166,255,.06)}
.st-ok  {border-color:#00ff88;background:rgba(0,255,136,.07)}
.st-err {border-color:#ff4444;background:rgba(255,68,68,.07)}
.st-pin {border-color:#ffaa00;background:rgba(255,170,0,.06)}
.st-title{font-weight:700;font-size:15px;margin-bottom:3px}
.st-sub{color:#8b949e;font-size:12px}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
.pulse{animation:pulse 1.4s ease-in-out infinite}
</style>
</head>
<body>

<div class="hdr">
  <div class="hdr-left">
    <a href="/" class="back">← Dashboard</a>
    <h1>🏪 Casa de Marcat — NFC Payment Demo</h1>
  </div>
  <div class="esp-status">
    ESP32 <span class="dot" id="espDot"></span><span id="espLbl">verificare...</span>
  </div>
</div>

<div class="main">
  <div class="prod-panel">
    <div class="panel-lbl">Produse</div>
    <div class="prod-list" id="prodList"></div>
  </div>

  <div class="rec-panel">
    <div class="panel-lbl">Bon Fiscal</div>

    <div class="rec-empty" id="recEmpty">Bonul este gol</div>
    <table class="rec-tbl" id="recTable" style="display:none">
      <thead><tr><th>Produs</th><th>Cant.</th><th>Preț</th></tr></thead>
      <tbody id="recBody"></tbody>
    </table>
    <div id="recTotal" style="display:none">
      <div class="rec-total">
        <span class="tot-lbl">TOTAL:</span>
        <span class="tot-val" id="totAmt">0.00 RON</span>
      </div>
      <button class="btn-clear" onclick="clearCart()">🗑 Golește bon</button>
    </div>

    <div class="checkout">
      <button class="btn-pay" id="btnPay" disabled onclick="checkout()">
        <span>💳 ÎNCASEAZĂ</span>
        <span class="btn-pay-sub" id="payAmt">—</span>
      </button>
    </div>

    <div class="status-box" id="stBox">
      <div class="st-title" id="stTitle"></div>
      <div class="st-sub"   id="stSub"></div>
    </div>
  </div>
</div>

<script>
const PRODUCTS = [
  {id:1,name:"Cafea Espresso",price:12.50,emoji:"☕"},
  {id:2,name:"Sandwich Pui",  price:18.00,emoji:"🥪"},
  {id:3,name:"Apă Plată 0.5L",price: 4.50,emoji:"💧"},
  {id:4,name:"Suc Portocale", price: 8.00,emoji:"🍊"},
  {id:5,name:"Croissant",     price: 9.50,emoji:"🥐"},
  {id:6,name:"Salată Caesar", price:22.00,emoji:"🥗"},
];

let cart    = [];
let polling = null;

// ── Produse ──────────────────────────────────────────────────────────────────
function renderProducts() {
  document.getElementById('prodList').innerHTML = PRODUCTS.map(p => `
    <div class="prod-item">
      <div class="prod-info">
        <span class="prod-emoji">${p.emoji}</span>
        <div>
          <div class="prod-name">${p.name}</div>
          <div class="prod-price">${p.price.toFixed(2)} RON</div>
        </div>
      </div>
      <button class="btn-add" onclick="addItem(${p.id})">+</button>
    </div>`).join('');
}

// ── Coș ──────────────────────────────────────────────────────────────────────
function addItem(id) {
  const p = PRODUCTS.find(x => x.id === id);
  const e = cart.find(x => x.product_id === id);
  if (e) { e.quantity++; } else { cart.push({product_id:id,name:p.name,price:p.price,quantity:1}); }
  renderCart();
}

function clearCart() {
  cart = [];
  renderCart();
  hideStatus();
}

function totalCents() {
  return cart.reduce((s,i) => s + Math.round(i.price * 100) * i.quantity, 0);
}

function renderCart() {
  const empty   = document.getElementById('recEmpty');
  const table   = document.getElementById('recTable');
  const totDiv  = document.getElementById('recTotal');
  const body    = document.getElementById('recBody');
  const totEl   = document.getElementById('totAmt');
  const btn     = document.getElementById('btnPay');
  const amtEl   = document.getElementById('payAmt');

  if (cart.length === 0) {
    empty.style.display = ''; table.style.display = 'none'; totDiv.style.display = 'none';
    btn.disabled = true; amtEl.textContent = '—';
  } else {
    empty.style.display = 'none'; table.style.display = ''; totDiv.style.display = '';
    body.innerHTML = cart.map(i =>
      `<tr><td>${i.name}</td><td>${i.quantity}×</td><td>${(i.price*i.quantity).toFixed(2)}</td></tr>`
    ).join('');
    const total = totalCents() / 100;
    totEl.textContent = total.toFixed(2) + ' RON';
    btn.disabled = false;
    amtEl.textContent = total.toFixed(2) + ' RON';
  }
}

// ── Status ────────────────────────────────────────────────────────────────────
function showStatus(cls, title, sub, titleCls = '') {
  const box = document.getElementById('stBox');
  box.className = 'status-box vis ' + cls;
  const t = document.getElementById('stTitle');
  t.className = 'st-title ' + titleCls;
  t.textContent = title;
  document.getElementById('stSub').textContent = sub;
}
function hideStatus() {
  document.getElementById('stBox').className = 'status-box';
}

// ── Checkout ──────────────────────────────────────────────────────────────────
async function checkout() {
  if (!cart.length) return;
  const btn = document.getElementById('btnPay');
  btn.disabled = true;
  const origHTML = btn.innerHTML;
  btn.innerHTML = '<span>Se procesează...</span>';
  hideStatus();

  try {
    const resp = await fetch('/api/pos/initiate', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({items: cart.map(i => ({product_id: i.product_id, quantity: i.quantity}))})
    });

    if (resp.status === 503) {
      const d = await resp.json();
      showStatus('st-err', '❌ ' + d.error, d.hint || 'Pornește simulatorul.');
      btn.innerHTML = origHTML; btn.disabled = cart.length === 0;
      return;
    }
    if (resp.status === 409) {
      const d = await resp.json();
      showStatus('st-err', '⚠ Conflict', d.error);
      btn.innerHTML = origHTML; btn.disabled = cart.length === 0;
      return;
    }
    if (!resp.ok) {
      showStatus('st-err', '❌ Eroare', 'Eroare necunoscută. Încearcă din nou.');
      btn.innerHTML = origHTML; btn.disabled = cart.length === 0;
      return;
    }

    showStatus('st-wait', '● Apropiați telefonul de terminal...', '', 'st-title pulse');
    startPolling(btn, origHTML);

  } catch {
    showStatus('st-err', '❌ Eroare rețea', 'Nu s-a putut contacta serviciul.');
    btn.innerHTML = origHTML; btn.disabled = cart.length === 0;
  }
}

// ── Polling ────────────────────────────────────────────────────────────────────
function startPolling(btn, origHTML) {
  stopPolling();
  polling = setInterval(() => doPoll(btn, origHTML), 1000);
}
function stopPolling() { if (polling) { clearInterval(polling); polling = null; } }

async function doPoll(btn, origHTML) {
  try {
    const resp = await fetch('/api/pos/status');
    if (!resp.ok) return;
    handlePollResult(await resp.json(), btn, origHTML);
  } catch {}
}

function handlePollResult(data, btn, origHTML) {
  const s = data.status;

  if (s === 'WAITING_FOR_PHONE') {
    showStatus('st-wait', '● Apropiați telefonul de terminal...', '', 'st-title pulse');

  } else if (s === 'PROCESSING') {
    showStatus('st-proc', '⟳ Se procesează...', '');

  } else if (s === 'CHALLENGE_REQUIRED') {
    showStatus('st-pin', '🔐 Introduceți PIN pe terminal...', '');

  } else if (s === 'APPROVED') {
    stopPolling();
    const auth = data.body?.auth_code || data.auth_code || '';
    showStatus('st-ok', '✅ APROBAT', auth ? 'Auth: ' + auth : 'Tranzacție aprobată.');
    setTimeout(() => { clearCart(); btn.innerHTML = origHTML; btn.disabled = true; }, 3000);

  } else if (s === 'DECLINED') {
    stopPolling();
    const reason = data.body?.detail?.message || data.reason || '';
    showStatus('st-err', '❌ REFUZAT', reason || 'Tranzacție refuzată.');
    btn.innerHTML = origHTML; btn.disabled = cart.length === 0;

  } else if (s === 'ESP32_OFFLINE') {
    stopPolling();
    showStatus('st-err', '❌ ESP32 deconectat', 'Conexiunea cu terminalul s-a pierdut.');
    btn.innerHTML = origHTML; btn.disabled = cart.length === 0;
  }
}

// ── ESP32 indicator ────────────────────────────────────────────────────────────
async function checkEsp32() {
  const dot = document.getElementById('espDot');
  const lbl = document.getElementById('espLbl');
  try {
    const d = await (await fetch('/api/pos/esp32-status')).json();
    if (d.status === 'online') {
      dot.className = 'dot on'; lbl.textContent = d.esp32_state || 'online';
    } else {
      dot.className = 'dot off'; lbl.textContent = 'offline';
    }
  } catch { dot.className = 'dot off'; lbl.textContent = 'offline'; }
}

renderProducts();
checkEsp32();
setInterval(checkEsp32, 5000);
</script>
</body>
</html>"""
