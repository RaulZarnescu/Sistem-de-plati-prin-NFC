import httpx
import asyncio
import time
import random
import uuid
import os
import sys
from datetime import datetime, timezone
from dotenv import load_dotenv

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from shared.crypto_utils import compute_mac

load_dotenv()

key_a = bytes.fromhex(os.getenv('ISSUING_BANK_HMAC_MASTER_KEY', ''))
URL = "http://localhost:8001/api/v1/payments/authorize"
DPAN = "4000000000000001"

def amount_to_cents(amount: float) -> int:
    return int(round(amount * 100))

async def send_invalid_macs(client, count=50):
    print(f"--- 1. Triggering Crypto Brute Force ({count} invalid MACs) ---")
    tasks = []
    for i in range(count):
        nonce = f"BF-{uuid.uuid4().hex[:8]}"
        ts = datetime.now(timezone.utc).isoformat()
        atc = int(time.time() * 1000) + i
        
        body = {
            "dpan": DPAN,
            "transaction": {"amount": 1000, "currency": "RON", "pos_nonce": nonce, "terminal_timestamp": ts},
            "cryptogram": {"atc": atc, "mac": "INVALID_MAC_BRUTE_FORCE"}
        }
        
        idemp_key = f"bf-{uuid.uuid4().hex[:8]}"
        terminal = f"POS-BF-{random.randint(1, 100)}" # Use random terminals to avoid rate limit
        
        tasks.append(client.post(URL, json=body, headers={"X-Idempotency-Key": idemp_key, "X-Terminal-Id": terminal}))
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    statuses = [r.status_code for r in results if not isinstance(r, Exception)]
    print(f"Crypto Brute Force results: {statuses.count(400)} x 400 Bad Request out of {len(statuses)}")

async def send_valid_requests(client, count=50):
    print(f"--- Sending {count} valid requests ---")
    tasks = []
    for i in range(count):
        nonce = f"OK-{uuid.uuid4().hex[:8]}"
        ts = datetime.now(timezone.utc).isoformat()
        atc = int(time.time() * 1000) + i
        mac = compute_mac(key_a, 1000, "RON", nonce, ts, atc)
        
        body = {
            "dpan": DPAN,
            "transaction": {"amount": 1000, "currency": "RON", "pos_nonce": nonce, "terminal_timestamp": ts},
            "cryptogram": {"atc": atc, "mac": mac}
        }
        
        idemp_key = f"ok-{uuid.uuid4().hex[:8]}"
        terminal = f"POS-OK-{random.randint(1, 1000)}" 
        
        tasks.append(client.post(URL, json=body, headers={"X-Idempotency-Key": idemp_key, "X-Terminal-Id": terminal}))
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    statuses = [r.status_code if not isinstance(r, Exception) else str(r) for r in results]
    print(f"Valid requests results: 200x{statuses.count(200)}, 5xx: {len([s for s in statuses if isinstance(s, int) and s >= 500])}")

async def main():
    action = sys.argv[1] if len(sys.argv) > 1 else "all"
    
    async with httpx.AsyncClient(timeout=10.0) as client:
        if action in ["crypto", "all"]:
            await send_invalid_macs(client, count=100)
            
        if action in ["5xx", "all"]:
            print("\n--- 2. Triggering 5xx Errors ---")
            print("To trigger this, we need to stop a dependency. Use the PowerShell script wrapper to stop Redis or TSP.")
            await send_valid_requests(client, count=20)
            
        if action in ["sla", "all"]:
            print("\n--- 3. Triggering SLA Breach (p95) ---")
            print("Sending a massive burst of valid requests to degrade latency...")
            for _ in range(5):
                await send_valid_requests(client, count=100)
                await asyncio.sleep(0.5)

if __name__ == "__main__":
    asyncio.run(main())
