import httpx
import asyncio
import time
import random
import uuid
import os
from datetime import datetime, timezone
from dotenv import load_dotenv
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from shared.crypto_utils import compute_mac, derive_session_key

def amount_to_cents(amount: float) -> int:
    return int(round(amount * 100))

load_dotenv()

key_a = bytes.fromhex(os.getenv('BANK_BT_HMAC_KEY') or os.getenv('ISSUING_BANK_HMAC_MASTER_KEY', ''))
key_b = bytes.fromhex(os.getenv('BANK_BCR_HMAC_KEY') or os.getenv('ISSUING_BANK_B_HMAC_MASTER_KEY', ''))
key_c = bytes.fromhex(os.getenv('BANK_ING_HMAC_KEY', ''))

URL = "http://localhost:8001/api/v1/payments/authorize"

dpans = [
    ("4000000000000001", key_a),  # BT,  Visa
    ("TEST-STEP-UP-001", key_a),  # BT,  Visa, risk=55
    ("5000000000000002", key_b),  # BCR, Mastercard
    ("5000000000000003", key_c),  # ING, Mastercard
]

terminals = ["POS-BETA-01", "POS-BETA-02", "POS-BETA-03", "POS-BETA-04", "POS-BETA-05"]

# Keep track of ATC per PAN to avoid Replay Attack errors
atc_counters = {d[0]: 100000 for d in dpans}

async def send_request(client, req_id):
    dpan, key = random.choice(dpans)
    terminal = random.choice(terminals)
    amount = round(random.uniform(5.0, 500.0), 2)
    nonce = f"LT-{uuid.uuid4().hex[:8]}"
    ts = datetime.now(timezone.utc).isoformat()
    
    atc = int(time.time() * 1000) + random.randint(1, 100)

    amount_cents = amount_to_cents(amount)

    # Some invalid requests for 400s
    if random.random() < 0.1:
        mac = "INVALID_MAC"
    else:
        session_key = derive_session_key(key, atc)
        mac = compute_mac(session_key, amount_cents, "RON", nonce, ts, atc)

    body = {
        "dpan": dpan,
        "transaction": {
            "amount": amount_cents,
            "currency": "RON",
            "pos_nonce": nonce,
            "terminal_timestamp": ts
        },
        "cryptogram": {
            "atc": atc,
            "mac": mac
        }
    }

    idemp_key = f"idemp-lt-{req_id}-{uuid.uuid4().hex[:6]}"
    
    try:
        r = await client.post(
            URL, 
            json=body, 
            headers={"X-Idempotency-Key": idemp_key, "X-Terminal-Id": terminal},
            timeout=2.0
        )
        if r.status_code == 422:
            return f"422: {r.text}"
        return r.status_code
    except Exception as e:
        return str(e)

async def main():
    print("Incepere load test pentru generare de metrici in Prometheus...")
    async with httpx.AsyncClient() as client:
        for batch in range(15):
            print(f"Trimitere batch {batch+1}/15...")
            tasks = [send_request(client, f"{batch}-{i}") for i in range(10)]
            results = await asyncio.gather(*tasks)
            print(f"Rezultate batch {batch+1}: {results}")
            # Gateway has rate limits (2 req/sec per terminal). 10 concurrent over 5 terminals = ~2 req/term.
            # Might get some 429s, which is good for metrics.
            await asyncio.sleep(1)
            
if __name__ == "__main__":
    asyncio.run(main())
