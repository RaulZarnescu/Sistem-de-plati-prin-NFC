# issuing_bank/main.py — Schelet minimal
# Logica completă va fi adăugată în pașii următori.
from fastapi import FastAPI
from datetime import datetime, timezone
from dotenv import load_dotenv
load_dotenv()

app = FastAPI(title="NFC issuing_bank")

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "issuing_bank",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
