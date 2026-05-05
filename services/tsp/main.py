# tsp/main.py — Schelet minimal
# Logica completă va fi adăugată în pașii următori.
from fastapi import FastAPI
from datetime import datetime, timezone
from dotenv import load_dotenv
load_dotenv()

app = FastAPI(title="NFC tsp")

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "tsp",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
