# dashboard/main.py — Schelet minimal
# Logica completă va fi adăugată în pașii următori.
from fastapi import FastAPI
from datetime import datetime, timezone
from dotenv import load_dotenv
load_dotenv()

app = FastAPI(title="NFC dashboard")

from prometheus_fastapi_instrumentator import Instrumentator

Instrumentator().instrument(app).expose(app)

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "dashboard",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
