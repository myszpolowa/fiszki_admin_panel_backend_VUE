# database.py в fiszki_pycharm (GATEWAY)
import os
import httpx
from fastapi import HTTPException

DB_SERVICE_URL = os.getenv("DB_SERVICE_URL", "http://127.0.0.1:8003")

async def get_db() -> httpx.AsyncClient:
    client = httpx.AsyncClient(base_url=DB_SERVICE_URL, timeout=10.0)
    try:
        resp = await client.get("/health")
        resp.raise_for_status()
        return client
    except httpx.RequestError:
        await client.aclose()
        raise HTTPException(status_code=503, detail="DB Service is unavailable")
