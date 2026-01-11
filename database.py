# database.py в fiszki_pycharm (GATEWAY) — ИСПРАВЛЕННАЯ ВЕРСИЯ
import os
import httpx
import time
from fastapi import HTTPException

DB_SERVICE_URL = os.getenv("DB_SERVICE_URL", "http://127.0.0.1:8003")

# Кэш health check — Render free засыпает!
_db_health_ok = True
_db_health_time = 0

async def get_db() -> httpx.AsyncClient:
    global _db_health_ok, _db_health_time
    
    # Проверяем health не чаще раза в 2 минуты
    if time.time() - _db_health_time < 120:
        if _db_health_ok:
            return httpx.AsyncClient(base_url=DB_SERVICE_URL, timeout=30.0)  # 30s для пробуждения
    
    try:
        async with httpx.AsyncClient(base_url=DB_SERVICE_URL, timeout=10.0) as client:
            resp = await client.get("/health")
            if resp.status_code == 429:  # Rate limit
                _db_health_ok = True  # Игнорируем, DB живой
            elif resp.status_code != 200:
                _db_health_ok = False
                raise HTTPException(503, f"DB health failed: {resp.status_code}")
            else:
                _db_health_ok = True
    except (httpx.TimeoutException, httpx.ConnectError):
        # DB спит — пробуждаем в роуте
        _db_health_ok = True
    except Exception as e:
        print(f"DB health error: {e}")
        _db_health_ok = False
    
    _db_health_time = time.time()
    return httpx.AsyncClient(base_url=DB_SERVICE_URL, timeout=30.0)  # timeout↑ для free tier
