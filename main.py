# main.py — Gateway для Vue backend (порт 8002)

from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI, Depends, HTTPException, status, BackgroundTasks
from fastapi.responses import HTMLResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles

from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi.middleware.cors import CORSMiddleware
import httpx
import os

from database import get_db
from schemas import (
    LevelOut, QuestionOut, AdminLoginIn, AnswerOut,
    LevelCreate, LevelUpdate,
    QuestionCreate, QuestionUpdate,
    AnswerCreate, AnswerUpdate,
    UserOut, UserCreate, UserLoginIn,
    UserChangePasswordIn, UserChangeLoginIn, UserResetPasswordIn, AdminLevelOut,
)

# -------------------------------------------------
# Приложение и CORS
# -------------------------------------------------

app = FastAPI()

CORS_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "https://fiszkiadminpanelfrontend.vercel.app",  
    "*"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"], )


# -------------------------------------------------
# JWT для администратора
# -------------------------------------------------

SECRET_KEY = os.getenv("SECRET_KEY", "jnUubi5NNKDkRd2neldQRikDcOeQ5MagGnRvsxki7sQ")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/admin/login")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_admin(
    token: str = Depends(oauth2_scheme),
) -> dict:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        admin_id: str | None = payload.get("sub")
        role: str | None = payload.get("role")
        if admin_id is None or role != "admin":
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    return {"id_admin": int(admin_id), "role": role}

# -------------------------------------------------
# Health check с отладкой CORS
# -------------------------------------------------
@app.get("/health")
async def health():
    return {
        "status": "ok",
        "cors_origins": CORS_ORIGINS,
        "cors_env": ', '.join(CORS_ORIGINS)
    }

# -------------------------------------------------
# Публичные эндпоинты для телефона / Vue
# -------------------------------------------------


@app.get("/levels", response_model=list[LevelOut])
async def get_levels(
    background_tasks: BackgroundTasks,
    db_client: httpx.AsyncClient = Depends(get_db),
):
    resp = await db_client.get("/levels")
    resp.raise_for_status()
    background_tasks.add_task(db_client.aclose)
    return resp.json()


@app.get("/levels/{level_id}/questions", response_model=list[QuestionOut])
async def get_questions(
    level_id: int,
    background_tasks: BackgroundTasks,
    db_client: httpx.AsyncClient = Depends(get_db),
):
    resp = await db_client.get(f"/levels/{level_id}/questions")
    if resp.status_code == 404:
        background_tasks.add_task(db_client.aclose)
        raise HTTPException(status_code=404, detail="Level not found")
    resp.raise_for_status()
    background_tasks.add_task(db_client.aclose)
    return resp.json()


# ---------- Пользователи и прогресс ----------

@app.get("/user/{user_id}", response_model=UserOut)
async def get_user_by_id(
    user_id: int,
    background_tasks: BackgroundTasks,
    db_client: httpx.AsyncClient = Depends(get_db),
):
    resp = await db_client.get(f"/user/{user_id}")
    if resp.status_code == 404:
        background_tasks.add_task(db_client.aclose)
        raise HTTPException(status_code=404, detail="User not found")
    resp.raise_for_status()
    background_tasks.add_task(db_client.aclose)
    return resp.json()


@app.put("/user/{user_id}/progress", response_model=UserOut)
async def update_user_progress_by_id(
    user_id: int,
    new_progress: int,
    background_tasks: BackgroundTasks,
    db_client: httpx.AsyncClient = Depends(get_db),
):
    resp = await db_client.put(
        f"/user/{user_id}/progress",
        params={"new_progress": new_progress},
    )
    if resp.status_code == 404:
        background_tasks.add_task(db_client.aclose)
        raise HTTPException(status_code=404, detail="User not found")
    resp.raise_for_status()
    background_tasks.add_task(db_client.aclose)
    return resp.json()


@app.post("/user/register", response_model=UserOut)
async def register_user(
    data: UserCreate,
    background_tasks: BackgroundTasks,
    db_client: httpx.AsyncClient = Depends(get_db),
):
    resp = await db_client.post("/user/register", json=data.dict())
    if resp.status_code == 400:
        background_tasks.add_task(db_client.aclose)
        raise HTTPException(status_code=400, detail=resp.json().get("detail", "User already exists"))
    resp.raise_for_status()
    background_tasks.add_task(db_client.aclose)
    return resp.json()


@app.post("/user/login", response_model=UserOut)
async def login_user(
    data: UserLoginIn,
    background_tasks: BackgroundTasks,
    db_client: httpx.AsyncClient = Depends(get_db),
):
    resp = await db_client.post("/user/login", json=data.dict())
    if resp.status_code == 401:
        background_tasks.add_task(db_client.aclose)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    resp.raise_for_status()
    background_tasks.add_task(db_client.aclose)
    return resp.json()


@app.put("/user/{user_id}/change-password", response_model=UserOut)
async def change_password(
    user_id: int,
    data: UserChangePasswordIn,
    background_tasks: BackgroundTasks,
    db_client: httpx.AsyncClient = Depends(get_db),
):
    resp = await db_client.put(f"/user/{user_id}/change-password", json=data.dict())
    if resp.status_code in (400, 404):
        background_tasks.add_task(db_client.aclose)
        raise HTTPException(status_code=resp.status_code, detail=resp.json().get("detail"))
    resp.raise_for_status()
    background_tasks.add_task(db_client.aclose)
    return resp.json()


@app.put("/user/{user_id}/change-login", response_model=UserOut)
async def change_login(
    user_id: int,
    data: UserChangeLoginIn,
    background_tasks: BackgroundTasks,
    db_client: httpx.AsyncClient = Depends(get_db),
):
    resp = await db_client.put(f"/user/{user_id}/change-login", json=data.dict())
    if resp.status_code in (400, 404):
        background_tasks.add_task(db_client.aclose)
        raise HTTPException(status_code=resp.status_code, detail=resp.json().get("detail"))
    resp.raise_for_status()
    background_tasks.add_task(db_client.aclose)
    return resp.json()


RESET_CODE = os.getenv("RESET_CODE", "1111")


@app.post("/user/reset-password", response_model=UserOut)
async def reset_password(
    data: UserResetPasswordIn,
    background_tasks: BackgroundTasks,
    db_client: httpx.AsyncClient = Depends(get_db),
):
    resp = await db_client.post("/user/reset-password", json=data.dict())
    if resp.status_code in (400, 404):
        background_tasks.add_task(db_client.aclose)
        raise HTTPException(status_code=resp.status_code, detail=resp.json().get("detail"))
    resp.raise_for_status()
    background_tasks.add_task(db_client.aclose)
    return resp.json()

# -------------------------------------------------
# Логин администратора
# -------------------------------------------------


@app.post("/admin/login")
async def admin_login(
    background_tasks: BackgroundTasks,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db_client: httpx.AsyncClient = Depends(get_db),
):
    resp = await db_client.post(
        "/admin/login",
        data={"username": form_data.username, "password": form_data.password},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    if resp.status_code != 200:
        background_tasks.add_task(db_client.aclose)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid admin credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    data = resp.json()
    background_tasks.add_task(db_client.aclose)
    return data


# -------------------------------------------------
# ADMIN CRUD (проксирование в DB Service)
# -------------------------------------------------


@app.get("/admin/levels", response_model=list[AdminLevelOut])
async def admin_get_levels(
    background_tasks: BackgroundTasks,
    current_admin: dict = Depends(get_current_admin),
    db_client: httpx.AsyncClient = Depends(get_db),
):
    resp = await db_client.get("/admin/levels")
    resp.raise_for_status()
    background_tasks.add_task(db_client.aclose)
    return resp.json()


@app.post("/admin/levels", response_model=LevelOut)
async def admin_create_level(
    data: LevelCreate,
    background_tasks: BackgroundTasks,
    current_admin: dict = Depends(get_current_admin),
    db_client: httpx.AsyncClient = Depends(get_db),
):
    resp = await db_client.post("/admin/levels", json=data.dict())
    resp.raise_for_status()
    background_tasks.add_task(db_client.aclose)
    return resp.json()


@app.put("/admin/levels/{level_id}", response_model=LevelOut)
async def admin_update_level(
    level_id: int,
    data: LevelUpdate,
    background_tasks: BackgroundTasks,
    current_admin: dict = Depends(get_current_admin),
    db_client: httpx.AsyncClient = Depends(get_db),
):
    resp = await db_client.put(f"/admin/levels/{level_id}", json=data.dict())
    if resp.status_code == 404:
        background_tasks.add_task(db_client.aclose)
        raise HTTPException(status_code=404, detail="Level not found")
    resp.raise_for_status()
    background_tasks.add_task(db_client.aclose)
    return resp.json()


@app.delete("/admin/levels/{level_id}")
async def admin_delete_level(
    level_id: int,
    background_tasks: BackgroundTasks,
    current_admin: dict = Depends(get_current_admin),
    db_client: httpx.AsyncClient = Depends(get_db),
):
    resp = await db_client.delete(f"/admin/levels/{level_id}")
    if resp.status_code == 404:
        background_tasks.add_task(db_client.aclose)
        raise HTTPException(status_code=404, detail="Level not found")
    resp.raise_for_status()
    background_tasks.add_task(db_client.aclose)
    return {"detail": "Level deleted"}


@app.get("/admin/questions", response_model=list[QuestionOut])
async def admin_get_questions(
    background_tasks: BackgroundTasks,
    current_admin: dict = Depends(get_current_admin),
    db_client: httpx.AsyncClient = Depends(get_db),
):
    resp = await db_client.get("/admin/questions")
    resp.raise_for_status()
    background_tasks.add_task(db_client.aclose)
    return resp.json()


@app.post("/admin/questions", response_model=QuestionOut)
async def admin_create_question(
    data: QuestionCreate,
    background_tasks: BackgroundTasks,
    current_admin: dict = Depends(get_current_admin),
    db_client: httpx.AsyncClient = Depends(get_db),
):
    resp = await db_client.post("/admin/questions", json=data.dict())
    if resp.status_code == 404:
        background_tasks.add_task(db_client.aclose)
        raise HTTPException(status_code=404, detail="Level not found")
    resp.raise_for_status()
    background_tasks.add_task(db_client.aclose)
    return resp.json()


@app.put("/admin/questions/{question_id}", response_model=QuestionOut)
async def admin_update_question(
    question_id: int,
    data: QuestionUpdate,
    background_tasks: BackgroundTasks,
    current_admin: dict = Depends(get_current_admin),
    db_client: httpx.AsyncClient = Depends(get_db),
):
    resp = await db_client.put(f"/admin/questions/{question_id}", json=data.dict())
    if resp.status_code == 404:
        background_tasks.add_task(db_client.aclose)
        raise HTTPException(status_code=404, detail="Question not found")
    resp.raise_for_status()
    background_tasks.add_task(db_client.aclose)
    return resp.json()


@app.delete("/admin/questions/{question_id}")
async def admin_delete_question(
    question_id: int,
    background_tasks: BackgroundTasks,
    current_admin: dict = Depends(get_current_admin),
    db_client: httpx.AsyncClient = Depends(get_db),
):
    resp = await db_client.delete(f"/admin/questions/{question_id}")
    if resp.status_code == 404:
        background_tasks.add_task(db_client.aclose)
        raise HTTPException(status_code=404, detail="Question not found")
    resp.raise_for_status()
    background_tasks.add_task(db_client.aclose)
    return {"detail": "Question deleted"}


@app.get("/admin/answers", response_model=list[AnswerOut])
async def admin_get_answers(
    background_tasks: BackgroundTasks,
    current_admin: dict = Depends(get_current_admin),
    db_client: httpx.AsyncClient = Depends(get_db),
):
    resp = await db_client.get("/admin/answers")
    resp.raise_for_status()
    background_tasks.add_task(db_client.aclose)
    return resp.json()


@app.post("/admin/answers", response_model=AnswerOut)
async def admin_create_answer(
    data: AnswerCreate,
    background_tasks: BackgroundTasks,
    current_admin: dict = Depends(get_current_admin),
    db_client: httpx.AsyncClient = Depends(get_db),
):
    resp = await db_client.post("/admin/answers", json=data.dict())
    if resp.status_code == 404:
        background_tasks.add_task(db_client.aclose)
        raise HTTPException(status_code=404, detail="Question not found")
    resp.raise_for_status()
    background_tasks.add_task(db_client.aclose)
    return resp.json()


@app.put("/admin/answers/{answer_id}", response_model=AnswerOut)
async def admin_update_answer(
    answer_id: int,
    data: AnswerUpdate,
    background_tasks: BackgroundTasks,
    current_admin: dict = Depends(get_current_admin),
    db_client: httpx.AsyncClient = Depends(get_db),
):
    resp = await db_client.put(f"/admin/answers/{answer_id}", json=data.dict())
    if resp.status_code == 404:
        background_tasks.add_task(db_client.aclose)
        raise HTTPException(status_code=404, detail="Answer not found")
    resp.raise_for_status()
    background_tasks.add_task(db_client.aclose)
    return resp.json()


@app.delete("/admin/answers/{answer_id}")
async def admin_delete_answer(
    answer_id: int,
    background_tasks: BackgroundTasks,
    current_admin: dict = Depends(get_current_admin),
    db_client: httpx.AsyncClient = Depends(get_db),
):
    resp = await db_client.delete(f"/admin/answers/{answer_id}")
    if resp.status_code == 404:
        background_tasks.add_task(db_client.aclose)
        raise HTTPException(status_code=404, detail="Answer not found")
    resp.raise_for_status()
    background_tasks.add_task(db_client.aclose)
    return {"detail": "Answer deleted"}


@app.get("/admin/users", response_model=list[UserOut])
async def admin_get_users(
    background_tasks: BackgroundTasks,
    current_admin: dict = Depends(get_current_admin),
    db_client: httpx.AsyncClient = Depends(get_db),
):
    resp = await db_client.get("/admin/users")
    resp.raise_for_status()
    background_tasks.add_task(db_client.aclose)
    return resp.json()


@app.put("/admin/users/{user_id}/reset-progress", response_model=UserOut)
async def admin_reset_progress(
    user_id: int,
    background_tasks: BackgroundTasks,
    current_admin: dict = Depends(get_current_admin),
    db_client: httpx.AsyncClient = Depends(get_db),
):
    resp = await db_client.put(f"/admin/users/{user_id}/reset-progress")
    if resp.status_code == 404:
        background_tasks.add_task(db_client.aclose)
        raise HTTPException(status_code=404, detail="User not found")
    resp.raise_for_status()
    background_tasks.add_task(db_client.aclose)
    return resp.json()


@app.delete("/admin/users/{user_id}")
async def admin_delete_user(
    user_id: int,
    background_tasks: BackgroundTasks,
    current_admin: dict = Depends(get_current_admin),
    db_client: httpx.AsyncClient = Depends(get_db),
):
    resp = await db_client.delete(f"/admin/users/{user_id}")
    if resp.status_code == 404:
        background_tasks.add_task(db_client.aclose)
        raise HTTPException(status_code=404, detail="User not found")
    resp.raise_for_status()
    background_tasks.add_task(db_client.aclose)
    return {"detail": "User deleted"}


