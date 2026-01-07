# schemas.py
# Pydantic‑схемы: описывают, какой JSON отправляем на клиент и принимаем от него

from pydantic import BaseModel

# ---------- Ответы ----------

class AnswerOut(BaseModel):
    answer_id: int
    answer: str
    is_good: int

    class Config:
        from_attributes = True # позволяет возвращать модели SQLAlchemy напрямую


class QuestionOut(BaseModel):
    question_id: int
    question: str
    # список вариантов ответов для вопроса
    answers: list[AnswerOut]

    class Config:
        from_attributes = True


class LevelOut(BaseModel):
    level_id: int
    level_name: str

    class Config:
        from_attributes = True


# ---------- Логин админа ----------

class AdminLoginIn(BaseModel):
    login: str
    password: str

# --- Levels CRUD ---

class LevelCreate(BaseModel):
    level_name: str


class LevelUpdate(BaseModel):
    level_name: str

class AdminLevelOut(BaseModel):
    level_id: int
    level_name: str
    questions_count: int

# --- Questions / Answers CRUD ---

class QuestionCreate(BaseModel):
    level_id: int
    question: str


class QuestionUpdate(BaseModel):
    question: str


class AnswerCreate(BaseModel):
    question_id: int
    answer: str
    is_good: int  # 0 или 1


class AnswerUpdate(BaseModel):
    answer: str
    is_good: int


# --- Users (логины) ---

class UserOut(BaseModel):
    user_id: int
    login: str
    progress: int

    class Config:
        from_attributes = True


class UserBase(BaseModel):
    login: str

class UserCreate(UserBase):
    password: str

class UserUpdate(BaseModel):
    login: str | None = None
    password: str | None = None

class UserOut(BaseModel):
    user_id: int
    login: str
    password: str
    progress: int

    class Config:
        from_attributes = True


class UserLoginIn(BaseModel):
    login: str
    password: str


class UserChangePasswordIn(BaseModel):
    old_password: str
    new_password: str


class UserChangeLoginIn(BaseModel):
    new_login: str
    password: str


class UserResetPasswordIn(BaseModel):
    login: str
    code: str
    new_password: str



class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
