import sqlite3
import secrets
import random
from datetime import datetime, timedelta, timezone
from contextlib import contextmanager

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr

app = FastAPI()

DB_PATH = "users.db"


# ---------- Database setup ----------

@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                email TEXT PRIMARY KEY,
                subscription_status TEXT DEFAULT 'inactive',
                valid_until TEXT,
                login_code TEXT,
                code_expires_at TEXT,
                token TEXT
            )
        """)


init_db()


# ---------- Request/response shapes ----------

class EmailRequest(BaseModel):
    email: EmailStr


class VerifyRequest(BaseModel):
    email: EmailStr
    code: str


class TokenRequest(BaseModel):
    token: str


# ---------- Helpers ----------

def now_utc():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.isoformat()


# ---------- Endpoints ----------

@app.get("/")
def root():
    return {"status": "ok", "service": "restorenation-backend"}


@app.get("/health")
def health():
    return {"healthy": True}


@app.post("/request-login-code")
def request_login_code(req: EmailRequest):
    code = f"{random.randint(0, 999999):06d}"
    expires = now_utc() + timedelta(minutes=10)

    with get_db() as conn:
        existing = conn.execute(
            "SELECT email FROM users WHERE email = ?", (req.email,)
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE users SET login_code = ?, code_expires_at = ? WHERE email = ?",
                (code, iso(expires), req.email),
            )
        else:
            conn.execute(
                "INSERT INTO users (email, login_code, code_expires_at) VALUES (?, ?, ?)",
                (req.email, code, iso(expires)),
            )

    # For now we RETURN the code so we can test without email.
    # In Phase 3 this becomes an email send and we stop returning it.
    return {"message": "Login code generated", "code_for_testing": code}


@app.post("/verify-code")
def verify_code(req: VerifyRequest):
    with get_db() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE email = ?", (req.email,)
        ).fetchone()

        if not user or not user["login_code"]:
            raise HTTPException(status_code=400, detail="No login code requested for this email")

        if user["login_code"] != req.code:
            raise HTTPException(status_code=400, detail="Incorrect code")

        expires_at = datetime.fromisoformat(user["code_expires_at"])
        if now_utc() > expires_at:
            raise HTTPException(status_code=400, detail="Code expired, request a new one")

        token = secrets.token_urlsafe(32)
        conn.execute(
            "UPDATE users SET token = ?, login_code = NULL, code_expires_at = NULL WHERE email = ?",
            (token, req.email),
        )

    return {
        "message": "Login successful",
        "token": token,
        "subscription_status": user["subscription_status"],
        "valid_until": user["valid_until"],
    }


@app.post("/check-subscription")
def check_subscription(req: TokenRequest):
    with get_db() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE token = ?", (req.token,)
        ).fetchone()

        if not user:
            raise HTTPException(status_code=401, detail="Invalid or expired login")

    active = user["subscription_status"] == "active"
    return {
        "email": user["email"],
        "subscription_status": user["subscription_status"],
        "valid_until": user["valid_until"],
        "active": active,
    }
