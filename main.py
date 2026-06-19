import sqlite3
import secrets
import os
import stripe
import traceback
import random
from datetime import datetime, timedelta, timezone
from contextlib import contextmanager

from fastapi import FastAPI, HTTPException, Request
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

# ----- STRIPE WEBHOOK (added by patch) -----

# These are read from environment variables on Render (never hardcoded).
STRIPE_API_KEY = os.environ.get("STRIPE_API_KEY", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
stripe.api_key = STRIPE_API_KEY

# Map each Stripe price ID to how long it grants access.
# Fill these in during testing (Step 4) once we see the real price IDs.
# Keys are Stripe price IDs (look like "price_1AbC..."); values are days of access.
PRICE_DURATIONS = {
    "price_1TjPAXRs7Dym1YeRCsTgtXQW": 31,   # Monthly  ($19.99/mo)
    "price_1TjPBbRs7Dym1YeRmq9Ua5TE": 190,  # 6-Months ($119.99/6mo)
    "price_1TjPCyRs7Dym1YeRUy1j6CjL": 370,  # 1 Year   ($199.99/yr)
}
DEFAULT_DURATION_DAYS = 31  # fallback if a price ID isn't in the map yet


def _activate_user(email, days, stripe_customer_id=None):
    """Mark a user active and set valid_until = now + days."""
    valid_until = now_utc() + timedelta(days=days)
    with get_db() as conn:
        existing = conn.execute(
            "SELECT email FROM users WHERE email = ?", (email,)
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE users SET subscription_status = 'active', valid_until = ? WHERE email = ?",
                (iso(valid_until), email),
            )
        else:
            conn.execute(
                "INSERT INTO users (email, subscription_status, valid_until) VALUES (?, 'active', ?)",
                (email, iso(valid_until)),
            )
    print(f"[stripe] Activated {email} until {iso(valid_until)}")


def _deactivate_user_by_customer(stripe_customer_id):
    """Mark inactive by Stripe customer ID (used on cancel / payment failure)."""
    # We look the customer's email up from Stripe, then deactivate by email.
    try:
        cust = stripe.Customer.retrieve(stripe_customer_id)
        cust_dict = cust.to_dict() if hasattr(cust, "to_dict") else cust
        email = cust_dict.get("email")
    except Exception as e:
        print(f"[stripe] Could not retrieve customer {stripe_customer_id}: {e}")
        return
    if not email:
        return
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET subscription_status = 'inactive' WHERE email = ?",
            (email,),
        )
    print(f"[stripe] Deactivated {email}")


@app.post("/stripe-webhook")
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except Exception as e:
        print(f"[stripe] SIGNATURE verification failed: {e}")
        raise HTTPException(status_code=400, detail=f"Webhook verification failed: {e}")

    try:
        etype = event["type"]
        # Convert the Stripe object to a plain dict so .get() works normally.
        raw_obj = event["data"]["object"]
        # Stripe objects -> plain nested dict (the correct, supported way)
        if hasattr(raw_obj, "to_dict_recursive"):
            obj = raw_obj.to_dict_recursive()
        elif hasattr(raw_obj, "to_dict"):
            obj = raw_obj.to_dict()
        else:
            obj = dict(raw_obj)
        print(f"[stripe] received event: {etype}")

        if etype == "checkout.session.completed":
            cust_details = obj.get("customer_details") or {}
            if not isinstance(cust_details, dict):
                cust_details = dict(cust_details)
            email = cust_details.get("email") or obj.get("customer_email")
            print(f"[stripe] checkout email resolved to: {email}")

            days = DEFAULT_DURATION_DAYS
            try:
                session_id = obj.get("id")
                line_items = stripe.checkout.Session.list_line_items(session_id, limit=1)
                li_dict = line_items.to_dict() if hasattr(line_items, "to_dict") else line_items
                data = li_dict.get("data") or []
                if data:
                    price = (data[0] or {}).get("price") or {}
                    price_id = price.get("id")
                    days = PRICE_DURATIONS.get(price_id, DEFAULT_DURATION_DAYS)
                    print(f"[stripe] price_id={price_id} -> {days} days")
            except Exception as e:
                print(f"[stripe] could not read line items (using default {days}d): {e}")

            if email:
                _activate_user(email, days, obj.get("customer"))
            else:
                print("[stripe] no email on event; nothing activated")

        elif etype in ("customer.subscription.deleted", "invoice.payment_failed"):
            customer_id = obj.get("customer")
            if customer_id:
                _deactivate_user_by_customer(customer_id)

        else:
            print(f"[stripe] ignoring event type: {etype}")

    except Exception:
        print("[stripe] HANDLER ERROR (returning 200 so Stripe stops retrying):")
        traceback.print_exc()

    return {"received": True}
