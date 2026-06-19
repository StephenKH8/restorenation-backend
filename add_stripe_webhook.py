#!/usr/bin/env python3
"""
Patch script: adds the Stripe webhook endpoint to main.py.
Run from ~/restorenation-backend:  python3 add_stripe_webhook.py
Makes a backup at main.py.bak before editing. Idempotent-ish: refuses to
double-apply by checking for a marker string.
"""
import shutil
import sys

TARGET = "main.py"
MARKER = "# ----- STRIPE WEBHOOK (added by patch) -----"

with open(TARGET, "r") as f:
    src = f.read()

if MARKER in src:
    print("Webhook block already present — nothing to do.")
    sys.exit(0)

# --- 1. Add imports (after the existing 'import secrets' line) ---
assert "import secrets" in src, "Could not find 'import secrets' anchor in main.py"
src = src.replace(
    "import secrets",
    "import secrets\nimport os\nimport stripe",
    1,
)

# --- 2. Add the webhook block at the end of the file ---
WEBHOOK_BLOCK = '''

# ----- STRIPE WEBHOOK (added by patch) -----

# These are read from environment variables on Render (never hardcoded).
STRIPE_API_KEY = os.environ.get("STRIPE_API_KEY", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
stripe.api_key = STRIPE_API_KEY

# Map each Stripe price ID to how long it grants access.
# Fill these in during testing (Step 4) once we see the real price IDs.
# Keys are Stripe price IDs (look like "price_1AbC..."); values are days of access.
PRICE_DURATIONS = {
    # "price_xxx_monthly": 31,
    # "price_xxx_sixmonth": 184,
    # "price_xxx_annual": 366,
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
        email = cust.get("email")
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

    # Verify the event really came from Stripe.
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Webhook verification failed: {e}")

    etype = event["type"]
    obj = event["data"]["object"]

    if etype == "checkout.session.completed":
        email = (
            obj.get("customer_details", {}).get("email")
            or obj.get("customer_email")
        )
        # Figure out which plan they bought, to set the right duration.
        days = DEFAULT_DURATION_DAYS
        try:
            line_items = stripe.checkout.Session.list_line_items(obj["id"], limit=1)
            if line_items and line_items["data"]:
                price_id = line_items["data"][0]["price"]["id"]
                days = PRICE_DURATIONS.get(price_id, DEFAULT_DURATION_DAYS)
                print(f"[stripe] checkout price_id={price_id} -> {days} days")
        except Exception as e:
            print(f"[stripe] Could not read line items: {e}")

        if email:
            _activate_user(email, days, obj.get("customer"))

    elif etype in ("customer.subscription.deleted", "invoice.payment_failed"):
        customer_id = obj.get("customer")
        if customer_id:
            _deactivate_user_by_customer(customer_id)

    else:
        print(f"[stripe] Ignoring event type: {etype}")

    return {"received": True}
'''

src = src.rstrip() + WEBHOOK_BLOCK + "\n"

# --- 3. Make sure Request is imported from fastapi ---
if "from fastapi import" in src and "Request" not in src.split("from fastapi import")[1].split("\n")[0]:
    src = src.replace(
        "from fastapi import FastAPI, HTTPException",
        "from fastapi import FastAPI, HTTPException, Request",
        1,
    )

shutil.copy(TARGET, TARGET + ".bak")
with open(TARGET, "w") as f:
    f.write(src)

print("Patched main.py (backup at main.py.bak).")
print("New endpoint: POST /stripe-webhook")
