# ============================================
#  FULL DRILL APP (Updated strict COD parser)
# ============================================

import os
import re
import json
import sqlite3
from datetime import datetime

import requests
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, g, flash, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "fallback_secret_key_for_dev")

DATABASE = os.path.join(os.path.dirname(__file__), "orders.db")

MASTER_API_KEY = os.getenv("STEADFAST_API_KEY")
MASTER_SECRET_KEY = os.getenv("STEADFAST_SECRET_KEY")
MASTER_API_URL = os.getenv("STEADFAST_API_URL", "https://portal.packzy.com/api/v1")
MASTER_MERCHANT_ID = os.getenv("STEADFAST_MERCHANT_ID")


# ============================================
# DATABASE SETUP
# ============================================

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        need_init = not os.path.exists(DATABASE)
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
        if need_init:
            init_db(db)
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db(conn=None):
    close_conn = False
    if conn is None:
        conn = sqlite3.connect(DATABASE)
        close_conn = True
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            username TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            courier_api_key TEXT,
            courier_secret_key TEXT,
            courier_merchant_id TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message TEXT,
            status TEXT DEFAULT 'Pending',
            consignment_id TEXT,
            user_id INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    admin_email = os.getenv("DEFAULT_ADMIN_EMAIL", "admin@example.com")
    admin_password = os.getenv("DEFAULT_ADMIN_PASSWORD", "admin_secure_password")
    admin_username = os.getenv("DEFAULT_ADMIN_USERNAME", "Admin")

    c.execute("SELECT id FROM users WHERE email=?", (admin_email,))
    if not c.fetchone():
        hashed = generate_password_hash(admin_password)
        c.execute(
            "INSERT INTO users (email, password_hash, username, is_admin) VALUES (?, ?, ?, 1)",
            (admin_email, hashed, admin_username),
        )

    conn.commit()
    if close_conn:
        conn.close()


init_db()


# ============================================
#  UTILITIES + NEW STRICT PARSER
# ============================================

def bn_to_en_numbers(s: str) -> str:
    return s.translate(str.maketrans("০১২৩৪৫৬৭৮৯", "0123456789"))


def ultra_smart_parse(msg: str):
    """
    NEW STRICT RULE-BASED PARSER

    Rules:
    1) First line       → Name
    2) Until phone line → Address
    3) Phone line       → Phone number
    4) Last numeric     → COD amount
    """

    if not msg:
        return "Unknown", "Unknown", "", 0

    msg = bn_to_en_numbers(msg.strip())
    lines = [ln.strip() for ln in msg.split("\n") if ln.strip()]

    if len(lines) < 3:
        return "Unknown", "Unknown", "", 0

    # Name
    name = lines[0]

    phone_regex = re.compile(r"(?:\+?88)?(01[3-9]\d{8})")

    address_lines = []
    phone = ""
    cod = 0

    # Find phone & address
    i = 1
    while i < len(lines):
        line = lines[i]

        pm = phone_regex.search(line)
        if pm:
            phone = pm.group(1)
            break

        address_lines.append(line)
        i += 1

    # Last number anywhere in message = COD
    for line in reversed(lines):
        nums = re.findall(r"\d+", line)
        if nums:
            cod = int(nums[-1])
            break

    address = ", ".join(address_lines).strip()

    return name, address, phone, cod


# ============================================
#  COURIER API
# ============================================

def send_to_steadfast(payload: dict, api_url: str, api_key: str, secret_key: str, merchant_id: str = None, timeout: int = 20):
    headers = {
        "Api-Key": api_key,
        "Secret-Key": secret_key,
        "Content-Type": "application/json"
    }
    if merchant_id:
        payload["merchant_id"] = merchant_id

    try:
        url = api_url.rstrip("/") + "/create_order"
        resp = requests.post(url, headers=headers, json=payload, timeout=timeout)
    except Exception as e:
        return {"error": True, "message": f"Request exception: {e}"}

    if resp.status_code != 200:
        return {"error": True, "message": f"HTTP {resp.status_code}: {resp.text}"}

    try:
        return resp.json()
    except:
        return {"error": True, "message": "Invalid JSON", "raw": resp.text}


# ============================================
#  ROUTES
# ============================================

@app.route("/")
def home():
    if "user_id" not in session:
        return redirect(url_for("login"))
    db = get_db()
    c = db.cursor()
    uid = session["user_id"]
    c.execute("SELECT COUNT(*) FROM orders WHERE user_id=?", (uid,))
    total = c.fetchone()[0] or 0
    c.execute("SELECT COUNT(*) FROM orders WHERE status='Pending' AND user_id=?", (uid,))
    pending = c.fetchone()[0] or 0
    c.execute("SELECT COUNT(*) FROM orders WHERE status='Confirm' AND user_id=?", (uid,))
    confirm = c.fetchone()[0] or 0
    c.execute("SELECT COUNT(*) FROM orders WHERE status='Cancel' AND user_id=?", (uid,))
    cancel = c.fetchone()[0] or 0

    return render_template("home.html",
                           summary={"total": total, "pending": pending, "confirm": confirm, "cancel": cancel},
                           username=session.get("username"))


# ---------------- LOGIN ----------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        db = get_db()
        c = db.cursor()
        c.execute("SELECT id, password_hash, username, is_admin FROM users WHERE email=?", (email,))
        user = c.fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["is_admin"] = bool(user["is_admin"])
            return redirect(url_for("home"))

        flash("Invalid credentials.")

    return render_template("login.html")


# ---------------- REGISTER ----------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not email or not username or not password:
            flash("All fields required.")
            return render_template("register.html")

        db = get_db()
        c = db.cursor()
        c.execute("SELECT id FROM users WHERE email=?", (email,))
        if c.fetchone():
            flash("Email already registered.")
            return render_template("register.html")

        hashed = generate_password_hash(password)
        c.execute("INSERT INTO users (email, password_hash, username) VALUES (?, ?, ?)",
                  (email, hashed, username))
        db.commit()

        flash("Registration successful.")
        return redirect(url_for("login"))

    return render_template("register.html")


# ---------------- LOGOUT ----------------

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------- ENTRY ----------------

@app.route("/entry", methods=["GET", "POST"])
def entry():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        message = request.form.get("message", "").strip()

        if not message:
            flash("Invalid message.")
            return redirect(url_for("entry"))

        message = bn_to_en_numbers(message)

        db = get_db()
        c = db.cursor()
        c.execute("INSERT INTO orders (message, status, user_id) VALUES (?, 'Pending', ?)",
                  (message, session["user_id"]))
        db.commit()

        flash("Order added.")
        return redirect(url_for("status"))

    return render_template("entry.html")


# ---------------- EDIT ORDER ----------------

@app.route("/edit_order/<int:order_id>", methods=["GET", "POST"])
def edit_order(order_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_db()
    c = db.cursor()
    c.execute("SELECT * FROM orders WHERE id=? AND user_id=?", (order_id, session["user_id"]))
    order = c.fetchone()

    if not order:
        flash("Order not found.")
        return redirect(url_for("status"))

    if order["status"] == "Confirm":
        flash("Confirmed order cannot be edited.")
        return redirect(url_for("status"))

    if request.method == "POST":
        message = bn_to_en_numbers(request.form.get("message", "").strip())

        c.execute("UPDATE orders SET message=? WHERE id=?", (message, order_id))
        db.commit()

        flash("Order updated.")
        return redirect(url_for("status"))

    return render_template("edit_order.html", order=order)


# ---------------- ORDER LIST ----------------

@app.route("/status")
def status():
    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_db()
    c = db.cursor()
    c.execute("SELECT * FROM orders WHERE user_id=? ORDER BY id DESC", (session["user_id"],))
    orders = c.fetchall()

    return render_template("status.html", orders=orders)


# ---------------- UPDATE STATUS ----------------

@app.route("/update_status/<int:order_id>/<new_status>", methods=["POST"])
def update_status(order_id, new_status):
    if "user_id" not in session:
        return redirect(url_for("login"))

    if new_status not in ("Pending", "Confirm", "Cancel"):
        flash("Invalid status.")
        return redirect(url_for("status"))

    db = get_db()
    c = db.cursor()
    c.execute("SELECT * FROM orders WHERE id=? AND user_id=?", (order_id, session["user_id"]))
    order = c.fetchone()

    if not order:
        flash("Order not found.")
        return redirect(url_for("status"))

    if new_status == "Confirm":
        name, address, phone, cod = ultra_smart_parse(order["message"])

        invoice = f"{session['user_id']}-{order_id}-{int(datetime.utcnow().timestamp())}"

        payload = {
            "invoice": invoice,
            "recipient_name": name,
            "recipient_phone": phone or "01700000000",
            "recipient_address": address,
            "cod_amount": float(cod),
            "note": f"Order {order_id}"
        }

        c.execute("SELECT courier_api_key, courier_secret_key, courier_merchant_id FROM users WHERE id=?", (session["user_id"],))
        u = c.fetchone()

        api_key = u["courier_api_key"] if u["courier_api_key"] else MASTER_API_KEY
        secret_key = u["courier_secret_key"] if u["courier_secret_key"] else MASTER_SECRET_KEY
        merchant_id = u["courier_merchant_id"] if u["courier_merchant_id"] else MASTER_MERCHANT_ID

        resp = send_to_steadfast(payload, MASTER_API_URL, api_key, secret_key, merchant_id)

        if resp.get("error"):
            flash(f"Courier error: {resp['message']}")
            return redirect(url_for("status"))

        if resp.get("status") == 200 and resp.get("consignment"):
            cons_id = resp["consignment"].get("consignment_id")
            c.execute("UPDATE orders SET status='Confirm', consignment_id=? WHERE id=?", (cons_id, order_id))
            db.commit()

            flash(f"Sent to courier. Consignment: {cons_id}")
        else:
            flash("Unexpected courier response.")
        return redirect(url_for("status"))

    c.execute("UPDATE orders SET status=? WHERE id=?", (new_status, order_id))
    db.commit()

    flash(f"Order updated to {new_status}.")
    return redirect(url_for("status"))


# ---------------- TRACK ONE ----------------

@app.route("/track_order/<int:order_id>")
def track_order(order_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_db()
    c = db.cursor()
    c.execute("SELECT consignment_id FROM orders WHERE id=? AND user_id=?", (order_id, session["user_id"]))
    row = c.fetchone()

    if not row or not row["consignment_id"]:
        flash("This order has no consignment ID.")
        return redirect(url_for("status"))

    cid = row["consignment_id"]

    headers = {
        "Api-Key": MASTER_API_KEY,
        "Secret-Key": MASTER_SECRET_KEY,
        "Content-Type": "application/json"
    }

    try:
        r = requests.get(f"{MASTER_API_URL}/status_by_cid/{cid}", headers=headers, timeout=20)
        data = r.json()
        status = data.get("delivery_status", "Unknown")
    except:
        flash("Tracking error.")

    return render_template("track_order.html", consignment_id=cid, delivery_status=status)


# ---------------- TRACK ALL ----------------

@app.route("/track_all")
def track_all():
    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_db()
    c = db.cursor()
    c.execute("SELECT consignment_id FROM orders WHERE user_id=? AND consignment_id IS NOT NULL", (session["user_id"],))
    rows = c.fetchall()

    results = []
    headers = {
        "Api-Key": MASTER_API_KEY,
        "Secret-Key": MASTER_SECRET_KEY,
        "Content-Type": "application/json"
    }

    for r in rows:
        cid = r["consignment_id"]
        try:
            res = requests.get(f"{MASTER_API_URL}/status_by_cid/{cid}", headers=headers, timeout=10)
            if res.status_code == 200:
                results.append({"consignment_id": cid, "status": res.json().get("delivery_status", "Unknown")})
            else:
                results.append({"consignment_id": cid, "status": "Error"})
        except:
            results.append({"consignment_id": cid, "status": "Error"})

    return render_template("track_all.html", results=results)


# ---------------- ADMIN PANEL ----------------

@app.route("/admin/users")
def admin_users():
    if "user_id" not in session or not session.get("is_admin"):
        flash("Access denied.")
        return redirect(url_for("login"))

    db = get_db()
    c = db.cursor()
    c.execute("SELECT id, email, username, is_admin FROM users ORDER BY id ASC")
    users = c.fetchall()

    return render_template("admin_users.html", users=users)


@app.route("/admin/users/add", methods=["POST"])
def add_user():
    if "user_id" not in session or not session.get("is_admin"):
        flash("Access denied.")
        return redirect(url_for("login"))

    email = request.form.get("email", "").strip().lower()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    is_admin = 1 if request.form.get("is_admin") == "on" else 0

    if not email or not username or not password:
        flash("All fields required.")
        return redirect(url_for("admin_users"))

    db = get_db()
    c = db.cursor()

    c.execute("SELECT id FROM users WHERE email=?", (email,))
    if c.fetchone():
        flash("Email already exists.")
        return redirect(url_for("admin_users"))

    hashed = generate_password_hash(password)
    c.execute("INSERT INTO users (email, password_hash, username, is_admin) VALUES (?, ?, ?, ?)",
              (email, hashed, username, is_admin))
    db.commit()

    flash("User added.")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/reset/<int:user_id>", methods=["POST"])
def reset_user_password(user_id):
    if "user_id" not in session or not session.get("is_admin"):
        flash("Access denied.")
        return redirect(url_for("login"))

    new_pw = request.form.get("new_password", "drill123")
    hashed = generate_password_hash(new_pw)

    db = get_db()
    c = db.cursor()
    c.execute("UPDATE users SET password_hash=? WHERE id=?", (hashed, user_id))
    db.commit()

    flash("Password reset.")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/delete/<int:user_id>", methods=["POST"])
def delete_user(user_id):
    if "user_id" not in session or not session.get("is_admin"):
        flash("Access denied.")
        return redirect(url_for("login"))

    db = get_db()
    c = db.cursor()
    c.execute("DELETE FROM users WHERE id=?", (user_id,))
    db.commit()

    flash("User deleted.")
    return redirect(url_for("admin_users"))


# ============================================
# API PARSE TEST
# ============================================

@app.route("/api/parse", methods=["POST"])
def api_parse():
    data = request.get_json(force=True, silent=True) or {}
    msg = data.get("message", "")
    name, address, phone, cod = ultra_smart_parse(msg)
    return jsonify({"name": name, "address": address, "phone": phone, "cod_amount": cod})


# ============================================
# RUN
# ============================================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=True)
