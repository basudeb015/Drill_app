from flask import Flask, render_template, request, redirect, url_for, session, g, flash
import sqlite3, requests, os, json, re
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

# Optional HTTPS security (auto-handles local mode)
try:
    from flask_talisman import Talisman
    TALISMAN_AVAILABLE = True
except ImportError:
    TALISMAN_AVAILABLE = False

load_dotenv()

app = Flask(__name__)
if TALISMAN_AVAILABLE and os.getenv("RENDER") == "true":
    Talisman(app, content_security_policy=None)

app.secret_key = os.getenv("FLASK_SECRET_KEY", "fallback_secret_key")

DATABASE = 'orders.db'

# Master fallback courier credentials
MASTER_API_KEY = os.getenv("STEADFAST_API_KEY")
MASTER_SECRET_KEY = os.getenv("STEADFAST_SECRET_KEY")
MASTER_API_URL = os.getenv("STEADFAST_API_URL", "https://portal.packzy.com/api/v1")
MASTER_MERCHANT_ID = os.getenv("STEADFAST_MERCHANT_ID")

# ---------------- Helper Functions ----------------

def bn_to_en_numbers(text):
    """Convert Bangla digits to English digits."""
    if not text:
        return text
    bn = "০১২৩৪৫৬৭৮৯"
    en = "0123456789"
    return text.translate(str.maketrans(bn, en))

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        if not os.path.exists(DATABASE):
            init_db()
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    username TEXT NOT NULL,
                    is_admin INTEGER DEFAULT 0,
                    courier_api_key TEXT,
                    courier_secret_key TEXT,
                    courier_merchant_id TEXT
                )''')

    c.execute('''CREATE TABLE IF NOT EXISTS orders (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    message TEXT,
                    status TEXT DEFAULT 'Pending',
                    consignment_id TEXT,
                    tracking_code TEXT,
                    user_id INTEGER,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )''')

    c.execute("SELECT * FROM users WHERE email='admin@example.com'")
    if not c.fetchone():
        hashed = generate_password_hash('admin_secure_password')
        c.execute("INSERT INTO users (email, password_hash, username, is_admin) VALUES (?, ?, ?, ?)",
                  ('admin@example.com', hashed, 'bobo guys', 1))

    conn.commit()
    conn.close()

init_db()

# ---------------- Steadfast API ----------------

def send_to_steadfast(name, phone, address, invoice_id, cod_amount,
                      api_url, api_key, secret_key, merchant_id, note="From App"):
    headers = {
        "Api-Key": api_key,
        "Secret-Key": secret_key,
        "Content-Type": "application/json"
    }
    payload = {
        "invoice": invoice_id,
        "recipient_name": name,
        "recipient_phone": phone,
        "recipient_address": address,
        "cod_amount": float(cod_amount or 0),
        "note": note
    }
    if merchant_id:
        payload["merchant_id"] = merchant_id

    try:
        resp = requests.post(api_url.rstrip("/") + "/create_order",
                             headers=headers, data=json.dumps(payload), timeout=20)
        # Handle non-JSON responses gracefully
        if resp.status_code != 200:
            return {
                "error": True,
                "message": f"HTTP {resp.status_code}: {resp.text[:200]}"
            }
        try:
            return resp.json()
        except json.JSONDecodeError:
            return {
                "error": True,
                "message": f"Non-JSON response: {resp.text[:200]}"
            }
    except Exception as e:
        return {"error": True, "message": str(e)}


# ---------------- Routes ----------------

@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    c = conn.cursor()
    uid = session['user_id']
    c.execute("SELECT COUNT(*) FROM orders WHERE user_id=?", (uid,))
    total = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM orders WHERE status='Pending' AND user_id=?", (uid,))
    pending = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM orders WHERE status='Confirm' AND user_id=?", (uid,))
    confirm = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM orders WHERE status='Cancel' AND user_id=?", (uid,))
    cancel = c.fetchone()[0]
    summary = {'total': total, 'pending': pending, 'confirm': confirm, 'cancel': cancel}
    return render_template('home.html', summary=summary, username=session['username'])

# ---------- Auth ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT id, password_hash, username, is_admin FROM users WHERE email=?", (email,))
        user = c.fetchone()
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = bool(user['is_admin'])
            return redirect(url_for('home'))
        flash("Invalid credentials")
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        username = request.form['username']
        courier_api_key = request.form.get('courier_api_key') or None
        courier_secret_key = request.form.get('courier_secret_key') or None
        courier_merchant_id = request.form.get('courier_merchant_id') or None

        hashed = generate_password_hash(password)
        conn = get_db()
        c = conn.cursor()
        try:
            c.execute("""INSERT INTO users 
                         (email, password_hash, username, courier_api_key, courier_secret_key, courier_merchant_id)
                         VALUES (?, ?, ?, ?, ?, ?)""",
                      (email, hashed, username, courier_api_key, courier_secret_key, courier_merchant_id))
            conn.commit()
            flash("Registration successful!")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Email already registered.")
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully!")
    return redirect(url_for('login'))

# ---------- Orders ----------
@app.route('/entry', methods=['GET', 'POST'])
def entry():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        message = bn_to_en_numbers(request.form['message'].strip())
        conn = get_db()
        c = conn.cursor()
        c.execute("INSERT INTO orders (message, status, user_id) VALUES (?, ?, ?)",
                  (message, 'Pending', session['user_id']))
        conn.commit()
        flash("Order added successfully!")
        return redirect(url_for('status'))
    return render_template('entry.html')

@app.route('/status')
def status():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM orders WHERE user_id=? ORDER BY id DESC", (session['user_id'],))
    orders = c.fetchall()
    return render_template('status.html', orders=orders)

@app.route('/edit_order/<int:order_id>', methods=['GET', 'POST'])
def edit_order(order_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM orders WHERE id=? AND user_id=?", (order_id, session['user_id']))
    order = c.fetchone()
    if not order:
        flash("Order not found.")
        return redirect(url_for('status'))
    if order['status'] == 'Confirm':
        flash("Confirmed orders can't be edited.")
        return redirect(url_for('status'))

    if request.method == 'POST':
        message = bn_to_en_numbers(request.form['message'].strip())
        c.execute("UPDATE orders SET message=? WHERE id=? AND user_id=?", (message, order_id, session['user_id']))
        conn.commit()
        flash("Order updated successfully!")
        return redirect(url_for('status'))
    return render_template('edit_order.html', order=order)

# ---------- Confirm (Send to Courier) ----------
@app.route('/update_status/<int:order_id>/<new_status>', methods=['POST'])
def update_status(order_id, new_status):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM orders WHERE id=? AND user_id=?", (order_id, session['user_id']))
    order = c.fetchone()
    if not order:
        flash("Order not found.")
        return redirect(url_for('status'))

    if new_status == 'Confirm':
        message = order['message']
        lines = [ln.strip() for ln in message.splitlines() if ln.strip()]
        name = lines[0] if len(lines) > 0 else "Customer"
        full = " ".join(lines)
        phone = re.search(r'01[3-9]\d{8}', full)
        cod = re.findall(r'\d{2,6}', full)
        cod_amount = cod[-1] if cod else "0"
        phone_number = phone.group() if phone else "01700000000"
        address = " ".join(lines[1:])
        address = re.sub(r'01[3-9]\d{8}', '', address).strip()[:250]

        c.execute("SELECT courier_api_key, courier_secret_key, courier_merchant_id, username FROM users WHERE id=?",
                  (session['user_id'],))
        u = c.fetchone()
        api_key = u['courier_api_key'] or MASTER_API_KEY
        secret_key = u['courier_secret_key'] or MASTER_SECRET_KEY
        merchant_id = u['courier_merchant_id'] or MASTER_MERCHANT_ID
        username = u['username']

        invoice = f"{session['user_id']}-{order_id}"
        note = f"Sent by {username}"
        resp = send_to_steadfast(name, phone_number, address, invoice, cod_amount,
                                 MASTER_API_URL, api_key, secret_key, merchant_id, note)

        if resp.get("status") == 200:
            cons = resp.get("consignment", {})
            cons_id = str(cons.get("consignment_id", ""))
            track = cons.get("tracking_code", "")
            c.execute("UPDATE orders SET status=?, consignment_id=?, tracking_code=? WHERE id=?",
                      ('Confirm', cons_id, track, order_id))
            conn.commit()
            flash(f"✅ Sent to courier (Consignment ID: {cons_id})")
        else:
            flash(f"⚠️ Failed to send: {resp.get('message', str(resp))}")
    else:
        c.execute("UPDATE orders SET status=? WHERE id=? AND user_id=?", (new_status, order_id, session['user_id']))
        conn.commit()
        flash(f"Order marked {new_status}")

    conn.close()
    return redirect(url_for('status'))
# ---------- Track All Orders ----------
@app.route('/track_all')
def track_all():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT consignment_id, tracking_code, status FROM orders WHERE user_id=? AND consignment_id IS NOT NULL", (session['user_id'],))
    orders = c.fetchall()

    if not orders:
        flash("No orders with consignment IDs to track.")
        return redirect(url_for('status'))

    results = []
    for o in orders:
        if not o['consignment_id']:
            continue
        try:
            headers = {
                "Api-Key": MASTER_API_KEY,
                "Secret-Key": MASTER_SECRET_KEY,
                "Content-Type": "application/json"
            }
            url = f"{MASTER_API_URL}/status_by_cid/{o['consignment_id']}"
            resp = requests.get(url, headers=headers, timeout=20)
            data = resp.json()
            delivery_status = data.get("delivery_status", "Unknown")
            results.append({
                "consignment_id": o["consignment_id"],
                "tracking_code": o["tracking_code"],
                "status": delivery_status
            })
        except Exception as e:
            results.append({
                "consignment_id": o["consignment_id"],
                "tracking_code": o["tracking_code"],
                "status": f"Error: {str(e)}"
            })

    return render_template('track_all.html', results=results)
# ---------- Track Single Order ----------
@app.route('/track_order/<int:order_id>')
def track_order(order_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT consignment_id, tracking_code FROM orders WHERE id=? AND user_id=?", (order_id, session['user_id']))
    order = c.fetchone()

    if not order or not order['consignment_id']:
        flash("This order does not have a consignment ID yet.")
        return redirect(url_for('status'))

    consignment_id = order['consignment_id']

    try:
        headers = {
            "Api-Key": MASTER_API_KEY,
            "Secret-Key": MASTER_SECRET_KEY,
            "Content-Type": "application/json"
        }
        url = f"{MASTER_API_URL}/status_by_cid/{consignment_id}"
        resp = requests.get(url, headers=headers, timeout=20)
        if resp.status_code != 200:
            flash(f"Failed to fetch status: HTTP {resp.status_code}")
            return redirect(url_for('status'))

        data = resp.json()
        delivery_status = data.get("delivery_status", "Unknown")
        return render_template("track_order.html",
                               consignment_id=consignment_id,
                               tracking_code=order["tracking_code"],
                               delivery_status=delivery_status)
    except Exception as e:
        flash(f"Error: {e}")
        return redirect(url_for('status'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
