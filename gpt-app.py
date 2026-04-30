# ENT Monitor v3 — Final Stable Version

import subprocess, platform, threading, time, sqlite3
import os, re, secrets, shutil
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, jsonify, request, send_from_directory, session
from flask_cors import CORS
import bcrypt

# ── Config ─────────────────────────────────────────────────────────
DB_PATH        = "ent_monitor.db"
PING_INTERVAL  = 10   # safer interval
PING_TIMEOUT   = 2
PING_COUNT     = 1
HISTORY_LIMIT  = 100
SESSION_HOURS  = 8

FPING_BIN = shutil.which("fping")

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__, static_folder=_BASE_DIR)
app.secret_key = "change-this-secret-key"   # stable key
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=SESSION_HOURS)

CORS(app, supports_credentials=True)

# ── DB ─────────────────────────────────────────────────────────────
def get_db():
    db = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    db = get_db()
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT
    );
    CREATE TABLE IF NOT EXISTS customers (
        ip TEXT PRIMARY KEY,
        name TEXT
    );
    CREATE TABLE IF NOT EXISTS ping_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        status TEXT,
        latency_ms REAL,
        checked_at TEXT DEFAULT (datetime('now'))
    );
    """)
    db.commit()

    if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        db.execute("INSERT INTO users VALUES (1,'admin',?, 'admin')",
                   (bcrypt.hashpw(b"Admin@123", bcrypt.gensalt()).decode(),))
        db.commit()
    db.close()

# ── Auth ───────────────────────────────────────────────────────────
def require_login(f):
    @wraps(f)
    def wrapper(*a, **k):
        if not session.get("user"):
            return jsonify({"error":"unauthorized"}), 401
        return f(*a, **k)
    return wrapper

@app.route("/")
def index():
    return send_from_directory(_BASE_DIR, "dashboard.html")

@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    db = get_db()
    u = db.execute("SELECT * FROM users WHERE username=?",
                   (data["username"],)).fetchone()
    db.close()
    if not u or not bcrypt.checkpw(data["password"].encode(), u["password"].encode()):
        return jsonify({"error":"invalid"}), 401

    session["user"] = u["username"]
    return jsonify({"ok":True})

# ── Ping Engines ───────────────────────────────────────────────────
def system_ping(ip):
    try:
        result = subprocess.run(
            ["ping","-c","1","-W",str(PING_TIMEOUT),ip],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            return {"status":"online","latency_ms":1}
        return {"status":"offline","latency_ms":None}
    except:
        return {"status":"offline","latency_ms":None}

def fping_bulk(ips):
    if not FPING_BIN:
        return {ip: system_ping(ip) for ip in ips}

    cmd = [
        FPING_BIN,
        "-c", str(PING_COUNT),
        "-t", str(PING_TIMEOUT * 1000),
        "-p", str(PING_INTERVAL * 1000),
        "-q",
        "-A"
    ] + ips

    try:
        res = subprocess.run(cmd, capture_output=True, text=True)
        out = res.stderr + res.stdout
        results = {}

        for line in out.splitlines():
            m = re.match(r"^(\d+\.\d+\.\d+\.\d+)", line)
            if not m: continue
            ip = m.group(1)

            loss = int(re.search(r"(\d+)%", line).group(1))
            lat  = re.search(r"/([\d.]+)/", line)
            lat  = float(lat.group(1)) if lat else None

            results[ip] = {
                "status": "offline" if loss >= 50 else "online",
                "latency_ms": lat
            }

        return results
    except:
        return {ip: {"status":"offline"} for ip in ips}

# ── Sweep ──────────────────────────────────────────────────────────
_sweep_active = False

def save_ping(ip, status, latency):
    db = get_db()
    db.execute("INSERT INTO ping_results(ip,status,latency_ms) VALUES (?,?,?)",
               (ip,status,latency))
    db.commit()
    db.close()

def run_sweep():
    global _sweep_active  
    print("[sweep] started")

    while _sweep_active:
        try:
            db = get_db()
            rows = db.execute("SELECT ip FROM customers").fetchall()
            db.close()

            ips = [r["ip"] for r in rows]
            if not ips:
                time.sleep(PING_INTERVAL)
                continue

            results = fping_bulk(ips)

            for ip, r in results.items():
                save_ping(ip, r["status"], r.get("latency_ms"))

            print(f"[sweep] {len(ips)} IPs checked")

        except Exception as e:
            print("[sweep error]", e)

        time.sleep(PING_INTERVAL)

# ── API ────────────────────────────────────────────────────────────
@app.route("/api/customers", methods=["POST"])
@require_login
def add_customer():
    data = request.json
    db = get_db()
    db.execute("INSERT OR IGNORE INTO customers VALUES (?,?)",
               (data["ip"], data["name"]))
    db.commit()
    db.close()
    return jsonify({"ok":True})

@app.route("/api/stats")
@require_login
def stats():
    db = get_db()
    rows = db.execute("""
        SELECT ip,
        (SELECT status FROM ping_results p WHERE p.ip=c.ip ORDER BY id DESC LIMIT 1) as status
        FROM customers c
    """).fetchall()
    db.close()

    online = sum(1 for r in rows if r["status"]=="online")
    return jsonify({
        "total": len(rows),
        "online": online,
        "offline": len(rows)-online
    })

# ── MAIN ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("="*50)
    print("ENT Monitor Final")
    print("="*50)

    init_db()

    ## global _sweep_active  // for now manual keep it comment
    _sweep_active = True

    t = threading.Thread(target=run_sweep, daemon=True)
    t.start()

    print("[fping]", "OK" if FPING_BIN else "NOT INSTALLED")
    print("[server] http://0.0.0.0:5000")

    app.run(host="0.0.0.0", port=5000, threaded=True)