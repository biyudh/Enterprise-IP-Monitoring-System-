"""
ENT Monitor v3 — Backend API with Auth + Full CRUD
====================================================
Features:
  - User authentication (session-based, bcrypt hashed passwords)
  - Role-based access: admin (full access) | operator (view + ping only)
  - Real ICMP ping engine with threading
  - SQLite database: users, customers, ping_results
  - Full customer CRUD: add, edit, delete, bulk import
  - Audit log: every data change is recorded

Install:
    pip install flask flask-cors bcrypt

Run:
    python app.py

Default accounts (change after first login!):
    admin    / Admin@123   (role: admin)
    operator / Oper@123    (role: operator)
"""

import subprocess, platform, threading, time, sqlite3
import json, os, re, secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, jsonify, request, send_from_directory, session
from flask_cors import CORS
import bcrypt

import shutil
FPING_BIN = shutil.which("fping")

# ── Config ────────────────────────────────────────────────────────────────────
DB_PATH        = "ent_monitor.db"
PING_INTERVAL  = 5      # seconds between full sweeps
PING_TIMEOUT   = 2      # seconds per ping
FPING_COUNT    = 3      # number of probes per IP
FPING_INTERVAL = 50     # ms between probes to same host
HISTORY_LIMIT  = 100
SESSION_HOURS  = 8

_BASE_DIR      = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__, static_folder=_BASE_DIR)
app.secret_key = secrets.token_hex(32)   # re-generated each restart (sessions invalidated on restart)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=SESSION_HOURS)
CORS(app, supports_credentials=True, origins="*")

# ── Database ──────────────────────────────────────────────────────────────────
def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db

def init_db():
    db = get_db()
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        username   TEXT UNIQUE NOT NULL,
        password   TEXT NOT NULL,
        role       TEXT NOT NULL DEFAULT 'operator',  -- admin | operator
        full_name  TEXT,
        email      TEXT,
        active     INTEGER NOT NULL DEFAULT 1,
        created_at TEXT DEFAULT (datetime('now')),
        last_login TEXT
    );

    CREATE TABLE IF NOT EXISTS customers (
        ip         TEXT PRIMARY KEY,
        name       TEXT NOT NULL,
        subnet     TEXT,
        location   TEXT,
        contact    TEXT,
        notes      TEXT,
        active     INTEGER NOT NULL DEFAULT 1,
        added_by   TEXT,
        added_at   TEXT DEFAULT (datetime('now')),
        updated_at TEXT
    );

    CREATE TABLE IF NOT EXISTS ping_results (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        ip         TEXT NOT NULL,
        status     TEXT NOT NULL,
        latency_ms REAL,
        checked_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (ip) REFERENCES customers(ip) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS audit_log (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        username   TEXT NOT NULL,
        action     TEXT NOT NULL,
        target     TEXT,
        detail     TEXT,
        ip_addr    TEXT,
        ts         TEXT DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_ping_ip  ON ping_results(ip);
    CREATE INDEX IF NOT EXISTS idx_ping_ts  ON ping_results(checked_at);
    CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
    """)
    db.commit()

    # Seed default users if none exist
    cur = db.execute("SELECT COUNT(*) AS n FROM users")
    if cur.fetchone()["n"] == 0:
        for uname, pw, role, fname in [
            ("admin",    "Admin@123",  "admin",    "System Administrator"),
            ("operator", "Oper@123",   "operator", "NOC Operator"),
        ]:
            hashed = bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
            db.execute(
                "INSERT INTO users (username, password, role, full_name) VALUES (?,?,?,?)",
                (uname, hashed, role, fname)
            )
        db.commit()
        print("[init] Default users created: admin / Admin@123  |  operator / Oper@123")
    db.close()

# ── Auth helpers ──────────────────────────────────────────────────────────────
def log_action(username, action, target=None, detail=None):
    db = get_db()
    db.execute(
        "INSERT INTO audit_log (username, action, target, detail, ip_addr) VALUES (?,?,?,?,?)",
        (username, action, target, detail, request.remote_addr)
    )
    db.commit()
    db.close()

def require_login(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user"):
            return jsonify({"error": "Unauthorized", "code": 401}), 401
        return f(*args, **kwargs)
    return decorated

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user"):
            return jsonify({"error": "Unauthorized", "code": 401}), 401
        if session.get("role") != "admin":
            return jsonify({"error": "Forbidden — admin only", "code": 403}), 403
        return f(*args, **kwargs)
    return decorated

# ── Auth routes ───────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory(_BASE_DIR, "dashboard.html")

@app.route("/api/auth/login", methods=["POST"])
def login():
    data     = request.get_json() or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    db  = get_db()
    row = db.execute(
        "SELECT * FROM users WHERE username=? AND active=1", (username,)
    ).fetchone()

    if not row or not bcrypt.checkpw(password.encode(), row["password"].encode()):
        db.close()
        log_action(username, "LOGIN_FAIL", detail="Bad credentials")
        return jsonify({"error": "Invalid username or password"}), 401

    db.execute("UPDATE users SET last_login=datetime('now') WHERE username=?", (username,))
    db.commit()
    db.close()

    session.permanent = True
    session["user"]      = username
    session["role"]      = row["role"]
    session["full_name"] = row["full_name"] or username

    log_action(username, "LOGIN_OK")
    return jsonify({
        "ok": True,
        "username":  username,
        "role":      row["role"],
        "full_name": row["full_name"] or username
    })

@app.route("/api/auth/logout", methods=["POST"])
def logout():
    user = session.get("user", "unknown")
    session.clear()
    log_action(user, "LOGOUT")
    return jsonify({"ok": True})

@app.route("/api/auth/me")
def me():
    if not session.get("user"):
        return jsonify({"logged_in": False}), 200
    return jsonify({
        "logged_in": True,
        "username":  session["user"],
        "role":      session["role"],
        "full_name": session["full_name"]
    })

# ── User management (admin only) ──────────────────────────────────────────────
@app.route("/api/users", methods=["GET"])
@require_admin
def get_users():
    db   = get_db()
    rows = db.execute(
        "SELECT id,username,role,full_name,email,active,created_at,last_login FROM users ORDER BY id"
    ).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/users", methods=["POST"])
@require_admin
def create_user():
    data     = request.get_json() or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    role     = data.get("role", "operator")
    full_name= (data.get("full_name") or "").strip()
    email    = (data.get("email") or "").strip()

    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    if role not in ("admin", "operator"):
        return jsonify({"error": "role must be admin or operator"}), 400
    if len(password) < 6:
        return jsonify({"error": "password must be at least 6 characters"}), 400

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username,password,role,full_name,email) VALUES (?,?,?,?,?)",
            (username, hashed, role, full_name, email)
        )
        db.commit()
    except sqlite3.IntegrityError:
        db.close()
        return jsonify({"error": "Username already exists"}), 409
    db.close()
    log_action(session["user"], "USER_CREATE", target=username, detail=f"role={role}")
    return jsonify({"ok": True, "username": username}), 201

@app.route("/api/users/<int:uid>", methods=["PUT"])
@require_admin
def update_user(uid):
    data      = request.get_json() or {}
    full_name = (data.get("full_name") or "").strip()
    email     = (data.get("email") or "").strip()
    role      = data.get("role")
    active    = data.get("active")
    password  = (data.get("password") or "").strip()

    db  = get_db()
    row = db.execute("SELECT username FROM users WHERE id=?", (uid,)).fetchone()
    if not row:
        db.close()
        return jsonify({"error": "User not found"}), 404

    # Prevent removing last admin
    if role == "operator":
        admins = db.execute("SELECT COUNT(*) AS n FROM users WHERE role='admin' AND active=1").fetchone()["n"]
        current_role = db.execute("SELECT role FROM users WHERE id=?", (uid,)).fetchone()["role"]
        if current_role == "admin" and admins <= 1:
            db.close()
            return jsonify({"error": "Cannot demote the only admin"}), 400

    fields, vals = [], []
    if full_name: fields.append("full_name=?"); vals.append(full_name)
    if email:     fields.append("email=?");     vals.append(email)
    if role in ("admin","operator"): fields.append("role=?"); vals.append(role)
    if active is not None: fields.append("active=?"); vals.append(1 if active else 0)
    if password:
        if len(password) < 6:
            db.close()
            return jsonify({"error": "password must be at least 6 characters"}), 400
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        fields.append("password=?"); vals.append(hashed)

    if fields:
        vals.append(uid)
        db.execute(f"UPDATE users SET {','.join(fields)} WHERE id=?", vals)
        db.commit()
    db.close()
    log_action(session["user"], "USER_UPDATE", target=row["username"])
    return jsonify({"ok": True})

@app.route("/api/users/<int:uid>", methods=["DELETE"])
@require_admin
def delete_user(uid):
    db  = get_db()
    row = db.execute("SELECT username,role FROM users WHERE id=?", (uid,)).fetchone()
    if not row:
        db.close()
        return jsonify({"error": "User not found"}), 404
    if row["username"] == session["user"]:
        db.close()
        return jsonify({"error": "Cannot delete your own account"}), 400
    admins = db.execute("SELECT COUNT(*) AS n FROM users WHERE role='admin' AND active=1").fetchone()["n"]
    if row["role"] == "admin" and admins <= 1:
        db.close()
        return jsonify({"error": "Cannot delete the only admin"}), 400
    db.execute("DELETE FROM users WHERE id=?", (uid,))
    db.commit()
    db.close()
    log_action(session["user"], "USER_DELETE", target=row["username"])
    return jsonify({"ok": True})

@app.route("/api/auth/change-password", methods=["POST"])
@require_login
def change_own_password():
    data     = request.get_json() or {}
    old_pw   = (data.get("old_password") or "").strip()
    new_pw   = (data.get("new_password") or "").strip()
    if not old_pw or not new_pw:
        return jsonify({"error": "Both fields required"}), 400
    if len(new_pw) < 6:
        return jsonify({"error": "New password must be at least 6 characters"}), 400

    db  = get_db()
    row = db.execute("SELECT password FROM users WHERE username=?", (session["user"],)).fetchone()
    if not bcrypt.checkpw(old_pw.encode(), row["password"].encode()):
        db.close()
        return jsonify({"error": "Current password is incorrect"}), 401
    hashed = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
    db.execute("UPDATE users SET password=? WHERE username=?", (hashed, session["user"]))
    db.commit()
    db.close()
    log_action(session["user"], "PASSWORD_CHANGE")
    return jsonify({"ok": True})

# ── Backend status ────────────────────────────────────────────────────────────
@app.route("/api/backend-status")
def backend_status():
    """Simple heartbeat — frontend polls this to show 'Backend online/offline'."""
    return jsonify({"ok": True, "fping": bool(FPING_BIN), "sweep_active": _sweep_active})

# ── Stats ─────────────────────────────────────────────────────────────────────
@app.route("/api/stats")
@require_login
def api_stats():
    db   = get_db()
    rows = db.execute("""
        SELECT c.ip, c.name,
               p.status, p.latency_ms
        FROM customers c
        LEFT JOIN ping_results p ON p.id = (
            SELECT id FROM ping_results WHERE ip=c.ip ORDER BY id DESC LIMIT 1
        )
        WHERE c.active=1
    """).fetchall()
    db.close()

    total    = len(rows)
    counts   = {}
    for r in rows:
        s = r["status"] or "unknown"
        counts[s] = counts.get(s, 0) + 1
    lats = [r["latency_ms"] for r in rows if r["latency_ms"]]
    return jsonify({
        "total":           total,
        "online":          counts.get("online", 0),
        "offline":         counts.get("offline", 0),
        "reserved":        counts.get("reserved", 0),
        "passive":         counts.get("passive", 0),
        "unassigned":      counts.get("unassigned", 0),
        "unknown":         counts.get("unknown", 0),
        "avg_latency_ms":  round(sum(lats)/len(lats), 2) if lats else None,
        "generated_at":    datetime.now().isoformat()
    })

# ── Customers ─────────────────────────────────────────────────────────────────
@app.route("/api/customers")
@require_login
def api_customers():
    db   = get_db()
    rows = db.execute("""
        SELECT c.ip, c.name, c.subnet, c.location, c.contact, c.notes,
               c.active, c.added_by, c.added_at, c.updated_at,
               p.status, p.latency_ms, p.checked_at
        FROM customers c
        LEFT JOIN ping_results p ON p.id = (
            SELECT id FROM ping_results WHERE ip=c.ip ORDER BY id DESC LIMIT 1
        )
        WHERE c.active=1
        ORDER BY c.ip
    """).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/customers/<ip>")
@require_login
def api_customer_detail(ip):
    db  = get_db()
    row = db.execute("SELECT * FROM customers WHERE ip=?", (ip,)).fetchone()
    if not row:
        db.close()
        return jsonify({"error": "Not found"}), 404
    history = db.execute(
        "SELECT status,latency_ms,checked_at FROM ping_results WHERE ip=? ORDER BY id DESC LIMIT 50",
        (ip,)
    ).fetchall()
    db.close()
    result = dict(row)
    result["history"] = [dict(h) for h in history]
    return jsonify(result)

@app.route("/api/customers", methods=["POST"])
@require_login
def api_add_customer():
    data    = request.get_json() or {}
    ip      = (data.get("ip") or "").strip()
    name    = (data.get("name") or "").strip()
    location= (data.get("location") or "").strip()
    contact = (data.get("contact") or "").strip()
    notes   = (data.get("notes") or "").strip()

    if not ip or not name:
        return jsonify({"error": "ip and name are required"}), 400
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
        return jsonify({"error": "Invalid IP format"}), 400

    subnet = "103.180.241.0/24" if ".241." in ip else \
             "103.180.240.0/24" if ".240." in ip else "unknown"

    db = get_db()
    try:
        db.execute(
            "INSERT INTO customers (ip,name,subnet,location,contact,notes,added_by) VALUES (?,?,?,?,?,?,?)",
            (ip, name, subnet, location, contact, notes, session["user"])
        )
        db.commit()
    except sqlite3.IntegrityError:
        db.close()
        return jsonify({"error": "IP already exists"}), 409
    db.close()
    log_action(session["user"], "CUSTOMER_ADD", target=ip, detail=name)
    return jsonify({"ok": True, "ip": ip}), 201

@app.route("/api/customers/<ip>", methods=["PUT"])
@require_login
def api_update_customer(ip):
    data     = request.get_json() or {}
    name     = (data.get("name") or "").strip()
    location = (data.get("location") or "").strip()
    contact  = (data.get("contact") or "").strip()
    notes    = (data.get("notes") or "").strip()

    if not name:
        return jsonify({"error": "name is required"}), 400

    db = get_db()
    db.execute("""
        UPDATE customers SET name=?,location=?,contact=?,notes=?,updated_at=datetime('now')
        WHERE ip=?
    """, (name, location, contact, notes, ip))
    db.commit()
    db.close()
    log_action(session["user"], "CUSTOMER_UPDATE", target=ip, detail=name)
    return jsonify({"ok": True})

@app.route("/api/customers/<ip>", methods=["DELETE"])
@require_login
def api_delete_customer(ip):
    db  = get_db()
    row = db.execute("SELECT name FROM customers WHERE ip=?", (ip,)).fetchone()
    if not row:
        db.close()
        return jsonify({"error": "Not found"}), 404
    db.execute("DELETE FROM customers WHERE ip=?", (ip,))
    db.commit()
    db.close()
    log_action(session["user"], "CUSTOMER_DELETE", target=ip, detail=row["name"])
    return jsonify({"ok": True})

@app.route("/api/customers/bulk", methods=["POST"])
@require_login
def api_bulk_import():
    data    = request.get_json() or {}
    entries = data.get("entries", [])
    if not entries:
        return jsonify({"error": "No entries provided"}), 400

    db      = get_db()
    added   = 0
    skipped = 0
    errors  = []

    for e in entries:
        ip   = (e.get("ip") or "").strip()
        name = (e.get("name") or "").strip()
        if not ip or not name:
            skipped += 1
            continue
        subnet = "103.180.241.0/24" if ".241." in ip else \
                 "103.180.240.0/24" if ".240." in ip else "unknown"
        try:
            db.execute(
                "INSERT INTO customers (ip,name,subnet,location,contact,notes,added_by) VALUES (?,?,?,?,?,?,?)",
                (ip, name, subnet,
                 (e.get("location") or "").strip(),
                 (e.get("contact") or "").strip(),
                 (e.get("notes") or "").strip(),
                 session["user"])
            )
            added += 1
        except sqlite3.IntegrityError:
            errors.append(f"{ip} already exists")
            skipped += 1

    db.commit()
    db.close()
    log_action(session["user"], "BULK_IMPORT", detail=f"added={added} skipped={skipped}")
    return jsonify({"ok": True, "added": added, "skipped": skipped, "errors": errors})

# ── Ping ──────────────────────────────────────────────────────────────────────
# ── Logical classification (name-based) ──────────────────────────────────────
def classify_status(name):
    """Determine logical status from customer name before real ping."""
    if not name or name.lower() in ("unassigned", "free"):
        return "unassigned"
    n = name.lower()
    if any(k in n for k in ("reserved", "lab test", "test ip")):
        return "reserved"
    if any(k in n for k in ("passive", "terminated")):
        return "passive"
    return "active"

# ── fping single-IP ───────────────────────────────────────────────────────────
def fping_single(ip):
    """
    Use fping for a single IP (on-demand ping from the API).
    Sends FPING_COUNT probes, returns averaged latency.
    fping flags:
      -c  count     : number of probes
      -t  timeout   : per-probe timeout in ms
      -p  interval  : ms between probes
      -q            : quiet (suppress per-probe output, show summary only)
      -e            : show elapsed time on return
    """
    try:
        cmd = [
            FPING_BIN,
            "-c", str(FPING_COUNT),
            "-t", str(PING_TIMEOUT * 1000),
            "-p", str(FPING_INTERVAL),
            "-q",
            ip
        ]
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=PING_TIMEOUT * FPING_COUNT + 2
        )
        # fping summary line (stderr): IP : xmt/rcv/%loss = a/b/c%, min/avg/max = x/y/z
        output = result.stderr + result.stdout

        # Parse loss percentage
        loss_m = re.search(r"(\d+)%\s*loss", output)
        loss   = int(loss_m.group(1)) if loss_m else 100

        # Parse avg latency from min/avg/max
        lat_m  = re.search(r"min/avg/max\s*=\s*[\d.]+/([\d.]+)/[\d.]+", output)
        avg_ms = round(float(lat_m.group(1)), 2) if lat_m else None

        # Decision: >=50% loss = offline, else online with averaged latency
        if loss >= 50:
            return {"status": "offline", "latency_ms": avg_ms, "loss_pct": loss}
        return {"status": "online", "latency_ms": avg_ms, "loss_pct": loss}

    except Exception as e:
        print(f"[fping_single] {ip}: {e}")
        return {"status": "offline", "latency_ms": None, "loss_pct": 100}

# ── fping bulk-sweep ──────────────────────────────────────────────────────────
def fping_bulk(ip_list):
    """
    Ping ALL IPs in one fping call — massively faster than individual pings.
    Returns dict: { ip -> {status, latency_ms, loss_pct} }

    fping flags:
      -c  count     : probes per host
      -t  timeout   : ms per probe
      -p  interval  : ms between probes to same host
      -q            : summary output only
      -A            : print IP instead of hostname
    """
    if not ip_list:
        return {}

    try:
        cmd = [
            FPING_BIN,
            "-c", str(FPING_COUNT),
            "-t", str(PING_TIMEOUT * 1000),
            "-p", str(FPING_INTERVAL),
            "-q",
            "-A",
        ] + ip_list

        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=PING_TIMEOUT * FPING_COUNT + 10
        )
        output = result.stderr + result.stdout
        results = {}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            # Format: 103.180.241.132 : xmt/rcv/%loss = 5/5/0%, min/avg/max = 1.2/1.8/2.4
            ip_m = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s*:", line)
            if not ip_m:
                continue
            ip = ip_m.group(1)

            loss_m = re.search(r"(\d+)%\s*loss", line)
            loss   = int(loss_m.group(1)) if loss_m else 100

            lat_m  = re.search(r"min/avg/max\s*=\s*[\d.]+/([\d.]+)/[\d.]+", line)
            avg_ms = round(float(lat_m.group(1)), 2) if lat_m else None

            if loss >= 50:
                results[ip] = {"status": "offline", "latency_ms": avg_ms, "loss_pct": loss}
            else:
                results[ip] = {"status": "online",  "latency_ms": avg_ms, "loss_pct": loss}

        # IPs not appearing in output = unreachable (100% loss)
        for ip in ip_list:
            if ip not in results:
                results[ip] = {"status": "offline", "latency_ms": None, "loss_pct": 100}

        return results

    except Exception as e:
        print(f"[fping_bulk] Error: {e}")
        # Return offline for all on error
        return {ip: {"status": "offline", "latency_ms": None, "loss_pct": 100} for ip in ip_list}

# ── system ping fallback (single IP) ──────────────────────────────────────────
def systing_ping(ip):
    """Fallback when fping is not installed."""
    system = platform.system().lower()
    cmd = (["ping", "-n", "3", "-w", str(PING_TIMEOUT * 1000), ip]
           if system == "windows"
           else ["ping", "-c", "3", "-W", str(PING_TIMEOUT), ip])
    try:
        t0     = time.time()
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=PING_TIMEOUT * 3 + 2)
        elapsed = (time.time() - t0) * 1000
        if result.returncode == 0:
            # Try avg from ping summary: rtt min/avg/max/mdev = x/y/z/w ms
            m = re.search(r"(?:avg|rtt)[^=]*=\s*[\d.]+/([\d.]+)", result.stdout + result.stderr)
            latency = float(m.group(1)) if m else round(elapsed / 3, 2)
            return {"status": "online", "latency_ms": round(latency, 2), "loss_pct": 0}
        return {"status": "offline", "latency_ms": None, "loss_pct": 100}
    except Exception:
        return {"status": "offline", "latency_ms": None, "loss_pct": 100}

# ── Unified ping entry point ───────────────────────────────────────────────────
def ping_ip(ip):
    """Single-IP ping — uses fping if available, else system ping."""
    if FPING_BIN:
        return fping_single(ip)
    return systing_ping(ip)

def determine_status(name, ping_result):
    """Override ping result with logical status for reserved/passive/unassigned IPs."""
    logical = classify_status(name)
    if logical in ("reserved", "passive", "unassigned"):
        # Keep latency if reachable, but show logical label
        return {"status": logical,
                "latency_ms": ping_result.get("latency_ms"),
                "loss_pct":   ping_result.get("loss_pct")}
    return ping_result

def save_ping(ip, status, latency_ms, loss_pct=None):
    db = get_db()
    # Store as UTC ISO-8601 with Z suffix so JS Date() parses timezone correctly
    now_utc = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    db.execute("INSERT INTO ping_results (ip,status,latency_ms,checked_at) VALUES (?,?,?,?)",
               (ip, status, latency_ms, now_utc))
    db.execute("""
        DELETE FROM ping_results WHERE ip=? AND id NOT IN (
            SELECT id FROM ping_results WHERE ip=? ORDER BY id DESC LIMIT ?
        )
    """, (ip, ip, HISTORY_LIMIT))
    db.commit()
    db.close()

@app.route("/api/ping/<ip>")
@require_login
def api_ping(ip):
    db  = get_db()
    row = db.execute("SELECT name FROM customers WHERE ip=?", (ip,)).fetchone()
    db.close()
    if not row:
        return jsonify({"error": "IP not in registry"}), 404
    raw    = ping_ip(ip)
    merged = determine_status(row["name"], raw)
    save_ping(ip, merged["status"], merged.get("latency_ms"))
    return jsonify({**merged, "ip": ip, "name": row["name"], "checked_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")})

@app.route("/api/history/<ip>")
@require_login
def api_history(ip):
    db   = get_db()
    rows = db.execute(
        "SELECT status,latency_ms,checked_at FROM ping_results WHERE ip=? ORDER BY id DESC LIMIT 50", (ip,)
    ).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])

# ── Audit log ─────────────────────────────────────────────────────────────────
@app.route("/api/audit")
@require_admin
def api_audit():
    limit = int(request.args.get("limit", 100))
    db    = get_db()
    rows  = db.execute(
        "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])

# ── Background sweep ──────────────────────────────────────────────────────────
_sweep_active = False

def run_sweep():
    """
    Main sweep loop.
    - If fping is available: single bulk fping call for ALL IPs at once — very fast.
    - Fallback: threaded individual pings (40 concurrent).
    """
    global _sweep_active
    engine = "fping" if FPING_BIN else "system ping"
    print(f"[sweep] Engine: {engine}")

    while _sweep_active:
        try:
            db   = get_db()
            rows = db.execute("SELECT ip,name FROM customers WHERE active=1").fetchall()
            db.close()

            if not rows:
                time.sleep(PING_INTERVAL)
                continue

            t_start = time.time()

            if FPING_BIN:
                # ── fping bulk mode: one subprocess for entire fleet ──────────
                ip_list   = [r["ip"]   for r in rows]
                name_map  = {r["ip"]: r["name"] for r in rows}
                bulk_res  = fping_bulk(ip_list)

                for ip, raw in bulk_res.items():
                    name   = name_map.get(ip, "")
                    merged = determine_status(name, raw)
                    save_ping(ip, merged["status"],
                              merged.get("latency_ms"),
                              merged.get("loss_pct"))

            else:
                # ── Fallback: threaded individual system pings ────────────────
                sem = threading.Semaphore(40)

                def ping_and_save(ip, name):
                    with sem:
                        raw    = systing_ping(ip)
                        merged = determine_status(name, raw)
                        save_ping(ip, merged["status"],
                                  merged.get("latency_ms"),
                                  merged.get("loss_pct"))

                threads = [
                    threading.Thread(target=ping_and_save,
                                     args=(r["ip"], r["name"]), daemon=True)
                    for r in rows
                ]
                for t in threads: t.start()
                for t in threads: t.join(timeout=PING_TIMEOUT * FPING_COUNT + 5)

            elapsed = round(time.time() - t_start, 2)
            print(f"[sweep] {len(rows)} IPs in {elapsed}s via {engine}")

        except Exception as e:
            print(f"[sweep] Error: {e}")

        time.sleep(PING_INTERVAL)

# ── Seed data ─────────────────────────────────────────────────────────────────
SEED_DATA = [
    ("103.180.241.129","Unassigned"),("103.180.241.130","VIvasoft"),
    ("103.180.241.131","Siddhartha Business Group of Hospitality Tinkune"),
    ("103.180.241.132","International Quality Health Care Center Pvt. Ltd"),
    ("103.180.241.133","Prabhu General Insurance"),
    ("103.180.241.134","Siddhartha Lumbini Green Hotel"),
    ("103.180.241.135","Kageshwori Manohara Aspatal (Mulpani Hospital)"),
    ("103.180.241.136","Hams Hospital"),("103.180.241.137","Hams Hospital"),
    ("103.180.241.138","Hams Hospital"),("103.180.241.139","Hams Hospital"),
    ("103.180.241.140","Dwarika Resort"),("103.180.241.141","Aayulogic Pvt.ltd."),
    ("103.180.241.142","Prabhu Stock Market Limited"),
    ("103.180.241.143","Reserved for ENT Lab test"),
    ("103.180.241.144","Bharatpur Garden Resort"),
    ("103.180.241.145","Ekta Medical College"),
    ("103.180.241.146","Hotel Central Plaza Pvt Ltd"),
    ("103.180.241.147","Bir Hospital - IME Pay Counter [passive]"),
    ("103.180.241.148","Dabur Nepal"),("103.180.241.149","Hotel Kunshaling"),
    ("103.180.241.150","Ocular Holdings Pvt Ltd, Baneshwor"),
    ("103.180.241.151","Dabur Nepal"),("103.180.241.152","Siddhartha Cottage Butwal"),
    ("103.180.241.153","S Cafe Lagankhel, Lalitpur"),
    ("103.180.241.154","Siddhartha Foodland, Old Baneshwor"),
    ("103.180.241.155","S Cafe Manmohan, Kathmandu"),
    ("103.180.241.156","STR Advertisement Pvt. Ltd"),
    ("103.180.241.157","A.S.T Pvt. Ltd, Birjung"),
    ("103.180.241.158","Siddhartha Insurance, Thali"),
    ("103.180.241.159","Siddhartha Insurance, Lubu"),
    ("103.180.241.160","Siddhartha Insurance, Thimi"),
    ("103.180.241.161","Voice of Children"),
    ("103.180.241.162","Lifestar Pharmaceutical Pvt. Ltd"),
    ("103.180.241.163","Muktinath Krishi Company Limited, HO"),
    ("103.180.241.164","Lifestar Pharmaceutical Pvt. Ltd"),
    ("103.180.241.165","Yatri Kunj Hotel"),
    ("103.180.241.166","Shivasakti Suppliers Hotel, Butwal"),
    ("103.180.241.167","Olive Group"),("103.180.241.168","Norvic Hospital"),
    ("103.180.241.169","BYD Cimex INC Pvt LTD Guheshwori"),
    ("103.180.241.170","Ocular Holdings Pvt Ltd, Kalimati"),
    ("103.180.241.171","Siddhartha Cottage, Nepalgunj"),
    ("103.180.241.172","Music Nepal"),("103.180.241.173","Dwarika Resort"),
    ("103.180.241.174","Saanvi Hotel & Sport Center Pvt Ltd"),
    ("103.180.241.175","Gokyo Labs"),
    ("103.180.241.176","Siddhartha Cottage Restaurant & Bar, Tinkune"),
    ("103.180.241.177","Mechinagar Nagarpalika"),("103.180.241.178","Shikali Resort"),
    ("103.180.241.179","Advertisement Display Project [NOC]"),
    ("103.180.241.180","Nagarik Community Teaching Hospital"),
    ("103.180.241.181","Unassigned"),("103.180.241.182","Unassigned"),("103.180.241.183","Unassigned"),
    ("103.180.241.184","Narayani Bakery & Food Industries"),
    ("103.180.241.185","Himtal Hydropower"),("103.180.241.186","Ambition Guru (UN Park)"),
    ("103.180.241.187","Capital Nepal, Dillibazar"),("103.180.241.188","UNO Technology"),
    ("103.180.241.189","DM Cinema"),("103.180.241.190","Hotel City Palace"),
    ("103.180.241.191","Hotel Manang Thamel"),
    ("103.180.241.192","Ambition Guru, Kamaladi-Durbarmarg"),
    ("103.180.241.193","Shree Brahma Rupa Higher Secondary School"),
    ("103.180.241.194","Chandragiri Hills Resort"),
    ("103.180.241.195","Hotel Marsyangdi, Thamel"),
    ("103.180.241.196","Prabhu Insurance CEO"),
    ("103.180.241.197","Trisara Restaurant and Bar"),
    ("103.180.241.198","Informatics College Pvt Ltd"),
    ("103.180.241.199","Neosys Technologies P. Ltd"),
    ("103.180.241.200","Bay Hotel Pokhara"),
    ("103.180.241.201","Adhyanta Fund Management"),
    ("103.180.241.202","G-Ramayan Hotel (The Ramayana Hotel)"),
    ("103.180.241.203","Zen Edu Hub"),("103.180.241.204","Hotel Royal Villa"),
    ("103.180.241.205","Number Himalaya Hydropower Limited"),
    ("103.180.241.206","Ideal International Recruitment"),
    ("103.180.241.207","Star Boss Coffee House Durbarmarg"),
    ("103.180.241.208","Hotel Jungle Mahal Matatirtha Pvt Ltd"),
    ("103.180.241.209","Count on Me"),("103.180.241.210","Apex Life School"),
    ("103.180.241.211","Dabur Nepal Guest House Maharjgunj"),
    ("103.180.241.212","Kwality Durbar"),
    ("103.180.241.213","College of Information Technology and Engineering"),
    ("103.180.241.214","Reduct.video"),
    ("103.180.241.215","Tulsipur Sub-Metropolitan Office"),
    ("103.180.241.216","Gandaki College of Engineering"),
    ("103.180.241.217","IGI Prudential Insurance"),("103.180.241.218","DDSM"),
    ("103.180.241.219","National Academy of Vocational Training"),
    ("103.180.241.220","APF"),("103.180.241.221","Hotel New Aananda Mahendranagar"),
    ("103.180.241.222","Hetauda Hospital"),
    ("103.180.241.223","Shikhar Insurance Lagankhel"),
    ("103.180.241.224","Apex Hotel Siddhartha Hospitality Damauli"),
    ("103.180.241.225","National Logistic Pvt Ltd, Mahendranagar"),
    ("103.180.241.226","For GNN (Encoder) Prabhu TV"),
    ("103.180.241.227","I to B Pvt Ltd [Passive connection]"),
    ("103.180.241.228","Aam Nepali Media Pvt. Ltd. (An TV)"),
    ("103.180.241.229","Prince Mart Kathmandu"),
    ("103.180.241.230","Four Symmetrons Innovation Pvt Ltd."),
    ("103.180.241.231","Pacific Multispeciality Clinic"),
    ("103.180.241.232","Manmohan Cardiothoracic Vascular & Transplant Center"),
    ("103.180.241.233","Drishti Eye Care Center Pvt. Ltd [passive]"),
    ("103.180.241.234","Tulasi Mehar School Hetauda [passive]"),
    ("103.180.241.235","Nepal Ceramic, Birgunj [H.O]"),
    ("103.180.241.236","Shasheela Motors Pvt Ltd"),
    ("103.180.241.237","Siddhartha Cottage Restaurant Dhobighat"),
    ("103.180.241.238","Rhythm Neuropsychiatry Hospital And Research Center"),
    ("103.180.241.239","Apex Hotel Siddhartha Hospitality Damauli TV"),
    ("103.180.241.240","Yeti International College"),
    ("103.180.241.241","Barahi Multipurpose Co-operative, Koteshor [HO]"),
    ("103.180.241.242","Gaurishankar TV Network Pvt. Ltd."),
    ("103.180.241.243","River Bank Jungle Resort, Maharajgunj"),
    ("103.180.241.244","Samridihi Finance - DC Datalaya"),
    ("103.180.241.245","Ishan Children & Womens Hospital Pvt. Ltd."),
    ("103.180.241.246","Rastriya Banijya Bank RBB, Thahpathali"),
    ("103.180.241.247","Mercy Corps Nepal"),
    ("103.180.241.248","Amnil Technology [QUICKFOX TECHNOLOGIES PVT.LTD]"),
    ("103.180.241.249","Apex Manokamana Group Naxaal"),
    ("103.180.241.250","Sajilo Digital Communication, Simara"),
    ("103.180.241.251","Hotel Siddhartha Sundhara"),
    ("103.180.241.252","Sikhar Insurance-Medicity"),
    ("103.180.241.253","Asha Indriya Hospitality"),
    ("103.180.241.254","Rock International Pvt.Ltd Kakarvitta"),
    ("103.180.240.2","Navya Hotel Bardibas"),("103.180.240.3","Arniko Garments Pvt Ltd"),
    ("103.180.240.4","Shree Chhaya Nandan"),("103.180.240.5","Hotel KJS Inn, Mahendranagar"),
    ("103.180.240.6","IGI Prudential Insurance Limited - Panipokhari Office"),
    ("103.180.240.7","Digital Wallet Corporation"),("103.180.240.8","Nepal Gas Test IP"),
    ("103.180.240.9","Lumbini Medical College (LMC)"),
    ("103.180.240.10","Ganga Diagnostic Center"),
    ("103.180.240.11","Industrial District Management [IDM]"),
    ("103.180.240.12","River Bank Jungle Resort Chitwan"),
    ("103.180.240.13","Aqore Software Pvt. Ltd."),
    ("103.180.240.14","Balaju Industrial District Management [BID]"),
    ("103.180.240.15","Lakeside Retreat, Pokhara"),
    ("103.180.240.16","Hotel Thamel Kathmandu"),("103.180.240.17","Dwarika's Hotel"),
    ("103.180.240.18","Yeti Health Science Academy"),
    ("103.180.240.19","Chaitanya Multiple Campus"),("103.180.240.20","AP1 Television"),
    ("103.180.240.21","National Academy of Science and Technology"),
    ("103.180.240.22","Paakshala Academy of Hospitality"),
    ("103.180.240.23","Hook Hospitality (Udhyatech Pvt.Ltd)"),
    ("103.180.240.24","Smart Solution"),
    ("103.180.240.25","Happy Hour Pvt. Ltd, Mahendranagar"),
    ("103.180.240.26","Sake and Feng-1"),("103.180.240.27","NMB Microfinance Ltd"),
    ("103.180.240.28","Pashmina Creation Nepal"),
    ("103.180.240.29","Prabhu TV (Pulchowk) GNN"),
    ("103.180.240.30","Central College of Business Management"),
    ("103.180.240.31","Ministry of Internal Affairs and Law, Biratnagar"),
    ("103.180.240.32","Academy of Culinary Arts and Hospitality Management"),
    ("103.180.240.33","St. Xaviers School Godawari"),
    ("103.180.240.34","Bright Zone International School, Limpia"),
    ("103.180.240.35","Dwarika's Hotel"),
    ("103.180.240.36","Nepal Institute of Health Sciences"),
    ("103.180.240.37","Vu Devi Services Pvt.Ltd"),
    ("103.180.240.38","Prabhu TV (Pulchowk) GNN"),("103.180.240.39","Tushal Multivenue"),
    ("103.180.240.40","Softtech Infosys Pvt. Ltd."),
    ("103.180.240.41","Softtech Infosys Pvt. Ltd."),
    ("103.180.240.42","Hotel Tradition & Spa Pvt Ltd"),
    ("103.180.240.43","Annapurna Hotel"),("103.180.240.44","Jana Jyoti Multiple Campus"),
    ("103.180.240.45","Lavie Hospitality (Lavee Garden)"),
    ("103.180.240.46","Dreams Hill Resort, Baglung"),
    ("103.180.240.47","Hotel Sitasharan, Zeromile, Janakpur"),
    ("103.180.240.48","Happy Hour Bhairawa"),("103.180.240.49","Patanjali Yog Peeth TV"),
    ("103.180.240.50","Lalbandi Municipality"),("103.180.240.51","S Cafe Naxal"),
    ("103.180.240.52","Sitasharan Hotel and Plaza"),("103.180.240.53","Nepal Gas"),
    ("103.180.240.54","United Traders Syndicate Pvt. Ltd."),
    ("103.180.240.55","Inland Revenue Office Balaju"),
    ("103.180.240.56","Tech Law College"),("103.180.240.57","Elevate VA Pvt.Ltd."),
    ("103.180.240.58","Madhesi Commission"),("103.180.240.59","Patanjali Yog Peeth TV"),
    ("103.180.240.60","Parewa Labs Pvt. Ltd."),
    ("103.180.240.61","Siddhartha River Side Resort, Chumlingtar"),
    ("103.180.240.62","Hotel Gulmohar, Bharatpur"),
    ("103.180.240.63","Mithila Yatri Niwas Janakpur"),
    ("103.180.240.64","Janata TV Baneswor"),
    ("103.180.240.65","Meraki Holistic Wellness Resort"),
    ("103.180.240.66","Prabhu Helicopter Ltd."),("103.180.240.67","Bright Future Academy"),
    ("103.180.240.68","Sanima General Insurance"),("103.180.240.69","New IT-Venture"),
    ("103.180.240.70","Sarokar TV Himalayan Televoice"),
    ("103.180.240.71","JBBL HO Kamalpokhari"),
    ("103.180.240.72","Hotel Kantipur Plaza, Nepalgunj"),
    ("103.180.240.73","Apex Manokamana Group Naxaal"),
    ("103.180.240.74","Siddhartha International Hotel, Bhairawaha"),
    ("103.180.240.75","Sushil Koirala Prakhar Cancer Hospital"),
    ("103.180.240.76","Village Highland Resort"),
    ("103.180.240.77","Catalyst Management [CMS Bishal Nagar]"),
    ("103.180.240.78","Arghakhachi Digital Cable Network"),
    ("103.180.240.79","Cypher Technology"),("103.180.240.80","Royal Tulip by Massif"),
    ("103.180.240.81","Rigorous Web"),("103.180.240.82","Rigorous Web"),
    ("103.180.240.83","Gadhi View Resort"),("103.180.240.84","HAMS Nursing College"),
    ("103.180.240.85","Hotel Tiger Palace"),("103.180.240.86","Hotel Thamel House"),
    ("103.180.240.87","PYC and Associates"),("103.180.240.88","Sangam City Hotel"),
    ("103.180.240.89","Godawari Residential School"),
    ("103.180.240.90","Medina Medical Center"),("103.180.240.91","Fenix Trading Pvt Ltd"),
    ("103.180.240.92","Southwestern Business College"),
    ("103.180.240.93","Karki Consulting"),
    ("103.180.240.94","Gandaki College of Engineering"),
    ("103.180.240.95","Hotel Aatithya Satkar Pvt Ltd."),
    ("103.180.240.96","Sarokar TV Himalayan Televoice"),
    ("103.180.240.97","Kalika Lagubitta Bittya Sanstha Ltd"),
    ("103.180.240.98","Global TV [Kalinchowk TV]"),
    ("103.180.240.99","Narayani Regional Hospital"),
    ("103.180.240.100","IME Motors Pvt. Ltd"),("103.180.240.101","CMS Nepal Internet"),
    ("103.180.240.102","Nari TV"),("103.180.240.103","Samsonite Nepal Thapathali"),
    ("103.180.240.104","Hotel Red Stone"),("103.180.240.105","Sumeru City Hospital"),
    ("103.180.240.106","Shikhar Biotech"),
    ("103.180.240.107","Model College Pvt.Ltd, Janakpur"),
    ("103.180.240.108","Hotel Rubus Pvt.Ltd"),("103.180.240.110","LMC - AP Test"),
    ("103.180.240.111","Siddhartha View Nepalgunj"),
    ("103.180.240.112","Siddhartha Sunny Resort Surkhet"),
    ("103.180.240.113","Space 4K Television > LogPoint Nepal"),
    ("103.180.240.114","Shree Jana Kalyana Secondary School"),
    ("103.180.240.115","Ray Media Group Pvt.Ltd"),
    ("103.180.240.116","Sanjeevani Institute of Advanced Studies and Teaching Hospital"),
    ("103.180.240.117","Sanjay Adhakari Sir Resort"),
    ("103.180.240.118","Hathway Investment Pvt. Ltd."),
    ("103.180.240.119","Bandipur Siddhartha Village"),
    ("103.180.240.120","Siddhartha Dhangadi"),
    ("103.180.240.121","Kathmandu Royal Chamber Hotel Pvt.Ltd"),
    ("103.180.240.122","Sampada Garden Hotel"),("103.180.240.123","Purna's Resort"),
    ("103.180.240.124","Studio MCR"),("103.180.240.125","Southwestern School"),
    ("103.180.240.126","C.C.S. Nepal Pvt. Ltd - Chinese Embassy"),
    ("103.180.240.127","Amnil Technology Pvt.Ltd, Manbhawan (new)"),
    ("103.180.240.128","Image Television"),
    ("103.180.240.129","Sanima General Insurance"),("103.180.240.130","VIvasoft"),
    ("103.180.240.131","Avinash Vet Pharma Pvt Ltd, Balaju"),
    ("103.180.240.132","Hotel Green Lumbini Pvt.Ltd"),
    ("103.180.240.133","Hotel Nine Hills, Sundhara"),("103.180.240.134","Kaveri Inn Hotel"),
    ("103.180.240.135","Krishna Medical and Technical Research Center"),
    ("103.180.240.136","Singha Durbar Baidhya Khana Samiti"),
    ("103.180.240.137","Nepal Ceramic Jeetpur"),
    ("103.180.240.138","Kopila Valley School, Birendranagar, Surkhet"),
    ("103.180.240.139","Malpi International College"),("103.180.240.140","Treebone Resort"),
    ("103.180.240.141","Bardali Media, Pokhara"),
    ("103.180.240.142","Multi Rich International Pvt.Ltd"),
    ("103.180.240.143","Renegade Insurance Nepal, Jawlakhel"),
    ("103.180.240.144","Prisma Social Media Network"),
    ("103.180.240.145","Sagun Saving & Credit"),
    ("103.180.240.146","Global Education Services Bagmati Pvt.Ltd"),
    ("103.180.240.147","Kamala Khatri Home"),
    ("103.180.240.148","Shivom Multipropose Services Pvt.Ltd"),
    ("103.180.240.149","Lekali Thakali"),("103.180.240.150","Click Mandu"),
    ("103.180.240.151","Hotel Sherpani"),("103.180.240.152","Mahalaxmi Enterprise"),
    ("103.180.240.153","Dhulikhel Mountain Resort - DMR"),
    ("103.180.240.154","Hotel Le-Himalayan"),("103.180.240.155","Prabhu TV Chitwan"),
    ("103.180.240.156","Dalle Restaurant Pvt Ltd - HO"),
    ("103.180.240.157","Maulakalika Cable Car Resort"),
    ("103.180.240.158","Patanjali Yogpeeth Internet"),
    ("103.180.240.159","Chandragiri Hills"),
    ("103.180.240.160","Everest Travels & Tours Pvt.Ltd"),
    ("103.180.240.161","Leapfrog"),
    ("103.180.240.162","Paschimanchal Solution Pvt.Ltd - Terminated"),
    ("103.180.240.163","Meraki"),("103.180.240.164","Pink Elephant Club Nova"),
    ("103.180.240.165","Nepal TV Network Pvt. Ltd"),
    ("103.180.240.166","Siddhartha International Hotel, Bhairawaha"),
    ("103.180.240.167","Cimex Inc Pvt Ltd [BYD]"),
    ("103.180.240.168","Blackardy Private Limited"),
    ("103.180.240.169","ENT Lab Test MKTK"),("103.180.240.170","Siddhartha Boutique Boudha"),
    ("103.180.240.171","Dhulikhel Mountain Resort"),
    ("103.180.240.172","Srijana Gyansagar School"),
    ("103.180.240.173","Swagatam Hotel Lahan"),("103.180.240.174","CG Entertainment Pvt Ltd."),
    ("103.180.240.175","Devine Kathmandu Hotel Pvt. Ltd."),
    ("103.180.240.176","Saarvashree Herbs Pvt. Ltd"),
    ("103.180.240.177","Buzz Entertainment Pvt. Ltd. (Jay Nepal Hall)"),
    ("103.180.240.178","Kanjirowa National School Pvt.Ltd"),
    ("103.180.240.179","Sarang Wildlife Sanctuary, Meghauli"),
    ("103.180.240.180","Polychangda Project, Nijgadh"),
    ("103.180.240.181","Bishwojyoti Cineplex"),
    ("103.180.240.182","IME Swift Technology (IME Limited)"),
    ("103.180.240.183","Hotel Prime Suite"),("103.180.240.184","I.T. Care Nepal Pvt. Ltd."),
    ("103.180.240.185","Thasang Ghar"),("103.180.240.186","Raut Construction"),
    ("103.180.240.187","AGL Birgunj"),("103.180.240.188","Hotel Yakroo Manang Pvt.Ltd"),
    ("103.180.240.189","Maulakalika Cable Car"),
    ("103.180.240.190","Tulshipur Khanepani Upobhakta Sanstha"),
    ("103.180.240.191","Nepal Kasthamandap College"),
    ("103.180.240.192","Siddhartha Tikapur"),("103.180.240.193","Meta IT Learning"),
    ("103.180.240.194","Nepal Everest Food And Snacks Pvt. Ltd"),
    ("103.180.240.195","Smarten Technology"),("103.180.240.196","Digital Labs - Tinkune"),
    ("103.180.240.197","Gandaki College of Engineering"),
    ("103.180.240.198","United Business Hotel"),
    ("103.180.240.199","Greenland Academy Pvt Ltd"),
    ("103.180.240.200","AP1 Television Gwarko"),
    ("103.180.240.201","Siddhartha Cottage Butwal, Milan Chok"),
    ("103.180.240.202","Lumbini Cable Car"),
    ("103.180.240.203","Saake Food and Beverage Pvt. Ltd."),
    ("103.180.240.204","Hotel Godawari"),("103.180.240.205","Clock B Innovation"),
    ("103.180.240.206","Nepal Broadcasting Channel"),("103.180.240.207","Sikhar Palace"),
    ("103.180.240.208","Free"),("103.180.240.209","ADBL"),
    ("103.180.240.210","Gaurishankar Agro Chapur"),
    ("103.180.240.211","Chhauni Army Barrage"),
    ("103.180.240.212","Infrastructure Development Office, Lalitpur [IDO]"),
    ("103.180.240.213","BCN Network"),("103.180.240.214","Codavatar Tech Private Limited"),
    ("103.180.240.215","Karma Bar and Club"),("103.180.240.216","Ocular (Passive)"),
    ("103.180.240.217","Midas Technology Pvt. Ltd"),
    ("103.180.240.218","Genuine Secondary School"),
    ("103.180.240.219","Nepal Pulp & Paper Industries Pvt Ltd"),
    ("103.180.240.220","Shree Mahendranagar Secondary School"),
    ("103.180.240.221","Nari TV HD"),("103.180.240.222","Chandragiri Hills"),
    ("103.180.240.223","Uno Internet Ventures Pvt. Ltd."),
    ("103.180.240.224","Tech One Global Nepal"),
    ("103.180.240.225","Sidhartha Vilasa Banbas Resort Chitwan"),
    ("103.180.240.226","Soaltee Westend Resort"),
    ("103.180.240.227","Explore Nepal TV Network Pvt. Ltd. (Encoder)"),
    ("103.180.240.228","Barakhari Media"),("103.180.240.229","Hotel KI"),
    ("103.180.240.230","BBN"),
    ("103.180.240.231","ACME Technology Pvt.Ltd (Data Center)"),
    ("103.180.240.232","Unnati Nepal Foundation"),("103.180.240.233","Hotel Purna Yoga"),
    ("103.180.240.234","Samiyog Tourist Resort"),("103.180.240.235","NCMT College"),
    ("103.180.240.236","Batash Organization - Pokhara"),
    ("103.180.240.237","Himalaya Airlines Private Limited"),
    ("103.180.240.238","Rhythm Neuropsychiatry Hospital And Research Center"),
    ("103.180.240.239","Prabhu Group Building [Chairman]"),
    ("103.180.240.240","Hotel A One Venue"),
    ("103.180.240.241","Hotel Mustang Lete and Thakali Kitchen"),
    ("103.180.240.242","Royal Tulip by Massif"),
    ("103.180.240.243","Global Reach Pvt.Ltd, Pokhara"),
    ("103.180.240.244","Karya Binyak Healthy Homes, Kupondole"),
    ("103.180.240.245","DHI"),("103.180.240.246","Dreams College Bharatpur"),
    ("103.180.240.247","ENT Lab Test Rujie"),("103.180.240.248","Duhabi Municipality Office"),
    ("103.180.240.249","To Universal Language"),("103.180.240.250","News 24"),
    ("103.180.240.251","Siddhartha Central Palm Bharatpur"),
    ("103.180.240.252","Sipradhi Trading"),
    ("103.180.240.253","Best Western Plus Godavari Resort"),
    ("103.180.240.254","Civil Khadyana Udhyoga Pvt.Ltd."),
]

def seed_customers():
    db = get_db()
    n  = db.execute("SELECT COUNT(*) AS n FROM customers").fetchone()["n"]
    if n == 0:
        print(f"[init] Seeding {len(SEED_DATA)} customers...")
        for ip, name in SEED_DATA:
            subnet = "103.180.241.0/24" if ".241." in ip else "103.180.240.0/24"
            db.execute(
                "INSERT OR IGNORE INTO customers (ip,name,subnet,added_by) VALUES (?,?,?,'system')",
                (ip, name, subnet)
            )
        db.commit()
        print("[init] Seed done.")
    db.close()

# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  ENT Monitor v3 — Auth + Full CRUD Backend")
    print("=" * 60)
    init_db()
    seed_customers()

    _sweep_active = True
    t = threading.Thread(target=run_sweep, daemon=True)
    t.start()

    fping_status = f"✓ {FPING_BIN}" if FPING_BIN else "✗ NOT FOUND — using system ping (install: sudo apt install fping)"
    print(f"[fping]  {fping_status}")
    print(f"[engine] Sweep every {PING_INTERVAL}s | {FPING_COUNT} probes per IP | timeout {PING_TIMEOUT}s")
    print(f"[server] Open → http://0.0.0.0:5000")
    print(f"[auth]   admin / Admin@123  |  operator / Oper@123")
    print(f"[prod]   gunicorn -c gunicorn.conf.py app:app")
    print("=" * 60)
    print("[DEV MODE] Using Flask dev server — use gunicorn for production!")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
