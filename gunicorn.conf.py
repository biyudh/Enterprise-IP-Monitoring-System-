# ─────────────────────────────────────────────────────────────────
#  gunicorn.conf.py  —  ENT Monitor Production Config. 
# ─────────────────────────────────────────────────────────────────
#  Run with:   gunicorn -c gunicorn.conf.py app:app 
# ─────────────────────────────────────────────────────────────────
import multiprocessing, os

# ── Binding ──────────────────────────────────────────────────────
bind            = "0.0.0.0:5000"      # change port here if needed

# ── Workers ──────────────────────────────────────────────────────
# Rule of thumb: (2 × CPU cores) + 1
# For a monitoring app with I/O-heavy ping threads, use "gthread"
# worker class with multiple threads per worker.
workers         = 2                   # keep low — ping threads are per-process
worker_class    = "gthread"           # threaded workers (needed for background sweep)
threads         = 4                   # threads per worker
worker_connections = 200

# ── Timeouts ─────────────────────────────────────────────────────
timeout         = 30                  # worker timeout in seconds
keepalive       = 5                   # keep-alive connection seconds
graceful_timeout= 10

# ── Logging ──────────────────────────────────────────────────────
loglevel        = "info"
accesslog       = "logs/access.log"
errorlog        = "logs/error.log"
capture_output  = True                # capture print() from app into errorlog
access_log_format = '%(h)s "%(r)s" %(s)s %(b)s %(D)sµs'

# ── Process naming ───────────────────────────────────────────────
proc_name       = "ent-monitor"

# ── Reload on code change (development only) ─────────────────────
reload          = False               # set True during development
reload_engine   = "auto"

# ── Security ─────────────────────────────────────────────────────
limit_request_line   = 4094
limit_request_fields = 100
forwarded_allow_ips  = "*"           # set to nginx IP in production

# ── Startup hook — launch background ping sweep once per master ──
# IMPORTANT: The sweep thread must be started here so it runs once,
# not once per worker (which would cause duplicate pings).
def on_starting(server):
    """Called once when gunicorn master starts — launch ping sweep."""
    import threading, app as application
    application.init_db()
    application.seed_customers()
    application._sweep_active = True
    t = threading.Thread(target=application.run_sweep, daemon=True)
    t.start()
    fping = "✓ fping" if application.FPING_BIN else "✗ fping missing — using system ping"
    server.log.info(f"[ENT Monitor] Ping sweep started | {fping}")
    server.log.info(f"[ENT Monitor] DB: {application.DB_PATH}")

def on_exit(server):
    """Graceful shutdown — stop ping sweep."""
    try:
        import app as application
        application._sweep_active = False
        server.log.info("[ENT Monitor] Ping sweep stopped.")
    except Exception:
        pass
