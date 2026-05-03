# ENT Monitor v4 — Setup & Production Guide

## Files in this package

| File | Purpose |
|------|---------|
| `app.py` | Flask backend — fping engine + API + auth |
| `dashboard.html` | Frontend — served by Flask/Gunicorn |
| `gunicorn.conf.py` | Production WSGI server config |
| `ent-monitor.service` | systemd service (auto-start on boot) |
| `README.md` | This file |

---

## 1. Install dependencies

```bash
# Python packages
pip install flask flask-cors bcrypt gunicorn

# fping — REQUIRED for stable ping results
sudo apt install fping          # Ubuntu / Debian / Kali
sudo yum install fping          # CentOS / RHEL / Rocky
sudo pacman -S fping            # Arch Linux

# Verify fping works
fping -v
fping -c 3 8.8.8.8
```

---

## 2. Why fping instead of system ping?

| | System `ping` | `fping` |
|--|--|--|
| Per sweep call | 1 subprocess per IP = 379 processes | **1 subprocess for all 379 IPs** |
| Probes per check | 1 (unreliable) | 5 (averaged — stable) |
| Sweep speed (379 IPs) | ~15–30 seconds | **< 2 seconds** |
| Jitter / fluctuation | High (single sample) | Low (avg of 5 probes) |
| Loss detection | Binary (pass/fail) | **% packet loss reported** |
| CPU usage | High (many processes) | Very low (one process) |

### How fping is configured in `app.py`

```python
PING_INTERVAL  = 5     # sweep every 5 seconds
PING_TIMEOUT   = 1     # 1 second timeout per probe
FPING_COUNT    = 5     # 5 probes per IP — results are averaged
FPING_INTERVAL = 50    # 50ms between probes to same host
```
```Actual
# ── Config ────────────────────────────────────────────────────────────────────
DB_PATH         = "ent_monitor.db"
PING_INTERVAL   = 5       # seconds between full sweeps (8s gives clean non-overlapping cycles)
PING_TIMEOUT    = 2000    # per-probe timeout in ms (2000ms = 2s)
FPING_COUNT     = 5       # probes per IP — 5 is most thorough
FPING_INTERVAL  = 100      # ms between probes to SAME host
HISTORY_LIMIT   = 200     # ping history rows kept per IP
SESSION_HOURS   = 8



The effective command run per sweep:
```bash
fping -c 5 -t 1000 -p 50 -q -A \
  103.180.241.129 103.180.241.130 103.180.241.131 ... (all 379 IPs)
```

Output parsed:
```
103.180.241.132 : xmt/rcv/%loss = 5/5/0%,  min/avg/max = 1.20/1.85/2.40
103.180.241.133 : xmt/rcv/%loss = 5/3/40%, min/avg/max = 8.10/9.20/10.40
103.180.241.134 : xmt/rcv/%loss = 5/0/100% (unreachable)
```

- **≥ 50% loss** → marked `offline`
- **< 50% loss** → marked `online` with **averaged latency**

---

## 3. Development mode (quick test)

```bash
cd /home/yudha/ent-monitor/test3-monitor
source myvenv/bin/activate
python app.py
```

Open: `http://localhost:5000`

---

## 4. Production mode with Gunicorn

### Why not Flask dev server in production?

| | Flask dev server | Gunicorn |
|--|--|--|
| Concurrent requests | 1 at a time | Many (workers × threads) |
| Stability | Crashes on errors | Auto-restarts workers |
| Performance | Single thread | Multi-worker + threads |
| Security | Debug info exposed | Production-hardened |
| Logging | Console only | Structured log files |

### Run with Gunicorn

```bash
cd /home/yudha/ent-monitor/test3-monitor
source myvenv/bin/activate

# Create logs directory first
mkdir -p logs

# Start
gunicorn -c gunicorn.conf.py app:app

# Or run in background
gunicorn -c gunicorn.conf.py app:app --daemon
```

---

## 5. Production with systemd (auto-start on boot)

```bash
# Edit the service file — update paths to match your system
nano ent-monitor.service

# Install the service
sudo cp ent-monitor.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable ent-monitor      # auto-start on boot
sudo systemctl start ent-monitor       # start now

# Check status
sudo systemctl status ent-monitor

# View live logs
sudo journalctl -u ent-monitor -f

# Restart after code changes
sudo systemctl restart ent-monitor
```

---

## 6. Production with Nginx (reverse proxy — recommended)

Put Nginx in front of Gunicorn so:
- Port 80/443 is used instead of 5000
- HTTPS/SSL terminates at Nginx
- Static files are served efficiently

```bash
sudo apt install nginx
sudo nano /etc/nginx/sites-available/ent-monitor
```

Paste this:
```nginx
server {
    listen 80;
    server_name 192.168.18.133;   # your server IP or domain

    location / {
        proxy_pass         http://127.0.0.1:5000;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 30;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/ent-monitor /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

Now any PC opens `http://192.168.18.133` (no port needed).

---

## 7. fping permission (if ping fails with permission error)

fping needs raw socket access. If you see permission errors:

```bash
# Option A — setuid (most common fix)
sudo chmod u+s $(which fping)

# Option B — capabilities (more secure)
sudo setcap cap_net_raw+ep $(which fping)

# Verify
fping -c 1 8.8.8.8
```

---

## 8. Default login credentials

| Username | Password | Role |
|----------|----------|------|
| admin | Admin@123 | Full access — users, delete, audit log |
| operator | Oper@123 | View + ping + edit customers |

**Change these immediately after first login** via the "Change Password" menu.

---

## 9. Architecture summary

```
Browser (any PC on LAN)
        │  HTTP
        ▼
   Nginx :80  (optional reverse proxy)
        │
        ▼
 Gunicorn :5000
   Worker 1 (gthread, 4 threads)
   Worker 2 (gthread, 4 threads)
        │ serves API requests
        ▼
    app.py (Flask)
        │
        ├─► SQLite DB (ent_monitor.db)
        │      ├ users
        │      ├ customers
        │      ├ ping_results
        │      └ audit_log
        │
        └─► Background sweep thread (runs in master process)
               └─► fping bulk call every 5s → all 379 IPs at once
```
