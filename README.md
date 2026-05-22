# ENT Monitor Overview — Details, Setup & Production Guide

<img width="685" height="358" alt="Screenshot from 2026-05-22 20-44-54" src="https://github.com/user-attachments/assets/c9a2c0c3-5667-44b9-b013-167d8e314ba0" />
<img width="685" height="358" alt="Screenshot from 2026-05-22 20-45-11" src="https://github.com/user-attachments/assets/06f77a2a-8d81-47a6-b7e8-701de024d581" />
Here is the beginner-friendly visual explanation of app_35.py of ent ip monitoring dashboard created by us.
Now I have everything I need. Let me build a comprehensive, beginner-friendly visual explanation.


Here's a full walkthrough of everything in my app, section by section:

What the app does, in one sentence: 
It continuously pings ~378 customer public IP addresses (businesses on my network), records whether each one is online or offline, and serves that data to a web dashboard with login-protected access.

The libraries i imported
Flask is the heart of the app — it's a Python web framework that lets i define URL routes (like /api/customers) and return data to the browser. flask_cors allows the browser frontend (dashboard1.html) to talk to Flask even if they're on different origins. bcrypt securely hashes passwords before saving them — even if my database is stolen, passwords aren't readable. sqlite3 is Python's built-in database driver for the lightweight SQLite database file (ent_monitor.db). threading runs the background pinger loop in a separate thread so it doesn't block Flask from answering requests. subprocess lets Python run an external program — in this case, fping.

The ping engine: fping + chunked two-pass sweep
fping is a Linux command-line tool that can ping hundreds of IPs simultaneously (much faster than Python's built-in ping). my app runs it via subprocess.run(). The clever part is the two-pass chunked approach:
Pass 1 sends a single quick probe to all ~378 IPs split into chunks of 100. Any IP that responds is immediately marked online. Pass 2 retries only the ones that didn't respond — sending 3 probes this time to catch transient drops. This avoids false "offline" readings caused by brief network hiccups.

Hysteresis: stopping false alarms
The hysteresis_status() function is my anti-flapping filter. A host is only marked offline after failing 2 consecutive sweeps, not just one. This means a single bad ping result won't flip a customer's status from green to red. Recovery is immediate — one successful ping and they're back online.

The database (SQLite)
Four tables: users stores staff accounts with hashed passwords and roles. customers holds each customer's IP address and name (the ~378 entries in SEED_DATA at the bottom of the file). ping_results stores the history of every ping check (up to 200 results per IP). audit_log records every action any user takes — logins, edits, deletions.

The role system
Three levels: admin can do everything including deleting customers and managing users. operator can add/edit customers and run pings. viewer can only look. The @require_login, @require_operator, and @require_admin decorators on each route enforce these rules automatically — they're like a security guard at the door of each API endpoint.

The API routes
Each @app_35.route(...) defines a URL the browser can call. For example, when the dashboard loads, it calls GET /api/stats to get the count of online/offline customers, and GET /api/customers to get the full list with latest statuses. When an operator clicks "ping now", the browser calls GET /api/ping/<ip>, which immediately runs fping on that single IP and returns the result.

The seed data
The huge SEED_DATA list at the bottom is my initial customer database — Nepali hospitals, hotels, TV stations, schools, and businesses. The seed_customers() function inserts them all into the database on first run, but only if the table is empty.

How it all starts
When i run python app_35.py, three things happen in order: init_db() creates the tables, seed_customers() populates the customer list, and start_internal_sweeper() launches the background thread that pings everyone every 30 seconds. Then Flask starts listening on port 5001 and i open the dashboard in my browser.


##

<img width="1307" height="711" alt="image" src="https://github.com/user-attachments/assets/b844f9fc-5611-40d0-a2f6-515edfd86702" />

<img width="1307" height="711" alt="image" src="https://github.com/user-attachments/assets/7b27bf88-e2be-4535-91d3-0b7bc96fc49e" />

<img width="1307" height="711" alt="image" src="https://github.com/user-attachments/assets/abecf8bc-fd67-4014-ae56-c8dd407b9d6f" />



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
| biyudh | ********** | Full access — users, delete, audit log |
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
