import sqlite3
import datetime
import threading
import time
from flask import Flask, jsonify, request, send_from_directory
from flask_socketio import SocketIO, emit
import os

DB_PATH   = r"C:\SentinelView\database\sentinel.db"
FRONTEND  = r"C:\SentinelView\frontend"

app    = Flask(__name__, static_folder=FRONTEND)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ── Serve dashboard ────────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory(FRONTEND, "index.html")

# ── GET /api/alerts ────────────────────────────────────────────────
@app.route("/api/alerts")
def get_alerts():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, timestamp, rule_name, severity,
               source_ip, hostname, event_id,
               description, responded, blocked
        FROM alerts
        ORDER BY id DESC
        LIMIT 50
    ''')
    rows = cursor.fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

# ── GET /api/events ────────────────────────────────────────────────
@app.route("/api/events")
def get_events():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, timestamp, event_id, source,
               hostname, category, severity, message
        FROM events
        ORDER BY id DESC
        LIMIT 100
    ''')
    rows = cursor.fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

# ── GET /api/stats ─────────────────────────────────────────────────
@app.route("/api/stats")
def get_stats():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM events")
    total_events = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM alerts")
    total_alerts = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM alerts WHERE responded = 0")
    open_alerts = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM alerts WHERE blocked = 1")
    total_blocks = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'CRITICAL'")
    critical = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'HIGH'")
    high = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM soar_actions")
    soar_actions = cursor.fetchone()[0]

    cursor.execute('''
        SELECT COUNT(*) FROM events
        WHERE datetime(created_at) > datetime('now', '-1 minute')
    ''')
    eps = cursor.fetchone()[0]

    conn.close()
    return jsonify({
        "total_events":  total_events,
        "total_alerts":  total_alerts,
        "open_alerts":   open_alerts,
        "total_blocks":  total_blocks,
        "critical":      critical,
        "high":          high,
        "soar_actions":  soar_actions,
        "events_per_min": eps
    })

# ── GET /api/soar_actions ──────────────────────────────────────────
@app.route("/api/soar_actions")
def get_soar_actions():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, timestamp, action_type, target,
               command_run, result, alert_id
        FROM soar_actions
        ORDER BY id DESC
        LIMIT 50
    ''')
    rows = cursor.fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

# ── POST /api/block ────────────────────────────────────────────────
@app.route("/api/block", methods=["POST"])
def manual_block():
    data    = request.get_json()
    ip      = data.get("ip", "")
    alert_id = data.get("alert_id", 0)

    if not ip:
        return jsonify({"status": "error", "message": "No IP provided"}), 400

    import subprocess
    rule_name = f"SENTINEL_BLOCK_{ip}"
    command = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}",
        "dir=in", "action=block",
        f"remoteip={ip}",
        "protocol=any", "enable=yes"
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            conn = get_db()
            cursor = conn.cursor()
            if alert_id:
                cursor.execute(
                    "UPDATE alerts SET responded=1, blocked=1 WHERE id=?",
                    (alert_id,)
                )
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute('''
                INSERT INTO soar_actions
                (timestamp, action_type, target, command_run, result, alert_id)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (timestamp, "MANUAL_BLOCK", ip,
                  " ".join(command), "SUCCESS", alert_id))
            conn.commit()
            conn.close()
            return jsonify({"status": "success", "message": f"IP {ip} blocked"})
        else:
            return jsonify({"status": "error", "message": result.stderr}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# ── POST /api/ingest  (remote agents post here) ───────────────────
@app.route("/api/ingest", methods=["POST"])
def ingest():
    data   = request.get_json()
    events = data.get("events", [])
    conn   = get_db()
    cursor = conn.cursor()
    saved  = 0
    for ev in events:
        try:
            cursor.execute('''
                INSERT INTO events
                (timestamp, event_id, source, hostname,
                 category, severity, message, raw_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                ev.get("timestamp"), ev.get("event_id"),
                ev.get("source"),    ev.get("hostname"),
                ev.get("category"),  ev.get("severity"),
                ev.get("message"),   ev.get("raw", "")
            ))
            saved += 1
        except Exception:
            pass
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "saved": saved})

# ── Background thread — push live data every 3 seconds ────────────
def push_live_data():
    while True:
        try:
            conn = get_db()
            cursor = conn.cursor()

            cursor.execute('''
                SELECT id, timestamp, event_id, source,
                       hostname, category, severity, message
                FROM events
                ORDER BY id DESC LIMIT 5
            ''')
            events = [dict(r) for r in cursor.fetchall()]

            cursor.execute('''
                SELECT id, timestamp, rule_name, severity,
                       source_ip, hostname, description,
                       responded, blocked
                FROM alerts
                ORDER BY id DESC LIMIT 10
            ''')
            alerts = [dict(r) for r in cursor.fetchall()]

            cursor.execute("SELECT COUNT(*) FROM alerts WHERE responded=0")
            open_alerts = cursor.fetchone()[0]

            conn.close()

            socketio.emit("live_update", {
                "events":      events,
                "alerts":      alerts,
                "open_alerts": open_alerts
            })
        except Exception as e:
            print(f"[SOCKET] Push error: {e}")

        time.sleep(3)


# ── GET /api/chart-data ────────────────────────────────────────────
@app.route("/api/chart-data")
def get_chart_data():
    conn   = get_db()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT strftime('%H', created_at) as hour,
               severity,
               COUNT(*) as count
        FROM events
        WHERE datetime(created_at) > datetime('now', '-24 hours')
        GROUP BY hour, severity
        ORDER BY hour ASC
    ''')
    rows = cursor.fetchall()

    hours      = [f"{h:02d}:00" for h in range(24)]
    critical   = [0]*24
    high       = [0]*24
    medium     = [0]*24
    info       = [0]*24

    for row in rows:
        try:
            h   = int(row[0])
            sev = row[1]
            cnt = row[2]
            if sev == 'CRITICAL': critical[h] += cnt
            elif sev == 'HIGH':   high[h]     += cnt
            elif sev == 'MEDIUM': medium[h]   += cnt
            else:                 info[h]      += cnt
        except Exception:
            pass

    cursor.execute('''
        SELECT rule_name, COUNT(*) as count
        FROM alerts
        GROUP BY rule_name
        ORDER BY count DESC
        LIMIT 8
    ''')
    alert_types = [{"name": r[0], "count": r[1]}
                   for r in cursor.fetchall()]

    cursor.execute('''
        SELECT severity, COUNT(*) as count
        FROM alerts
        GROUP BY severity
    ''')
    sev_dist = {r[0]: r[1] for r in cursor.fetchall()}

    cursor.execute('''
        SELECT strftime('%H', created_at) as hour,
               COUNT(*) as count
        FROM alerts
        WHERE datetime(created_at) > datetime('now', '-24 hours')
        GROUP BY hour
        ORDER BY hour ASC
    ''')
    alert_trend = [0]*24
    for row in cursor.fetchall():
        try:
            alert_trend[int(row[0])] = row[1]
        except Exception:
            pass

    cursor.execute('''
        SELECT action_type, COUNT(*) as count
        FROM soar_actions
        GROUP BY action_type
    ''')
    soar_dist = {r[0]: r[1] for r in cursor.fetchall()}

    cursor.execute('''
        SELECT COUNT(*) FROM events
        WHERE datetime(created_at) > datetime('now', '-1 hour')
    ''')
    last_hour_events = cursor.fetchone()[0]

    cursor.execute('''
        SELECT COUNT(*) FROM alerts
        WHERE datetime(created_at) > datetime('now', '-1 hour')
    ''')
    last_hour_alerts = cursor.fetchone()[0]

    conn.close()
    return jsonify({
        "hours":            hours,
        "events_critical":  critical,
        "events_high":      high,
        "events_medium":    medium,
        "events_info":      info,
        "alert_types":      alert_types,
        "severity_dist":    sev_dist,
        "alert_trend":      alert_trend,
        "soar_dist":        soar_dist,
        "last_hour_events": last_hour_events,
        "last_hour_alerts": last_hour_alerts,
    })

# ── POST /api/soar-command ─────────────────────────────────────────
@app.route("/api/soar-command", methods=["POST"])
def soar_command():
    data    = request.get_json()
    command = data.get("command","")
    target  = data.get("target","")
    if not command:
        return jsonify({"status":"error","message":"No command"}), 400
    conn   = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS soar_commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            command TEXT,
            target TEXT,
            executed INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute(
        "INSERT INTO soar_commands (command,target) VALUES (?,?)",
        (command, target)
    )
    conn.commit()
    conn.close()
    return jsonify({"status":"ok","message":f"Command {command} queued"})
# ── Start ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("[SERVER] SentinelView API starting...")
    print("[SERVER] Dashboard → http://localhost:5000")
    print("[SERVER] API endpoints:")
    print("         GET  /api/alerts")
    print("         GET  /api/events")
    print("         GET  /api/stats")
    print("         GET  /api/soar_actions")
    print("         POST /api/block")
    print("         POST /api/ingest")
    print("-" * 50)

    t = threading.Thread(target=push_live_data, daemon=True)
    t.start()

    socketio.run(app, host="0.0.0.0", port=5000, debug=False) 
