import win32evtlog
import win32evtlogutil
import win32con
import sqlite3
import time
import socket
import datetime
import requests
import psutil

# ── CHANGE THIS TO YOUR HASEEB-PC IP ADDRESS ──
SERVER_URL    = "http://192.168.1.12:5000/api/ingest"
HOSTNAME      = socket.gethostname()
POLL_INTERVAL = 10

LOG_CHANNELS = [
    "Security",
    "System",
    "Application",
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-PowerShell/Operational",
]

SEVERITY_MAP = {
    win32con.EVENTLOG_ERROR_TYPE:       "HIGH",
    win32con.EVENTLOG_WARNING_TYPE:     "MEDIUM",
    win32con.EVENTLOG_INFORMATION_TYPE: "INFO",
    win32con.EVENTLOG_AUDIT_FAILURE:    "HIGH",
    win32con.EVENTLOG_AUDIT_SUCCESS:    "INFO",
}

IMPORTANT_IDS = {
    4624, 4625, 4634, 4648, 4672, 4688,
    4698, 4720, 4726, 4728, 4732, 4740,
    4756, 4776, 4798, 4799, 1102, 7045,
    1116, 1117, 5001, 5010, 5012, 4104,
}

last_sent_time = {}

def read_channel(channel):
    events = []
    try:
        hand = win32evtlog.OpenEventLog(None, channel)
        raw_events = win32evtlog.ReadEventLog(
            hand,
            win32evtlog.EVENTLOG_BACKWARDS_READ |
            win32evtlog.EVENTLOG_SEQUENTIAL_READ,
            0
        )
        for event in raw_events:
            event_id = event.EventID & 0xFFFF
            if event_id not in IMPORTANT_IDS:
                continue
            severity  = SEVERITY_MAP.get(event.EventType, "INFO")
            timestamp = str(event.TimeGenerated)
            try:
                msg = win32evtlogutil.SafeFormatMessage(event, channel)
            except Exception:
                msg = "Message unavailable"

            events.append({
                "event_id":  event_id,
                "severity":  severity,
                "timestamp": timestamp,
                "source":    event.SourceName,
                "hostname":  HOSTNAME,
                "category":  channel.split("/")[0],
                "message":   (msg or "")[:500],
                "raw":       f"EventID:{event_id}"
            })
        win32evtlog.CloseEventLog(hand)
    except Exception as e:
        if "not found" not in str(e).lower():
            print(f"[AGENT] Channel error: {e}")
    return events

def collect_network():
    events = []
    try:
        suspicious_ports = [4444, 5555, 6666, 1337, 31337]
        for conn in psutil.net_connections(kind="inet"):
            if conn.status != "ESTABLISHED" or not conn.raddr:
                continue
            if conn.raddr.port in suspicious_ports:
                try:
                    pname = psutil.Process(conn.pid).name()
                except Exception:
                    pname = "unknown"
                events.append({
                    "event_id":  9001,
                    "severity":  "HIGH",
                    "timestamp": datetime.datetime.now().strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                    "source":    "NetworkMonitor",
                    "hostname":  HOSTNAME,
                    "category":  "Suspicious network connection",
                    "message":   (
                        f"Suspicious connection from {HOSTNAME}. "
                        f"Process: {pname} PID {conn.pid}. "
                        f"Remote: {conn.raddr.ip}:{conn.raddr.port}"
                    ),
                    "raw":       f"EventID:9001"
                })
    except Exception as e:
        print(f"[AGENT] Network error: {e}")
    return events

def send_to_server(events):
    if not events:
        return 0
    try:
        response = requests.post(
            SERVER_URL,
            json={"events": events},
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            return data.get("saved", 0)
        else:
            print(f"[AGENT] Server error: {response.status_code}")
            return 0
    except requests.exceptions.ConnectionError:
        print(f"[AGENT] Cannot reach server at {SERVER_URL}")
        print(f"[AGENT] Make sure Haseeb-pc is running and reachable")
        return 0
    except Exception as e:
        print(f"[AGENT] Send error: {e}")
        return 0

def run_agent():
    print(f"[AGENT] Starting on: {HOSTNAME}")
    print(f"[AGENT] Sending logs to: {SERVER_URL}")
    print(f"[AGENT] Poll interval: {POLL_INTERVAL} seconds")
    print("-" * 52)

    cycle = 0
    while True:
        cycle += 1
        now   = datetime.datetime.now().strftime("%H:%M:%S")
        all_events = []

        for channel in LOG_CHANNELS:
            events = read_channel(channel)
            all_events.extend(events[:20])

        net_events = collect_network()
        all_events.extend(net_events)

        saved = send_to_server(all_events)
        print(f"[{now}] Cycle {cycle} — sent {len(all_events)} events → server saved {saved}")

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    run_agent()