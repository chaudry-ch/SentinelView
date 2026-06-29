import win32evtlog
import win32evtlogutil
import win32con
import sqlite3
import time
import socket
import datetime
import subprocess
import psutil

DB_PATH       = r"C:\SentinelView\database\sentinel.db"
HOSTNAME      = socket.gethostname()
POLL_INTERVAL = 5

LOG_CHANNELS = [
    "Security",
    "System",
    "Application",
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "Microsoft-Windows-TaskScheduler/Operational",
    "Microsoft-Windows-DriverFrameworks-UserMode/Operational",
]

SEVERITY_MAP = {
    win32con.EVENTLOG_ERROR_TYPE:       "HIGH",
    win32con.EVENTLOG_WARNING_TYPE:     "MEDIUM",
    win32con.EVENTLOG_INFORMATION_TYPE: "INFO",
    win32con.EVENTLOG_AUDIT_FAILURE:    "HIGH",
    win32con.EVENTLOG_AUDIT_SUCCESS:    "INFO",
}

IMPORTANT_EVENT_IDS = {
    # Security
    4624: "Successful logon",
    4625: "Failed logon",
    4634: "Logoff",
    4648: "Logon with explicit credentials",
    4672: "Special privileges assigned",
    4688: "New process created",
    4698: "Scheduled task created",
    4699: "Scheduled task deleted",
    4700: "Scheduled task enabled",
    4720: "User account created",
    4722: "User account enabled",
    4725: "User account disabled",
    4726: "User account deleted",
    4728: "Member added to security group",
    4732: "Member added to local group",
    4740: "Account locked out",
    4756: "Member added to universal group",
    4776: "Credential validation attempt",
    4798: "User local group membership enumerated",
    4799: "Security group membership enumerated",
    1102: "Audit log cleared",
    # System
    7045: "New service installed",
    7036: "Service state changed",
    7040: "Service start type changed",
    # Windows Defender
    1116: "Defender malware detected",
    1117: "Defender action taken on malware",
    1118: "Defender remediation started",
    1119: "Defender remediation succeeded",
    1120: "Defender remediation failed",
    5001: "Defender real-time protection disabled",
    5010: "Defender scanning disabled",
    5012: "Defender tamper detected",
    # PowerShell
    4103: "PowerShell module logging",
    4104: "PowerShell script block logging",
    # RDP / Terminal Services
    21:   "RDP logon success",
    23:   "RDP logon failed",
    24:   "RDP session disconnected",
    25:   "RDP session reconnected",
    # Task Scheduler
    106:  "Task registered",
    140:  "Task updated",
    141:  "Task deleted",
    200:  "Task executed",
    201:  "Task completed",
    # USB
    2003: "USB device inserted",
    2004: "USB device removed",
}

def get_db():
    return sqlite3.connect(DB_PATH)

def save_event(timestamp, event_id, source, hostname,
               category, severity, message, raw):
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO events
            (timestamp, event_id, source, hostname,
             category, severity, message, raw_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp, event_id, source, hostname,
              category, severity, message, raw))
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()

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
            severity = SEVERITY_MAP.get(event.EventType, "INFO")
            timestamp = str(event.TimeGenerated)

            try:
                msg = win32evtlogutil.SafeFormatMessage(event, channel)
            except Exception:
                msg = "Message unavailable"

            if event_id in IMPORTANT_EVENT_IDS:
                category = IMPORTANT_EVENT_IDS[event_id]
                if event_id in [4625, 4740, 1102, 7045,
                                 4720, 4726, 1116, 1117,
                                 5001, 5010, 5012, 4104]:
                    severity = "HIGH"
                elif event_id in [4672, 1120]:
                    severity = "CRITICAL"
            else:
                category = channel.split("/")[0]

            events.append({
                "event_id":  event_id,
                "severity":  severity,
                "timestamp": timestamp,
                "source":    event.SourceName,
                "category":  category,
                "message":   (msg or "")[:500],
                "raw":       f"EventID:{event_id}"
            })

        win32evtlog.CloseEventLog(hand)
    except Exception as e:
        if "not found" not in str(e).lower():
            print(f"[COLLECTOR] Channel error ({channel.split('/')[0]}): {e}")
    return events

def collect_network_connections():
    events = []
    try:
        suspicious_ports = [
            4444, 5555, 6666, 7777, 8888, 9999,
            1337, 31337, 12345, 54321
        ]
        suspicious_ips_prefix = [
            "185.", "45.", "194.", "198.", "91."
        ]
        conns = psutil.net_connections(kind="inet")
        for conn in conns:
            if conn.status != "ESTABLISHED":
                continue
            if not conn.raddr:
                continue
            rip   = conn.raddr.ip
            rport = conn.raddr.port
            flagged = False
            reason  = ""

            if rport in suspicious_ports:
                flagged = True
                reason  = f"Suspicious port {rport}"
            elif any(rip.startswith(p) for p in suspicious_ips_prefix):
                flagged = True
                reason  = f"Suspicious IP range {rip}"

            if flagged:
                try:
                    proc = psutil.Process(conn.pid)
                    pname = proc.name()
                except Exception:
                    pname = "unknown"

                events.append({
                    "event_id":  9001,
                    "severity":  "HIGH",
                    "timestamp": datetime.datetime.now().strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                    "source":    "NetworkMonitor",
                    "category":  "Suspicious network connection",
                    "message":   (
                        f"Suspicious outbound connection. "
                        f"Process: {pname} (PID {conn.pid}). "
                        f"Remote: {rip}:{rport}. "
                        f"Reason: {reason}"
                    ),
                    "raw":       f"EventID:9001 IP:{rip} Port:{rport}"
                })
    except Exception as e:
        print(f"[COLLECTOR] Network monitor error: {e}")
    return events

def collect_defender_status():
    events = []
    try:
        result = subprocess.run(
            ["powershell", "-Command",
             "Get-MpComputerStatus | Select-Object "
             "RealTimeProtectionEnabled, "
             "AntivirusEnabled, "
             "AntispywareEnabled | "
             "ConvertTo-Json"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0 and result.stdout:
            import json
            status = json.loads(result.stdout)
            if not status.get("RealTimeProtectionEnabled", True):
                events.append({
                    "event_id":  5001,
                    "severity":  "CRITICAL",
                    "timestamp": datetime.datetime.now().strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                    "source":    "WindowsDefender",
                    "category":  "Defender real-time protection disabled",
                    "message":   (
                        "Windows Defender real-time protection "
                        "is DISABLED. System is unprotected."
                    ),
                    "raw":       "EventID:5001"
                })
    except Exception:
        pass
    return events

def collect_once():
    collected = 0

    for channel in LOG_CHANNELS:
        events = read_channel(channel)
        for ev in events[:30]:
            save_event(
                ev["timestamp"], ev["event_id"],
                ev["source"],    HOSTNAME,
                ev["category"],  ev["severity"],
                ev["message"],   ev["raw"]
            )
            collected += 1

    net_events = collect_network_connections()
    for ev in net_events:
        save_event(
            ev["timestamp"], ev["event_id"],
            ev["source"],    HOSTNAME,
            ev["category"],  ev["severity"],
            ev["message"],   ev["raw"]
        )
        collected += 1

    defender_events = collect_defender_status()
    for ev in defender_events:
        save_event(
            ev["timestamp"], ev["event_id"],
            ev["source"],    HOSTNAME,
            ev["category"],  ev["severity"],
            ev["message"],   ev["raw"]
        )
        collected += 1

    return collected

def run_collector():
    print(f"[COLLECTOR] Starting on: {HOSTNAME}")
    print(f"[COLLECTOR] Monitoring:")
    print(f"            Windows Security · System · Application")
    print(f"            Windows Defender · PowerShell · RDP")
    print(f"            Task Scheduler · USB · Network connections")
    print(f"[COLLECTOR] Poll interval: {POLL_INTERVAL} seconds")
    print("-" * 52)

    cycle = 0
    while True:
        cycle += 1
        count = collect_once()
        now   = datetime.datetime.now().strftime("%H:%M:%S")
        print(f"[{now}] Cycle {cycle} — collected {count} events")
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    run_collector()