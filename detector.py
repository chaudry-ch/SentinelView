import sqlite3
import time
import datetime
from collections import defaultdict

DB_PATH        = r"C:\SentinelView\database\sentinel.db"
POLL_INTERVAL  = 5
last_checked_id = 0

def get_db():
    return sqlite3.connect(DB_PATH)

def get_new_events():
    global last_checked_id
    conn   = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, timestamp, event_id, source,
               hostname, category, severity, message
        FROM events
        WHERE id > ?
        ORDER BY id ASC
    ''', (last_checked_id,))
    rows = cursor.fetchall()
    conn.close()
    if rows:
        last_checked_id = rows[-1][0]
    return rows

def create_alert(rule_name, severity, source_ip,
                 hostname, event_id, description):
    conn   = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id FROM alerts
        WHERE rule_name = ? AND hostname = ?
        AND datetime(created_at) > datetime('now', '-60 minutes')
    ''', (rule_name, hostname))
    if cursor.fetchone():
        conn.close()
        return False

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute('''
        INSERT INTO alerts
        (timestamp, rule_name, severity, source_ip,
         hostname, event_id, description)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (timestamp, rule_name, severity, source_ip,
          hostname, event_id, description))
    conn.commit()
    conn.close()

    now = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{now}] *** ALERT [{severity}] {rule_name} on {hostname}")
    print(f"         {description[:80]}")
    return True

class ThreatDetector:
    def __init__(self):
        self.failed_logins    = defaultdict(list)
        self.process_creates  = defaultdict(list)
        self.rdp_failures     = defaultdict(list)
        self.net_connections  = defaultdict(list)
        self.group_enumerations = defaultdict(list)

    def clean_old(self):
        cutoff = time.time() - 300
        for d in [self.failed_logins, self.process_creates,
                  self.rdp_failures, self.net_connections,
                  self.group_enumerations]:
            for k in list(d.keys()):
                d[k] = [t for t in d[k] if t > cutoff]

    def analyze(self, events):
        self.clean_old()
        now = time.time()

        for row in events:
            (ev_id, timestamp, event_id, source,
             hostname, category, severity, message) = row
            msg = (message or "").lower()

            # ── Brute Force ────────────────────────────────────────
            if event_id == 4625:
                self.failed_logins[hostname].append(now)
                count = len(self.failed_logins[hostname])
                if count >= 5:
                    create_alert(
                        "Brute Force Login Detected", "CRITICAL",
                        hostname, hostname, 4625,
                        f"{count} failed logins in 5 min on {hostname}."
                    )

            # ── Account Lockout ────────────────────────────────────
            elif event_id == 4740:
                create_alert(
                    "Account Locked Out", "HIGH",
                    hostname, hostname, 4740,
                    f"Account locked out on {hostname}. Possible attack."
                )

            # ── Audit Log Cleared ──────────────────────────────────
            elif event_id == 1102:
                create_alert(
                    "Security Audit Log Cleared", "CRITICAL",
                    hostname, hostname, 1102,
                    f"Audit log cleared on {hostname}. Attacker hiding tracks."
                )

            # ── New User Account ───────────────────────────────────
            elif event_id == 4720:
                create_alert(
                    "New User Account Created", "HIGH",
                    hostname, hostname, 4720,
                    f"New user account created on {hostname}. Verify authorization."
                )

            # ── User Account Deleted ───────────────────────────────
            elif event_id == 4726:
                create_alert(
                    "User Account Deleted", "HIGH",
                    hostname, hostname, 4726,
                    f"User account deleted on {hostname}. Possible cleanup by attacker."
                )

            # ── New Service ────────────────────────────────────────
            elif event_id == 7045:
                create_alert(
                    "New Service Installed", "HIGH",
                    hostname, hostname, 7045,
                    f"New service installed on {hostname}. Malware persistence tactic."
                )

            # ── Scheduled Task ─────────────────────────────────────
            elif event_id in [4698, 106]:
                create_alert(
                    "Scheduled Task Created", "MEDIUM",
                    hostname, hostname, event_id,
                    f"Scheduled task created on {hostname}. Attacker persistence tactic."
                )

            # ── Dangerous Privilege ────────────────────────────────
            elif event_id == 4672:
                if any(p in msg for p in [
                    "sedebuggerprivilege", "setcbprivilege",
                    "seimpersonateprivilege"
                ]):
                    create_alert(
                        "Dangerous Privilege Assigned", "CRITICAL",
                        hostname, hostname, 4672,
                        f"SeDebug/SeTcb privilege on {hostname}. Mimikatz signature."
                    )

            # ── Suspicious Process ─────────────────────────────────
            elif event_id == 4688:
                keywords = [
                    "powershell", "cmd.exe", "wscript", "cscript",
                    "mshta", "regsvr32", "certutil", "bitsadmin",
                    "wget", "curl", "nc.exe", "ncat", "mimikatz",
                    "psexec", "wmic", "rundll32", "msiexec"
                ]
                if any(k in msg for k in keywords):
                    self.process_creates[hostname].append(now)
                    if len(self.process_creates[hostname]) >= 3:
                        create_alert(
                            "Suspicious Process Execution", "HIGH",
                            hostname, hostname, 4688,
                            f"Suspicious process chain on {hostname}. Possible malware."
                        )

            # ── After Hours Login ──────────────────────────────────
            elif event_id == 4624:
                try:
                    dt   = datetime.datetime.strptime(
                        timestamp[:19], "%Y-%m-%d %H:%M:%S"
                    )
                    hour = dt.hour
                    if hour < 7 or hour > 22:
                        create_alert(
                            "After-Hours Login", "MEDIUM",
                            hostname, hostname, 4624,
                            f"Login at {dt.strftime('%H:%M')} on {hostname}. Outside working hours."
                        )
                except Exception:
                    pass

            # ── Windows Defender Malware Detected ─────────────────
            elif event_id == 1116:
                create_alert(
                    "Malware Detected by Defender", "CRITICAL",
                    hostname, hostname, 1116,
                    f"Windows Defender detected malware on {hostname}. Immediate action required."
                )

            # ── Defender Disabled ──────────────────────────────────
            elif event_id in [5001, 5010, 5012]:
                create_alert(
                    "Windows Defender Disabled", "CRITICAL",
                    hostname, hostname, event_id,
                    f"Windows Defender protection disabled on {hostname}. System is unprotected."
                )

            # ── Defender Action Failed ─────────────────────────────
            elif event_id == 1120:
                create_alert(
                    "Defender Remediation Failed", "HIGH",
                    hostname, hostname, 1120,
                    f"Defender failed to remove malware on {hostname}. Manual action needed."
                )

            # ── PowerShell Suspicious Script ───────────────────────
            elif event_id == 4104:
                ps_suspicious = [
                    "invoke-expression", "iex(",
                    "downloadstring", "downloadfile",
                    "bypass", "encodedcommand",
                    "webclient", "shellcode",
                    "mimikatz", "invoke-mimikatz",
                    "invoke-bloodhound", "invoke-empire"
                ]
                if any(k in msg for k in ps_suspicious):
                    create_alert(
                        "Malicious PowerShell Detected", "CRITICAL",
                        hostname, hostname, 4104,
                        f"Malicious PowerShell script on {hostname}. Possible download cradle or encoded payload."
                    )

            # ── RDP Brute Force ────────────────────────────────────
            elif event_id == 23:
                self.rdp_failures[hostname].append(now)
                if len(self.rdp_failures[hostname]) >= 5:
                    create_alert(
                        "RDP Brute Force Detected", "CRITICAL",
                        hostname, hostname, 23,
                        f"Multiple RDP login failures on {hostname}. Remote desktop attack."
                    )

            # ── RDP Success After Hours ────────────────────────────
            elif event_id == 21:
                try:
                    dt   = datetime.datetime.strptime(
                        timestamp[:19], "%Y-%m-%d %H:%M:%S"
                    )
                    if dt.hour < 7 or dt.hour > 22:
                        create_alert(
                            "After-Hours RDP Login", "HIGH",
                            hostname, hostname, 21,
                            f"RDP login at {dt.strftime('%H:%M')} on {hostname}. Outside working hours."
                        )
                except Exception:
                    pass

            # ── USB Device Inserted ────────────────────────────────
            elif event_id in [2003, 2004]:
                create_alert(
                    "USB Device Connected", "MEDIUM",
                    hostname, hostname, event_id,
                    f"USB storage device connected to {hostname}. Possible data exfiltration risk."
                )

            # ── Suspicious Network Connection ──────────────────────
            elif event_id == 9001:
                self.net_connections[hostname].append(now)
                create_alert(
                    "Suspicious Network Connection", "HIGH",
                    hostname, hostname, 9001,
                    f"Suspicious outbound connection from {hostname}. {message[:100]}"
                )

            # ── Group Membership Enumeration ───────────────────────
            elif event_id in [4798, 4799]:
                self.group_enumerations[hostname].append(now)
                if len(self.group_enumerations[hostname]) >= 3:
                    create_alert(
                        "Reconnaissance Detected", "HIGH",
                        hostname, hostname, event_id,
                        f"Group/user enumeration on {hostname}. Possible attacker mapping the network."
                    )

            # ── Member Added to Admin Group ────────────────────────
            elif event_id in [4728, 4732, 4756]:
                create_alert(
                    "User Added to Privileged Group", "CRITICAL",
                    hostname, hostname, event_id,
                    f"User added to admin/privileged group on {hostname}. Possible privilege escalation."
                )

def run_detector():
    print("[DETECTOR] Threat detection engine started.")
    print("[DETECTOR] Rules active:")
    print("           Brute Force · Lockout · Audit Clear · New User")
    print("           Malware · Defender Disabled · PowerShell · RDP")
    print("           USB · Network · Privilege Escalation · Recon")
    print("-" * 52)

    detector = ThreatDetector()
    cycle    = 0

    while True:
        cycle  += 1
        events  = get_new_events()
        now     = datetime.datetime.now().strftime("%H:%M:%S")
        if events:
            print(f"[{now}] Cycle {cycle} — checking {len(events)} events")
            detector.analyze(events)
        else:
            print(f"[{now}] Cycle {cycle} — no new events")
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    run_detector()