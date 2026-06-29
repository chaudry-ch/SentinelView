import sqlite3
import subprocess
import datetime
import time
import psutil
import smtplib
import socket
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

DB_PATH       = r"C:\SentinelView\database\sentinel.db"
POLL_INTERVAL = 5
HOSTNAME      = socket.gethostname()

# EMAIL SETTINGS - fill these in before running
EMAIL_ENABLED  = True
EMAIL_SENDER   = "your_gmail@gmail.com"
EMAIL_PASSWORD = "your_gmail_app_password_here"
EMAIL_RECEIVER = "your_gmail@gmail.com"
SMTP_SERVER    = "smtp.gmail.com"
SMTP_PORT      = 587

def get_db():
    return sqlite3.connect(DB_PATH)

def get_unresponded_alerts():
    conn   = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, rule_name, severity, source_ip,
               hostname, event_id, description
        FROM alerts
        WHERE responded = 0
        AND severity IN ('CRITICAL','HIGH')
        ORDER BY id ASC
    ''')
    rows = cursor.fetchall()
    conn.close()
    return rows

def mark_responded(alert_id, blocked=False):
    conn   = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE alerts
        SET responded = 1, blocked = ?
        WHERE id = ?
    ''', (1 if blocked else 0, alert_id))
    conn.commit()
    conn.close()

def log_action(alert_id, action_type, target, command, result):
    conn   = get_db()
    cursor = conn.cursor()
    ts     = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute('''
        INSERT INTO soar_actions
        (timestamp, action_type, target, command_run, result, alert_id)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (ts, action_type, target, command, result, alert_id))
    conn.commit()
    conn.close()

def is_blocked(ip):
    try:
        r = subprocess.run(
            ['netsh','advfirewall','firewall','show','rule',
             'name=SENTINEL_BLOCK_'+ip],
            capture_output=True, text=True
        )
        return 'No rules match' not in r.stdout
    except Exception:
        return False

def block_ip(ip, alert_id, reason):
    now   = datetime.datetime.now().strftime("%H:%M:%S")
    local = ['','local','localhost', HOSTNAME.lower()]

    if not ip or ip.lower() in local:
        print("["+now+"] [SOAR] Skip block - local event, no external IP")
        mark_responded(alert_id, blocked=False)
        log_action(alert_id, "SKIP", ip or "none", "none",
                   "Local event - no external IP to block")
        return

    if is_blocked(ip):
        print("["+now+"] [SOAR] "+ip+" already blocked")
        mark_responded(alert_id, blocked=True)
        return

    rule = "SENTINEL_BLOCK_"+ip
    cmd  = ['netsh','advfirewall','firewall','add','rule',
            'name='+rule,'dir=in','action=block',
            'remoteip='+ip,'protocol=any','enable=yes']
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            print("["+now+"] [SOAR] *** BLOCKED IP: "+ip+" ***")
            mark_responded(alert_id, blocked=True)
            log_action(alert_id, "BLOCK_IP", ip, ' '.join(cmd),
                       "SUCCESS - "+r.stdout.strip())
        else:
            print("["+now+"] [SOAR] Block failed: "+r.stderr.strip())
            mark_responded(alert_id, blocked=False)
            log_action(alert_id, "BLOCK_IP", ip, ' '.join(cmd),
                       "FAILED - "+r.stderr.strip())
    except Exception as e:
        print("["+now+"] [SOAR] Block error: "+str(e))
        log_action(alert_id, "BLOCK_IP", ip, ' '.join(cmd),
                   "ERROR: "+str(e))

def isolate_host(alert_id, reason):
    now = datetime.datetime.now().strftime("%H:%M:%S")
    print("["+now+"] [SOAR] *** ISOLATING HOST ***")
    cmd = ['powershell','-Command',
           'Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | '
           'Disable-NetAdapter -Confirm:$false']
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if r.returncode == 0:
            print("["+now+"] [SOAR] Host isolated - network disabled")
            log_action(alert_id, "ISOLATE_HOST", HOSTNAME,
                       ' '.join(cmd), "SUCCESS - adapters disabled")
        else:
            print("["+now+"] [SOAR] Isolation failed: "+r.stderr.strip())
            log_action(alert_id, "ISOLATE_HOST", HOSTNAME,
                       ' '.join(cmd), "FAILED - "+r.stderr.strip())
    except Exception as e:
        print("["+now+"] [SOAR] Isolation error: "+str(e))

def re_enable_network():
    now = datetime.datetime.now().strftime("%H:%M:%S")
    cmd = ['powershell','-Command',
           'Get-NetAdapter | Enable-NetAdapter -Confirm:$false']
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        print("["+now+"] [SOAR] Network re-enabled")
    except Exception as e:
        print("["+now+"] [SOAR] Re-enable error: "+str(e))

def extract_username(description):
    keywords = ['account:','user:','username:','account name:']
    desc_lower = description.lower()
    for kw in keywords:
        if kw in desc_lower:
            idx   = desc_lower.index(kw) + len(kw)
            chunk = description[idx:idx+40].strip()
            user  = chunk.split()[0].strip('.,;')
            if user and user not in ['','n/a','unknown','none']:
                return user
    return None

def disable_user(username, alert_id, reason):
    now       = datetime.datetime.now().strftime("%H:%M:%S")
    protected = ['administrator','system','guest',
                 'defaultaccount','wdagutilityaccount']

    if not username or username.lower() in protected:
        print("["+now+"] [SOAR] Skip disable - protected user")
        log_action(alert_id, "SKIP", "unknown_user", "none",
                   "Protected or unknown user - not disabled")
        return

    print("["+now+"] [SOAR] *** DISABLING USER: "+username+" ***")
    cmd = ['net','user', username, '/active:no']
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            print("["+now+"] [SOAR] User "+username+" disabled")
            log_action(alert_id, "DISABLE_USER", username,
                       ' '.join(cmd), "SUCCESS - account disabled")
        else:
            print("["+now+"] [SOAR] Disable failed: "+r.stderr.strip())
            log_action(alert_id, "DISABLE_USER", username,
                       ' '.join(cmd), "FAILED - "+r.stderr.strip())
    except Exception as e:
        print("["+now+"] [SOAR] Disable error: "+str(e))

def scan_processes(alert_id):
    now = datetime.datetime.now().strftime("%H:%M:%S")
    suspicious = [
        "mimikatz","procdump","pwdump","wce.exe",
        "fgdump","gsecdump","nc.exe","ncat.exe",
        "psexec","meterpreter"
    ]
    killed = []
    try:
        for proc in psutil.process_iter(['pid','name']):
            try:
                pname = proc.info['name'].lower()
                if any(s in pname for s in suspicious):
                    proc.kill()
                    killed.append(
                        proc.info['name']+"(PID "+str(proc.info['pid'])+")"
                    )
                    print("["+now+"] [SOAR] Killed: "+proc.info['name'])
            except Exception:
                pass
    except Exception as e:
        print("["+now+"] [SOAR] Scan error: "+str(e))

    result = "Killed: "+", ".join(killed) if killed \
             else "Scan complete - no malicious processes found"
    print("["+now+"] [SOAR] "+result)
    log_action(alert_id, "PROCESS_SCAN", HOSTNAME, "psutil_scan", result)
    return result

sent_email_for = set()

def send_email(rule_name, severity, hostname, description, alert_id):
    if not EMAIL_ENABLED:
        return
    if alert_id in sent_email_for:
        return
    sent_email_for.add(alert_id)

    now = datetime.datetime.now().strftime("%H:%M:%S")
    ts  = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    subject = "[SentinelView] "+severity+" ALERT - "+rule_name
    body    = (
        "SENTINELVIEW SECURITY ALERT\n"
        "============================\n\n"
        "Severity   : "+severity+"\n"
        "Rule       : "+rule_name+"\n"
        "Host       : "+hostname+"\n"
        "Time       : "+ts+"\n"
        "Alert ID   : "+str(alert_id)+"\n\n"
        "Description:\n"+description+"\n\n"
        "============================\n"
        "SOAR has automatically responded.\n"
        "Log in to http://localhost:5000 to review.\n"
        "============================\n\n"
        "SentinelView SIEM+SOAR Platform"
    )

    try:
        msg = MIMEMultipart()
        msg['From']    = EMAIL_SENDER
        msg['To']      = EMAIL_RECEIVER
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.send_message(msg)

        print("["+now+"] [SOAR] Email sent to "+EMAIL_RECEIVER)
        log_action(alert_id, "EMAIL_SENT", EMAIL_RECEIVER,
                   "smtp:"+SMTP_SERVER+":"+str(SMTP_PORT),
                   "SUCCESS - alert emailed to "+EMAIL_RECEIVER)
    except Exception as e:
        print("["+now+"] [SOAR] Email failed: "+str(e))
        log_action(alert_id, "EMAIL_FAILED", EMAIL_RECEIVER,
                   "smtp:"+SMTP_SERVER+":"+str(SMTP_PORT),
                   "FAILED - "+str(e))

def check_manual_commands():
    try:
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
        cursor.execute('''
            SELECT id, command, target FROM soar_commands
            WHERE executed = 0 ORDER BY id ASC
        ''')
        cmds = cursor.fetchall()
        conn.commit()
        conn.close()

        now = datetime.datetime.now().strftime("%H:%M:%S")
        for cmd_id, command, target in cmds:
            if command == "ISOLATE_HOST":
                isolate_host(0, "Manual isolation from dashboard")
            elif command == "REENABLE_NETWORK":
                re_enable_network()
            elif command == "DISABLE_USER":
                disable_user(target, 0, "Manual disable from dashboard")
            elif command == "BLOCK_IP":
                block_ip(target, 0, "Manual block from dashboard")

            conn2   = get_db()
            cursor2 = conn2.cursor()
            cursor2.execute(
                "UPDATE soar_commands SET executed=1 WHERE id=?",
                (cmd_id,)
            )
            conn2.commit()
            conn2.close()
            print("["+now+"] [SOAR] Manual command: "+command+" on "+target)
    except Exception:
        pass

def handle_alert(alert):
    (alert_id, rule_name, severity,
     source_ip, hostname, event_id, description) = alert
    now = datetime.datetime.now().strftime("%H:%M:%S")

    print("["+now+"] [SOAR] Handling ["+severity+"] "+rule_name+" on "+hostname)

    if severity == 'CRITICAL':
        send_email(rule_name, severity, hostname, description, alert_id)

    if rule_name == "Brute Force Login Detected":
        block_ip(source_ip, alert_id, "Brute force from "+source_ip)

    elif rule_name == "RDP Brute Force Detected":
        block_ip(source_ip, alert_id, "RDP brute force from "+source_ip)

    elif rule_name == "Dangerous Privilege Assigned":
        scan_processes(alert_id)
        mark_responded(alert_id, blocked=False)

    elif rule_name == "Malware Detected by Defender":
        scan_processes(alert_id)
        mark_responded(alert_id, blocked=False)

    elif rule_name == "Windows Defender Disabled":
        print("["+now+"] [SOAR] CRITICAL - Defender disabled on "+hostname)
        mark_responded(alert_id, blocked=False)
        log_action(alert_id, "CRITICAL_FLAG", hostname,
                   "manual_review", "Defender disabled - review needed")

    elif rule_name == "Malicious PowerShell Detected":
        scan_processes(alert_id)
        mark_responded(alert_id, blocked=False)

    elif rule_name == "Security Audit Log Cleared":
        print("["+now+"] [SOAR] CRITICAL - Audit log cleared on "+hostname)
        mark_responded(alert_id, blocked=False)
        log_action(alert_id, "CRITICAL_FLAG", hostname,
                   "escalated", "Audit log cleared - escalated")

    elif rule_name == "New User Account Created":
        username = extract_username(description)
        if username:
            disable_user(username, alert_id,
                         "Unauthorized account: "+username)
        else:
            mark_responded(alert_id, blocked=False)
            log_action(alert_id, "FLAG", hostname,
                       "flagged", "New user - flagged for review")

    elif rule_name == "User Added to Privileged Group":
        username = extract_username(description)
        if username:
            disable_user(username, alert_id,
                         "Privilege escalation: "+username)
        else:
            mark_responded(alert_id, blocked=False)
            log_action(alert_id, "FLAG", hostname,
                       "flagged", "Admin group change - flagged")

    elif rule_name == "Suspicious Network Connection":
        block_ip(source_ip, alert_id,
                 "Suspicious outbound to "+source_ip)

    elif rule_name == "Account Locked Out":
        block_ip(source_ip, alert_id,
                 "Lockout - possible attack from "+source_ip)

    elif rule_name == "Suspicious Process Execution":
        scan_processes(alert_id)
        mark_responded(alert_id, blocked=False)

    elif rule_name in ["New Service Installed", "Scheduled Task Created"]:
        mark_responded(alert_id, blocked=False)
        log_action(alert_id, "FLAG", hostname,
                   "flagged_for_review",
                   rule_name+" - marked for SOC review")

    else:
        mark_responded(alert_id, blocked=False)
        log_action(alert_id, "LOG_ONLY", hostname,
                   "no_action",
                   "Logged - no automated action for: "+rule_name)

def run_soar():
    print("[SOAR] Security Orchestration engine started.")
    print("[SOAR] Actions: Block IP | Isolate Host | Disable User | Process Scan | Email")
    print("-" * 52)

    cycle = 0
    while True:
        cycle += 1
        alerts = get_unresponded_alerts()

        if alerts:
            now = datetime.datetime.now().strftime("%H:%M:%S")
            print("["+now+"] [SOAR] Found "+str(len(alerts))+" alert(s) - acting now")
            for alert in alerts:
                handle_alert(alert)
        else:
            now = datetime.datetime.now().strftime("%H:%M:%S")
            print("["+now+"] [SOAR] Cycle "+str(cycle)+" - watching...")

        check_manual_commands()
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    run_soar()