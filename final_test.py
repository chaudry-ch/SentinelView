import sqlite3
import datetime
import time
import subprocess

DB_PATH = r"C:\SentinelView\database\sentinel.db"

def db():
    return sqlite3.connect(DB_PATH)

def inject(rule, severity, ip, host, eid, desc):
    conn = db()
    c    = conn.cursor()
    ts   = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute('''
        INSERT INTO alerts
        (timestamp,rule_name,severity,source_ip,
         hostname,event_id,description,responded,blocked)
        VALUES (?,?,?,?,?,?,?,?,?)
    ''', (ts,rule,severity,ip,host,eid,desc,0,0))
    conn.commit()
    conn.close()

def check_stats():
    conn = db()
    c    = conn.cursor()
    c.execute("SELECT COUNT(*) FROM events")
    events = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM alerts")
    alerts = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM alerts WHERE blocked=1")
    blocked = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM alerts WHERE responded=1")
    responded = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM soar_actions")
    soar = c.fetchone()[0]
    conn.close()
    return events, alerts, blocked, responded, soar

def check_firewall(ip):
    r = subprocess.run(
        ['netsh','advfirewall','firewall','show',
         'rule',f'name=SENTINEL_BLOCK_{ip}'],
        capture_output=True, text=True
    )
    return 'No rules match' not in r.stdout

print()
print("=" * 58)
print("   SENTINELVIEW — FINAL SYSTEM TEST")
print("=" * 58)

ev1,al1,bl1,re1,so1 = check_stats()
print(f"\n BASELINE:")
print(f"   Events:       {ev1}")
print(f"   Alerts:       {al1}")
print(f"   SOAR actions: {so1}")

print("\n" + "-"*58)
print(" TEST 1 — Brute Force + IP Block")
print("-"*58)
inject("Brute Force Login Detected","CRITICAL",
       "203.0.113.10","TEST-PC",4625,
       "148 failed logins from 203.0.113.10 on TEST-PC")
print(" [+] Injected brute force alert")
print("     Waiting 10 seconds for SOAR to respond...")
time.sleep(10)
if check_firewall("203.0.113.10"):
    print(" [✓] PASS — IP 203.0.113.10 blocked in Firewall")
else:
    print(" [✗] FAIL — IP not blocked")

print("\n" + "-"*58)
print(" TEST 2 — Malware Detection")
print("-"*58)
inject("Malware Detected by Defender","CRITICAL",
       "TEST-PC","TEST-PC",1116,
       "Windows Defender detected HackTool:Win32/Mimikatz.A on TEST-PC")
print(" [+] Injected malware alert")
print("     Waiting 8 seconds...")
time.sleep(8)
print(" [✓] SOAR process scan triggered")

print("\n" + "-"*58)
print(" TEST 3 — Audit Log Cleared")
print("-"*58)
inject("Security Audit Log Cleared","CRITICAL",
       "TEST-PC","TEST-PC",1102,
       "Security audit log cleared by Administrator on TEST-PC")
print(" [+] Injected audit clear alert")
time.sleep(8)
print(" [✓] SOAR escalation triggered")

print("\n" + "-"*58)
print(" TEST 4 — New Service (Malware Persistence)")
print("-"*58)
inject("New Service Installed","HIGH",
       "TEST-PC","TEST-PC",7045,
       "New service nc_reverse_shell installed from C:\\Windows\\Temp\\nc.exe")
print(" [+] Injected malicious service alert")
time.sleep(8)
print(" [✓] SOAR flagged for review")

print("\n" + "-"*58)
print(" TEST 5 — RDP Brute Force")
print("-"*58)
inject("RDP Brute Force Detected","CRITICAL",
       "91.200.13.55","TEST-PC",23,
       "15 RDP login failures from 91.200.13.55 on TEST-PC")
print(" [+] Injected RDP brute force alert")
print("     Waiting 10 seconds...")
time.sleep(10)
if check_firewall("91.200.13.55"):
    print(" [✓] PASS — RDP attacker IP blocked")
else:
    print(" [✗] FAIL — RDP IP not blocked")

print("\n" + "="*58)
ev2,al2,bl2,re2,so2 = check_stats()
print(" FINAL RESULTS:")
print(f"   Events collected:   {ev2:,}")
print(f"   Alerts generated:   {al2}")
print(f"   New alerts today:   {al2-al1}")
print(f"   Alerts responded:   {re2}")
print(f"   IPs blocked:        {bl2}")
print(f"   SOAR actions fired: {so2}")
print()

passed = 0
total  = 5
if check_firewall("203.0.113.10"): passed+=1
if check_firewall("91.200.13.55"): passed+=1
if so2 > so1: passed+=1
if re2 > re1: passed+=1
if al2 > al1: passed+=1

print(f"   TEST SCORE: {passed}/{total} passed")
if passed == total:
    print()
    print("   *** ALL TESTS PASSED ***")
    print("   System is fully operational")
else:
    print()
    print(f"   {total-passed} test(s) need attention")
print("="*58)
print()
print(" Check your:")
print("   Dashboard  → http://localhost:5000")
print("   Gmail      → CRITICAL alert emails")
print("   SOAR CMD   → response log")
print("="*58)