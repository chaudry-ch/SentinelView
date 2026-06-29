import subprocess
import threading
import time
import webbrowser
import os
import sys

BASE = r"C:\SentinelView"

SCRIPTS = [
    {
        "name":   "Collector",
        "script": rf"{BASE}\backend\collector.py",
        "color":  "0A"
    },
    {
        "name":   "Detector",
        "script": rf"{BASE}\backend\detector.py",
        "color":  "0B"
    },
    {
        "name":   "SOAR Engine",
        "script": rf"{BASE}\soar\soar.py",
        "color":  "0C"
    },
    {
        "name":   "Dashboard Server",
        "script": rf"{BASE}\backend\app.py",
        "color":  "0E"
    },
]

processes = []

def start_engine(script_info):
    title  = script_info["name"]
    script = script_info["script"]
    color  = script_info["color"]
    cmd = (
        f'start "SentinelView — {title}" '
        f'cmd /k "color {color} && echo Starting {title}... && '
        f'python {script}"'
    )
    proc = subprocess.Popen(cmd, shell=True)
    processes.append(proc)
    print(f"  [+] {title} started")

def open_dashboard():
    print("\n  Waiting for server to be ready...")
    time.sleep(5)
    print("  Opening dashboard in browser...")
    webbrowser.open("http://localhost:5000")

print("=" * 55)
print("   SentinelView SIEM+SOAR — Starting all engines")
print("=" * 55)
print()

for s in SCRIPTS:
    start_engine(s)
    time.sleep(1.5)

t = threading.Thread(target=open_dashboard, daemon=True)
t.start()

print()
print("  All engines launching in separate windows.")
print("  Dashboard will open automatically in 5 seconds.")
print("  Close this window at any time.")
print()
print("  To stop everything: close all SentinelView windows")
print("=" * 55)

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\n  Shutting down...")