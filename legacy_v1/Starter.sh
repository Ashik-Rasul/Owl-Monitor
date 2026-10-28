#!/bin/bash

echo "[+] Starting Monitoring Tools..."

# Background processes
setsid python3 brute_force_detection.py > /dev/null 2>&1 &
PID1=$!

setsid bash unusual_login_alert.sh > /dev/null 2>&1 &
PID2=$!

setsid bash Mailer_blacklist_fromSnort.sh > /dev/null 2>&1 &
PID3=$!

echo "-----------------------------------------"
echo "Background tools started"
echo "Brute Force Detector       : $PID1"
echo "unusual_login_alert.sh     : $PID2"
echo "mailer_blacklist_fromSnort : $PID3"
echo "-----------------------------------------"

# Save ONLY background PIDs
echo $PID1 $PID2 $PID3 > monitor_pids.txt

echo "[+] Starting sn.py in this terminal..."
echo "Press CTRL+C to stop sn.py"

# 👉 FOREGROUND (NO &)
python3 sn.py

echo "[+] sn.py stopped. Exiting Starter."
