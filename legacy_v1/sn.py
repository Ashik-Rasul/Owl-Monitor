#!/usr/bin/env python3

import time
import re
import os
import subprocess
import signal
import sys
import select
import threading
from datetime import datetime, timedelta
from collections import defaultdict

# ---------------------------
# CONFIG
# ---------------------------

LOG_FILE = "/var/log/snort/snort.alert.fast"
AUTH_LOG_FILE = "/var/log/auth.log"
BLACKLIST_FILE = "blacklist.txt"

TEMP_BLOCK_TIME = timedelta(hours=2)

running = True

# ---------------------------
# SIGNAL HANDLER
# ---------------------------

def stop_handler(sig, frame):
    global running
    print("\n[+] Stopping IDS Monitor...")
    running = False

signal.signal(signal.SIGINT, stop_handler)
signal.signal(signal.SIGTERM, stop_handler)

# ---------------------------
# ATTACK PATTERNS
# ---------------------------

attack_patterns = {
    "SYN_SCAN": r"SYN",
    "TCP_CONNECT_SCAN": r"TCP",
    "FIN_SCAN": r"FIN",
    "XMAS_SCAN": r"XMAS",
    "NULL_SCAN": r"NULL",
    "UDP_SCAN": r"UDP",
    "SSH_BRUTE_FORCE": r"SSH",
    "HTTP_DDOS": r"HTTP",
    "PING_FLOOD": r"ICMP",
    "SQL_INJECTION": r"OR 1=1",
    "XSS_ATTACK": r"<script>",
    "FTP_BRUTE_FORCE": r"FTP",
    "DNS_TUNNELING": r"DNS",
    "SMB_EXPLOIT": r"445"
}

severity_score = {
    "SYN_SCAN": 3,
    "TCP_CONNECT_SCAN": 3,
    "FIN_SCAN": 3,
    "XMAS_SCAN": 4,
    "NULL_SCAN": 4,
    "UDP_SCAN": 4,
    "SSH_BRUTE_FORCE": 8,
    "HTTP_DDOS": 9,
    "PING_FLOOD": 7,
    "SQL_INJECTION": 9,
    "XSS_ATTACK": 6,
    "FTP_BRUTE_FORCE": 7,
    "DNS_TUNNELING": 9,
    "SMB_EXPLOIT": 10
}

ip_regex = r'(\d+\.\d+\.\d+\.\d+)'

# SSH patterns
ssh_success_pattern = r"Accepted .* from (\d+\.\d+\.\d+\.\d+)"
ssh_fail_pattern = r"Failed .* from (\d+\.\d+\.\d+\.\d+)"

# ---------------------------
# DATA STORAGE
# ---------------------------

packet_counter = defaultdict(int)
blocked_ips = {}
permanent_block = set()
ip_attack_history = defaultdict(set)

ssh_success_count = defaultdict(int)
ssh_fail_count = defaultdict(int)

total_attacks = 0

# ---------------------------
# FIREWALL FUNCTIONS
# ---------------------------

def block_ip(ip):
    check = subprocess.call(
        ["sudo", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    if check != 0:
        subprocess.call(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])


def unblock_ip(ip):
    subprocess.call(
        ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

# ---------------------------
# FILE FUNCTIONS
# ---------------------------

def ensure_blacklist():
    if not os.path.exists(BLACKLIST_FILE):
        open(BLACKLIST_FILE, "w").close()


def write_blacklist(ip, attack, count):
    ensure_blacklist()

    if attack in ip_attack_history[ip]:
        return

    ip_attack_history[ip].add(attack)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(BLACKLIST_FILE, "a") as f:
        f.write(f"{now} {ip} {attack} {count}\n")

# ---------------------------
# DISPLAY
# ---------------------------

def severity_label(score):
    if score >= 9:
        return "CRITICAL"
    elif score >= 7:
        return "HIGH"
    elif score >= 4:
        return "MEDIUM"
    else:
        return "LOW"


def dashboard():
    os.system("clear" if os.name == "posix" else "cls")

    print("======================================")
    print(" SNORT + SSH IPS LIVE DASHBOARD ")
    print("======================================\n")

    print(f"Total Attacks Detected : {total_attacks}\n")

    print("Top Attackers\n")

    sorted_ips = sorted(packet_counter.items(), key=lambda x: x[1], reverse=True)

    for ip, count in sorted_ips[:5]:
        if ip in permanent_block:
            status = "PERMANENT BLOCK"
        elif ip in blocked_ips:
            status = "TEMP BLOCK"
        else:
            status = "ACTIVE"

        print(f"{ip} | packets:{count} | {status}")

    print("\nRecent Attack Types\n")

    for ip, attacks in ip_attack_history.items():
        for attack in attacks:
            score = severity_score.get(attack, 1)
            label = severity_label(score)
            print(f"{ip} → {attack} | score:{score} | {label}")

    # SSH Section
    print("\n======================================")
    print(" SSH LOGIN ACTIVITY ")
    print("======================================\n")

    for ip in set(list(ssh_success_count.keys()) + list(ssh_fail_count.keys())):
        success = ssh_success_count[ip]
        fail = ssh_fail_count[ip]

        print(f"{ip} → SUCCESS: {success} | FAILED: {fail}")

    print("\nMonitoring:")
    print(f"Snort Log : {LOG_FILE}")
    print(f"Auth Log  : {AUTH_LOG_FILE}")

# ---------------------------
# SSH LOG MONITOR
# ---------------------------

def monitor_auth_log():
    try:
        with open(AUTH_LOG_FILE, "r") as authlog:
            authlog.seek(0, 2)

            while running:
                ready, _, _ = select.select([authlog], [], [], 0.5)

                if not ready:
                    continue

                line = authlog.readline()
                if not line:
                    continue

                success_match = re.search(ssh_success_pattern, line)
                fail_match = re.search(ssh_fail_pattern, line)

                if success_match:
                    ip = success_match.group(1)
                    ssh_success_count[ip] += 1
                    print(f"[SSH SUCCESS] {ip}")

                elif fail_match:
                    ip = fail_match.group(1)
                    ssh_fail_count[ip] += 1
                    print(f"[SSH FAILED] {ip}")

                    # Brute force detection
                    if ssh_fail_count[ip] >= 5:
                        print(f"[!] SSH BRUTE FORCE DETECTED: {ip}")

                        if ip not in blocked_ips:
                            block_ip(ip)
                            blocked_ips[ip] = datetime.now()

    except FileNotFoundError:
        print(f"[ERROR] Auth log not found: {AUTH_LOG_FILE}")

# ---------------------------
# MAIN SNORT MONITOR
# ---------------------------

print("[+] Starting Snort + SSH IDS Monitor...\n")

# Start SSH monitoring thread
auth_thread = threading.Thread(target=monitor_auth_log, daemon=True)
auth_thread.start()

try:
    with open(LOG_FILE, "r") as logfile:

        logfile.seek(0, 2)

        while running:

            ready, _, _ = select.select([logfile], [], [], 0.5)

            if not ready:
                continue

            line = logfile.readline()

            if not line:
                continue

            ip_match = re.findall(ip_regex, line)

            if not ip_match:
                continue

            attacker_ip = ip_match[0]

            for attack, pattern in attack_patterns.items():

                if re.search(pattern, line, re.IGNORECASE):

                    packet_counter[attacker_ip] += 1
                    total_attacks += 1

                    score = severity_score.get(attack, 1)

                    print(f"[ATTACK] {attack} | {attacker_ip} | score:{score}")

                    if attacker_ip not in blocked_ips and attacker_ip not in permanent_block:

                        block_ip(attacker_ip)
                        blocked_ips[attacker_ip] = datetime.now()

                        write_blacklist(attacker_ip, attack, packet_counter[attacker_ip])

                    elif attacker_ip in blocked_ips:

                        if attack not in ip_attack_history[attacker_ip]:

                            block_ip(attacker_ip)
                            permanent_block.add(attacker_ip)

                            write_blacklist(attacker_ip, attack, packet_counter[attacker_ip])

            dashboard()

            # UNBLOCK LOGIC
            for ip, block_time in list(blocked_ips.items()):

                if datetime.now() - block_time > TEMP_BLOCK_TIME and ip not in permanent_block:

                    print(f"[+] Unblocking {ip}")
                    unblock_ip(ip)
                    del blocked_ips[ip]

except FileNotFoundError:
    print(f"[ERROR] Log file not found: {LOG_FILE}")

except Exception as e:
    print(f"[ERROR] {e}")

finally:
    print("[+] IDS Monitor stopped cleanly.")
