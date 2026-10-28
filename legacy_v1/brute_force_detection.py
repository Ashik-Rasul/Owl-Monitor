import time
import subprocess
import re
import logging
from collections import defaultdict

LOG_FILE = "/var/log/auth.log"

MAX_ATTEMPTS = 3
TIME_WINDOW = 30
BLOCK_TIME = 3600   # 1 hour

BLACKLIST_FILE = "blacklist.txt"

attempts = defaultdict(list)
blocked_ips = {}

ip_pattern = r'from (\d+\.\d+\.\d+\.\d+)'

logging.basicConfig(
    filename="ssh_ids.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


def save_blacklist(ip):
    with open(BLACKLIST_FILE, "a") as f:
        f.write(ip + "\n")


def block_ip(ip):

    if ip in blocked_ips:
        return

    logging.warning(f"Blocking IP: {ip}")

    subprocess.run([
        "sudo","iptables","-A","INPUT",
        "-p","tcp","--dport","22",
        "-s",ip,"-j","DROP"
    ])

    blocked_ips[ip] = time.time()

    save_blacklist(ip)


def unblock_ips():
    now = time.time()
    for ip in list(blocked_ips.keys()):
        if now - blocked_ips[ip] >= BLOCK_TIME:
            logging.warning(f"Unblocking IP: {ip}")
            subprocess.run([
                "sudo","iptables","-D","INPUT",
                "-p","tcp","--dport","22",
                "-s",ip,"-j","DROP"
            ])

            del blocked_ips[ip]

def detect_attack(ip):
    now = time.time()
    attempts[ip].append(now)
    attempts[ip] = [t for t in attempts[ip] if now - t <= TIME_WINDOW]
    if len(attempts[ip]) >= MAX_ATTEMPTS:
        logging.warning(f"SSH Brute Force Detected from {ip}")
        block_ip(ip)
        attempts[ip].clear()

def monitor_log():
    with open(LOG_FILE,"r") as f:
        f.seek(0,2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            if "Failed password" in line:
                match = re.search(ip_pattern,line)
                if match:
                    ip = match.group(1)
                    logging.info(f"Failed login attempt from {ip}")
                    detect_attack(ip)
            unblock_ips()
monitor_log()
