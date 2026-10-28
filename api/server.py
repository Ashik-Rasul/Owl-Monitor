import os
import json
import asyncio
import threading
import datetime
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from core.logger import setup_logger

logger = setup_logger(__name__)

app = FastAPI(title="Owl Monitor API", version="1.0")

# ── WebSocket Connection Manager ──────────────────────────────────────────────

class ConnectionManager:
    """Manages all active WebSocket connections from browser clients."""
    def __init__(self):
        self.active_connections: list[WebSocket] = []
        self._lock = threading.Lock()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        with self._lock:
            self.active_connections.append(websocket)
        logger.info(f"WebSocket client connected. Total clients: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        with self._lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)
        logger.info(f"WebSocket client disconnected. Total clients: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        """Send a JSON message to every connected browser."""
        data = json.dumps(message)
        with self._lock:
            connections = list(self.active_connections)
        for connection in connections:
            try:
                await connection.send_text(data)
            except Exception:
                self.disconnect(connection)

manager = ConnectionManager()

# ── In-memory store for recent events and metrics ─────────────────────────────

_store = {
    "alerts": [],           # List of recent alert dicts (max 100)
    "events": [],           # List of recent normalized events (max 200)
    "blocked_ips": [],      # List of currently blocked IPs
    "firewall_actions": [], # Confirmed firewall responses (max 100)
    "fim_violations": [],   # List of FIM violation events
    "threat_intel": {},     # ip -> threat intelligence details
    "metrics": {
        "threat_level": "Low",
        "active_alerts": 0,
        "network_events": 0,
        "system_status": "Healthy",
    }
}
_store_lock = threading.Lock()

def push_alert(alert_data: dict):
    """Called from the EventBus thread to store an alert and schedule a broadcast."""
    with _store_lock:
        _store["alerts"].insert(0, alert_data)
        if len(_store["alerts"]) > 100:
            _store["alerts"] = _store["alerts"][:100]
        _store["metrics"]["active_alerts"] = len(_store["alerts"])
        
        # Track Threat Intelligence per IP independently
        ti = alert_data.get("threat_intel")
        ip = alert_data.get("ip")
        if ti and ti.get("matched") and ip and ip != "N/A":
            _store["threat_intel"][ip] = ti

        # If alert action is block_ip and IP is valid, log requested action
        if alert_data.get("action") == "block_ip" and ip and ip not in ["N/A", "0.0.0.0", "127.0.0.1", "::1"]:
            # Note: actual confirmation occurs when push_blocked_ip is called by FirewallResponse
            pass

        # Update threat level based on the highest severity we've seen recently
        levels = {"Low": 0, "Medium": 1, "High": 2, "Very High": 3, "Critical": 4}
        current_level = levels.get(_store["metrics"]["threat_level"], 0)
        new_level = levels.get(alert_data.get("level", "Low"), 0)
        if new_level > current_level:
            for name, val in levels.items():
                if val == new_level:
                    _store["metrics"]["threat_level"] = name
                    break

    # Schedule the async broadcast from the sync thread
    _schedule_broadcast({"type": "new_alert", "data": alert_data})

def push_event(event_data: dict):
    """Called from EventBus thread to store a normalized event."""
    with _store_lock:
        _store["events"].insert(0, event_data)
        if len(_store["events"]) > 200:
            _store["events"] = _store["events"][:200]
        _store["metrics"]["network_events"] = len(_store["events"])
    
    _schedule_broadcast({"type": "new_event", "data": event_data})

def push_blocked_ip(ip: str, action: str = "DROP", status: str = "Block Successful"):
    """Called when an IP gets blocked via iptables."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    action_entry = {
        "ip": ip,
        "action": action,
        "target": "INPUT",
        "status": status,
        "timestamp": timestamp,
        "duration": "3600s (Temporary)"
    }
    with _store_lock:
        if ip not in _store["blocked_ips"]:
            _store["blocked_ips"].append(ip)
        _store["firewall_actions"].insert(0, action_entry)
        if len(_store["firewall_actions"]) > 100:
            _store["firewall_actions"] = _store["firewall_actions"][:100]
    _schedule_broadcast({"type": "ip_blocked", "data": action_entry})

def get_store():
    """Return a snapshot of the current state for initial page load."""
    with _store_lock:
        return json.loads(json.dumps(_store))

# ── Async bridge: schedule broadcasts from sync threads ───────────────────────

_loop = None

def set_event_loop(loop):
    global _loop
    _loop = loop

def _schedule_broadcast(message: dict):
    """Safely schedule an async broadcast from any thread."""
    if _loop and _loop.is_running():
        asyncio.run_coroutine_threadsafe(manager.broadcast(message), _loop)

# ── API Routes ────────────────────────────────────────────────────────────────

@app.get("/api/state")
async def get_state():
    """Return the full current state for initial page load."""
    return get_store()

@app.get("/api/rules")
async def get_rules():
    """Return actual loaded rules and capability inventory with runtime status."""
    import yaml
    rules_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")
    loaded_rules = []
    if os.path.exists(rules_dir):
        for fname in sorted(os.listdir(rules_dir)):
            if fname.endswith(".yaml") or fname.endswith(".yml"):
                fpath = os.path.join(rules_dir, fname)
                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        r = yaml.safe_load(f)
                        if isinstance(r, dict):
                            r["filename"] = fname
                            loaded_rules.append(r)
                except Exception:
                    pass

    capabilities = [
        # Authentication
        {
            "id": 1,
            "name": "Unusual-Time SSH Login — 12 AM to 7 AM",
            "category": "Authentication Security",
            "status": "PARTIALLY IMPLEMENTED",
            "runtime_status": "Runtime Unverified / Legacy Script",
            "detection_method": "Time-window log inspection (Auth log)",
            "data_source": "/var/log/auth.log",
            "severity": "Medium",
            "threshold": "Login accepted between 00:00 and 07:00",
            "time_window": "12 AM – 7 AM daily",
            "expected_response": "Email alert to administrator",
            "description": "Monitors SSH authentication logs for successful user logins occurring outside standard operational hours (12 AM to 7 AM). Implemented in legacy v1 bash scripts; not yet ported to v3 EventBus detection engine."
        },
        {
            "id": 2,
            "name": "SSH Brute Force",
            "category": "Authentication Security",
            "status": "ACTIVE",
            "runtime_status": "Loaded — Operational with AuthLogCollector",
            "detection_method": "Stateful sliding window threshold",
            "data_source": "/var/log/auth.log",
            "severity": "High",
            "threshold": "5 failed login attempts",
            "time_window": "120 seconds",
            "expected_response": "Automated iptables IP DROP + Email alert",
            "description": "Tracks repeated failed SSH authentication attempts from a single source IP. Triggers automated firewall mitigation when threshold is exceeded."
        },
        {
            "id": 3,
            "name": "Severe SSH Brute Force",
            "category": "Authentication Security",
            "status": "ACTIVE",
            "runtime_status": "Loaded — Operational with AuthLogCollector",
            "detection_method": "Stateful sliding window threshold (Aggressive)",
            "data_source": "/var/log/auth.log",
            "severity": "Very High",
            "threshold": "15 failed login attempts",
            "time_window": "180 seconds",
            "expected_response": "Immediate iptables DROP + Priority Email",
            "description": "High-volume credential stuffing or distributed password spray. Represents persistent brute force requiring elevated incident response."
        },
        # Network
        {
            "id": 4,
            "name": "Port Scanning",
            "category": "Network Security",
            "status": "ACTIVE",
            "runtime_status": "Operational (Requires Scapy + Root/Npcap)",
            "detection_method": "Unique destination port tracker in sliding window",
            "data_source": "Live network traffic (NetworkCollector)",
            "severity": "High",
            "threshold": "> 15 unique destination ports",
            "time_window": "10 seconds",
            "expected_response": "Automated iptables IP DROP",
            "description": "Detects horizontal and vertical reconnaissance scans where an attacker probes multiple ports to map accessible services."
        },
        {
            "id": 5,
            "name": "SYN Flood",
            "category": "Network Security",
            "status": "ACTIVE",
            "runtime_status": "Operational (Requires Scapy + Root/Npcap)",
            "detection_method": "TCP SYN-without-ACK packet rate threshold",
            "data_source": "Live network traffic (NetworkCollector)",
            "severity": "High",
            "threshold": "100 SYN packets",
            "time_window": "10 seconds",
            "expected_response": "Automated iptables IP DROP",
            "description": "Identifies TCP SYN flood attacks attempting to exhaust kernel connection state tables."
        },
        {
            "id": 6,
            "name": "ICMP / Ping Flood",
            "category": "Network Security",
            "status": "ACTIVE",
            "runtime_status": "Operational (Requires Scapy + Root/Npcap)",
            "detection_method": "ICMP Echo Request rate threshold",
            "data_source": "Live network traffic (NetworkCollector)",
            "severity": "High",
            "threshold": "50 ICMP Echo requests",
            "time_window": "10 seconds",
            "expected_response": "Automated iptables IP DROP",
            "description": "Detects high-volume ICMP Echo requests targeting network bandwidth or server responsiveness."
        },
        {
            "id": 7,
            "name": "DNS Flooding",
            "category": "Network Security",
            "status": "ACTIVE",
            "runtime_status": "Operational (Requires Scapy + Root/Npcap)",
            "detection_method": "UDP Port 53 query rate threshold",
            "data_source": "Live network traffic (NetworkCollector)",
            "severity": "High",
            "threshold": "50 DNS queries",
            "time_window": "10 seconds",
            "expected_response": "Automated iptables IP DROP",
            "description": "Flags abnormal spikes in DNS lookup requests designed to overwhelm local or upstream resolvers."
        },
        {
            "id": 8,
            "name": "DNS Tunneling",
            "category": "Network Security",
            "status": "ACTIVE",
            "runtime_status": "Operational (Requires Scapy + Root/Npcap)",
            "detection_method": "Shannon entropy calculation (> 4.2) + length check (> 60 chars)",
            "data_source": "Live network traffic (NetworkCollector)",
            "severity": "High",
            "threshold": "Query length > 60 chars & Entropy > 4.2",
            "time_window": "Per-query inspection",
            "expected_response": "Automated iptables IP DROP",
            "description": "Detects data exfiltration or C2 tunneling over DNS by computing the Shannon entropy of encoded subdomain strings."
        },
        {
            "id": 9,
            "name": "Network Beaconing",
            "category": "Network Security",
            "status": "ACTIVE",
            "runtime_status": "Operational (Requires Scapy + Root/Npcap)",
            "detection_method": "Inter-arrival delta variance analysis (< 0.25 variance)",
            "data_source": "Live network traffic (NetworkCollector)",
            "severity": "Medium",
            "threshold": ">= 5 successive intervals, 1.0s - 60.0s window",
            "time_window": "Last 6 packet connections",
            "expected_response": "SOC Alert Notification (alert_only)",
            "description": "Calculates variance in communication intervals between IP pairs to identify automated malware C2 callback beacons."
        },
        {
            "id": 10,
            "name": "ARP Spoofing",
            "category": "Network Security",
            "status": "ACTIVE",
            "runtime_status": "Operational (Requires Scapy + Root/Npcap)",
            "detection_method": "Stateful IP-to-MAC mapping conflict detection in ARP replies",
            "data_source": "Live network traffic (NetworkCollector)",
            "severity": "Critical",
            "threshold": "1 conflict event",
            "time_window": "Real-time inspection",
            "expected_response": "Automated iptables IP DROP + Critical Alert",
            "description": "Identifies ARP cache poisoning attempts where an attacker broadcasts gratuitous or unsolicited ARP replies claiming an existing host IP."
        },
        {
            "id": 11,
            "name": "Suspicious Packet Patterns",
            "category": "Network Security",
            "status": "ACTIVE",
            "runtime_status": "Operational (Requires Scapy + Root/Npcap)",
            "detection_method": "TCP flag anomaly analysis (Null Scan, Xmas Scan, SYN+FIN)",
            "data_source": "Live network traffic (NetworkCollector)",
            "severity": "Medium",
            "threshold": "Illegal or anomalous flag combinations",
            "time_window": "Immediate per-packet",
            "expected_response": "SOC Alert Notification (alert_only)",
            "description": "Inspects TCP flags for invalid combinations used in stealth OS fingerprinting and firewall traversal scans."
        },
        {
            "id": 12,
            "name": "Snort IDS Alert",
            "category": "Network Security",
            "status": "ACTIVE",
            "runtime_status": "Operational with Snort fast alert log",
            "detection_method": "Log collector tailing /var/log/snort/snort.alert.fast",
            "data_source": "/var/log/snort/snort.alert.fast",
            "severity": "Critical",
            "threshold": "Single IDS signature trigger",
            "time_window": "Immediate upon log write",
            "expected_response": "Automated iptables IP DROP",
            "description": "Integrates external Snort signature detections into the Owl Monitor unified EventBus and SOAR response pipeline."
        },
        # File Integrity
        {
            "id": 13,
            "name": "File Integrity Violation",
            "category": "File Integrity",
            "status": "ACTIVE",
            "runtime_status": "Operational with FIMCollector",
            "detection_method": "SHA-256 baseline hashing + permissions & UID tracking",
            "data_source": "Configured filesystem paths (/etc/passwd, /etc/shadow, etc.)",
            "severity": "Critical",
            "threshold": "Hash mismatch or metadata modification",
            "time_window": "60 second polling cycle",
            "expected_response": "Critical SOC Notification + Email alert",
            "description": "Monitors critical system files for unauthorized file modifications, creations, deletions, or permission alterations."
        },
        # Threat Intelligence
        {
            "id": 14,
            "name": "Malicious IP Reputation",
            "category": "Threat Intelligence",
            "status": "ACTIVE",
            "runtime_status": "Operational (MockProvider + AbuseIPDB integrated)",
            "detection_method": "Multi-feed IP reputation lookup + RiskScorer enrichment",
            "data_source": "External feeds (AbuseIPDB, MockProvider)",
            "severity": "Enrichment",
            "threshold": "Confidence score > 0% (Score 0-100)",
            "time_window": "Enriched at alert trigger time",
            "expected_response": "Risk score amplification + Country/ISP context",
            "description": "Enriches all detected attacker IPs with external threat intelligence to assess reputation score and abuse report history."
        },
        {
            "id": 15,
            "name": "Known Botnet Indicator",
            "category": "Threat Intelligence",
            "status": "ACTIVE",
            "runtime_status": "Operational (Enrichment Engine)",
            "detection_method": "Threat feed botnet flag aggregation",
            "data_source": "Threat Intel feeds",
            "severity": "Enrichment",
            "threshold": "Known botnet flag == True",
            "time_window": "Enriched at alert trigger time",
            "expected_response": "+10 Risk Score penalty + Alert escalation",
            "description": "Identifies if a source IP belongs to known botnet command-and-control infrastructure or compromised bot clusters."
        },
        # Machine Learning
        {
            "id": 16,
            "name": "Anomalous Network Behavior",
            "category": "Machine Learning",
            "status": "PLANNED",
            "runtime_status": "Not Implemented",
            "detection_method": "Unsupervised anomaly detection (Isolation Forest / Autoencoders)",
            "data_source": "Network telemetry vector embeddings",
            "severity": "Planned",
            "threshold": "Data unavailable — Planned feature",
            "time_window": "Planned feature",
            "expected_response": "Planned feature",
            "description": "Planned machine-learning capability for identifying non-signature statistical anomalies in network traffic volume and connection patterns."
        },
        {
            "id": 17,
            "name": "Anomalous Authentication Activity",
            "category": "Machine Learning",
            "status": "PLANNED",
            "runtime_status": "Not Implemented",
            "detection_method": "User & Entity Behavior Analytics (UEBA)",
            "data_source": "Historical authentication baseline",
            "severity": "Planned",
            "threshold": "Data unavailable — Planned feature",
            "time_window": "Planned feature",
            "expected_response": "Planned feature",
            "description": "Planned machine-learning capability to detect credential anomalies and atypical login patterns based on user behavioral baselines."
        },
        # Advanced Network Monitoring Technologies
        {
            "id": 18,
            "name": "PyShark-Based Traffic Analysis",
            "category": "Advanced Network Monitoring",
            "status": "PLANNED",
            "runtime_status": "Not Implemented (Project uses Scapy)",
            "detection_method": "TShark / Wireshark dissector analysis via PyShark",
            "data_source": "Deep packet inspection streams",
            "severity": "Supporting Technology",
            "threshold": "Data unavailable — Planned feature",
            "time_window": "Planned feature",
            "expected_response": "Planned feature",
            "description": "Planned deep-packet protocol inspection engine using PyShark. Currently, Owl Monitor utilizes Scapy for all active packet sniffing."
        },
        {
            "id": 19,
            "name": "libpcap-Based Packet Capture",
            "category": "Advanced Network Monitoring",
            "status": "PARTIALLY IMPLEMENTED",
            "runtime_status": "Checked at startup (Underlying Scapy capture driver)",
            "detection_method": "Kernel-level packet capture via libpcap / Npcap C library",
            "data_source": "Host network interface drivers",
            "severity": "Supporting Technology",
            "threshold": "System-level driver",
            "time_window": "Real-time capture",
            "expected_response": "Low-level packet stream provided to Scapy",
            "description": "Low-level packet capture library verified by DependencyChecker. Provides the raw packet stream utilized by Scapy when running with elevated permissions."
        }
    ]

    return {
        "loaded_rules": loaded_rules,
        "capabilities": capabilities
    }

@app.get("/api/config")
async def get_config():
    """Return sanitized system configuration without exposing sensitive credentials."""
    from core.config_loader import ConfigLoader
    try:
        cfg = ConfigLoader.load()
        fim = cfg.get("fim", {})
        net = cfg.get("network", {})
        resp = cfg.get("response", {})
        ti = cfg.get("threat_intel", {})
        
        return {
            "app_name": cfg.get("app", {}).get("name", "Owl Monitor"),
            "app_version": cfg.get("app", {}).get("version", "3.0"),
            "fim": {
                "enabled": fim.get("enabled", False),
                "check_interval": fim.get("check_interval", 60),
                "targets": fim.get("targets", [])
            },
            "network": {
                "enabled": net.get("enabled", True),
                "interface": net.get("interface", "")
            },
            "response": {
                "admin_email": resp.get("admin_email", "admin@localhost"),
                "block_time_seconds": resp.get("block_time_seconds", 3600)
            },
            "threat_intel": {
                "abuseipdb": {"enabled": ti.get("abuseipdb", {}).get("enabled", False), "configured": bool(ti.get("abuseipdb", {}).get("api_key"))},
                "otx": {"enabled": ti.get("otx", {}).get("enabled", False), "configured": bool(ti.get("otx", {}).get("api_key"))},
                "virustotal": {"enabled": ti.get("virustotal", {}).get("enabled", False), "configured": bool(ti.get("virustotal", {}).get("api_key"))},
                "mock_provider": {"enabled": True, "active": True}
            }
        }
    except Exception as e:
        logger.error(f"Error reading config: {e}")
        return {"error": "Configuration unavailable"}

@app.get("/api/system")
async def get_system_status():
    """Return runtime environment check from DependencyChecker."""
    from core.dependency_checker import DependencyChecker
    try:
        check = DependencyChecker.check_all()
        return {
            "status": "Online",
            "dependencies": check,
            "server_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    except Exception as e:
        return {"status": "Degraded", "error": str(e)}

@app.websocket("/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive; we only push data server → client
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# ── Mount Static Files (the web-ui directory) ─────────────────────────────────

web_ui_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "web-ui")

@app.get("/")
async def serve_index():
    return FileResponse(os.path.join(web_ui_dir, "index.html"))

app.mount("/", StaticFiles(directory=web_ui_dir), name="static")

# ── Server Runner ─────────────────────────────────────────────────────────────

def start_server(host="0.0.0.0", port=8000):
    """Start the Uvicorn server in a background daemon thread."""
    import uvicorn

    loop = asyncio.new_event_loop()
    set_event_loop(loop)
    
    config = uvicorn.Config(app, host=host, port=port, loop="asyncio", log_level="warning")
    server = uvicorn.Server(config)
    
    def _run():
        asyncio.set_event_loop(loop)
        loop.run_until_complete(server.serve())
    
    thread = threading.Thread(target=_run, daemon=True, name="uvicorn-server")
    thread.start()
    logger.info(f"Web Dashboard started at http://{host}:{port}")
    return thread
