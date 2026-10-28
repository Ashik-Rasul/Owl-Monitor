import sys
import os

def bootstrap_venv():
    """
    Ensures Owl Monitor runs within its virtual environment or with required dependencies available.
    If dependencies are missing and .venv exists, transparently re-executes using .venv python.
    """
    try:
        import yaml
        import fastapi
        import uvicorn
        import websockets
        import scapy
        # Core dependencies are available in the current Python interpreter
        return
    except ImportError:
        pass

    # Avoid infinite recursion loop
    if os.environ.get("OWL_MONITOR_BOOTSTRAPPED") == "1":
        print("======================================================================")
        print("[ERROR] Owl Monitor dependencies are missing in this environment.")
        print("[INFO]  Please run the setup script to install dependencies:")
        print("        ./setup.sh")
        print("======================================================================")
        sys.exit(1)

    # Determine workspace root and virtual environment path
    script_dir = os.path.dirname(os.path.abspath(__file__))
    venv_dir = os.path.join(script_dir, ".venv")
    
    # Check for Unix or Windows python binary inside .venv
    venv_python = os.path.join(venv_dir, "bin", "python")
    if not os.path.exists(venv_python):
        venv_python = os.path.join(venv_dir, "bin", "python3")
    if not os.path.exists(venv_python):
        venv_python = os.path.join(venv_dir, "Scripts", "python.exe")

    if os.path.exists(venv_python):
        print(f"[INFO] Dependencies missing in current Python. Auto-switching to project virtual environment: {venv_python}")
        os.environ["OWL_MONITOR_BOOTSTRAPPED"] = "1"
        os.execv(venv_python, [venv_python] + sys.argv)
    else:
        print("======================================================================")
        print("[ERROR] Owl Monitor dependencies are not installed.")
        print("[INFO]  Run ./setup.sh to set up the project virtual environment.")
        print("======================================================================")
        sys.exit(1)

# Execute bootstrap before importing modules that rely on third-party packages
bootstrap_venv()

import time
from core.logger import setup_logger
from core.event_bus import EventBus
from core.config_loader import ConfigLoader
from core.dependency_checker import DependencyChecker

logger = setup_logger("Main")

def main():
    logger.info("Starting Smart Log Analyzer Platform v3.0...")
    
    # 1. Dependency and Environment Check
    DependencyChecker.print_status_table()

    # 2. Load Configuration
    config = ConfigLoader.load()
    
    # 3. Initialize Event Bus
    event_bus = EventBus()
    
    # 4. Initialize Threat Intel Engine
    from utils.threat_intel import ThreatIntel
    ThreatIntel.initialize(config)
    
    # 5. Initialize Responders (SOAR & Web Dashboard)
    from responses.firewall import FirewallResponse
    from responses.notifications import EmailResponse
    from responses.web_dashboard import WebDashboardResponse
    
    firewall = FirewallResponse(event_bus)
    notifier = EmailResponse(event_bus, admin_email=config.get("response", {}).get("admin_email", "admin@localhost"))
    web_dashboard = WebDashboardResponse(event_bus)
    
    # 6. Initialize Detection Engine (Sigma Rules)
    from engine.rule_engine import RuleEngine
    rule_engine = RuleEngine(event_bus, rules_dir=config.get("rules", {}).get("path", "rules/"))
    
    # 7. Initialize Ingestion Collectors
    from collectors.log_collector import AuthLogCollector, SnortLogCollector
    from collectors.network_collector import NetworkCollector
    
    auth_log_path = config.get("logs", {}).get("auth_log", "/var/log/auth.log")
    snort_log_path = config.get("logs", {}).get("snort_log", "/var/log/snort/snort.alert.fast")
    
    auth_collector = AuthLogCollector(event_bus, log_file=auth_log_path)
    snort_collector = SnortLogCollector(event_bus, log_file=snort_log_path)
    
    auth_collector.start()
    snort_collector.start()

    # File Integrity Monitoring (FIM) Collector
    fim_config = config.get("fim", {})
    if fim_config.get("enabled", False):
        from collectors.fim_collector import FIMCollector
        fim_targets = fim_config.get("targets", [])
        fim_interval = fim_config.get("check_interval", 60)
        fim_collector = FIMCollector(event_bus, targets=fim_targets, check_interval=fim_interval)
        fim_collector.start()

    # Network Sniffer / Collector
    net_config = config.get("network", {})
    net_enabled = net_config.get("enabled", True)
    net_interface = net_config.get("interface", "")
    
    net_collector = NetworkCollector(event_bus, interface=net_interface, enabled=net_enabled)
    net_collector.start()
    
    # 8. Start Web Dashboard API Server
    from api.server import start_server
    start_server(host="0.0.0.0", port=8000)
    
    logger.info("==================================================")
    logger.info("Owl Monitor Platform initialized and running.")
    logger.info("Web Dashboard live at: http://localhost:8000")
    logger.info("Press Ctrl+C to stop.")
    logger.info("==================================================")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down Owl Monitor platform...")

if __name__ == "__main__":
    main()
