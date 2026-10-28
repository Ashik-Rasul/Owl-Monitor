import datetime
from core.logger import setup_logger
from core.event_bus import EventBus

logger = setup_logger(__name__)


class WebDashboardResponse:
    """
    Bridges the EventBus to the Web Dashboard.
    Subscribes to alert_triggered and normalized_event topics,
    formats the data, and pushes it to all connected WebSocket clients
    via the api.server module.
    """

    def __init__(self, event_bus: EventBus):
        self.event_bus = event_bus
        self.event_bus.subscribe("alert_triggered", self.handle_alert)
        self.event_bus.subscribe("normalized_event", self.handle_event)
        logger.info("WebDashboardResponse initialized and subscribed.")

    def handle_alert(self, alert: dict):
        """Format an alert for the frontend and push it to the API store."""
        from api.server import push_alert

        event = alert.get("event", {})
        ti = alert.get("threat_intel", {})
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")

        formatted = {
            "id": alert.get("id") or f"alert-{int(datetime.datetime.now().timestamp() * 1000)}",
            "time": timestamp,
            "rule_title": alert.get("rule_title", "Unknown"),
            "level": alert.get("level", "Low"),
            "risk_score": alert.get("risk_score", 0),
            "action": alert.get("action", "alert_only"),
            "ip": event.get("ip", "N/A"),
            "dst_ip": event.get("dst_ip", "N/A"),
            "sport": event.get("sport", "N/A"),
            "dport": event.get("dport", event.get("dst_port", "N/A")),
            "protocol": event.get("protocol") or ("TCP" if "tcp" in event.get("event_type", "") else "UDP" if ("udp" in event.get("event_type", "") or "dns" in event.get("event_type", "")) else "ICMP" if "icmp" in event.get("event_type", "") else "ARP" if "arp" in event.get("event_type", "") else "N/A"),
            "flags": event.get("flags", "N/A"),
            "query": event.get("query", "N/A"),
            "entropy": event.get("entropy", "N/A"),
            "interval": event.get("interval", "N/A"),
            "ports_scanned": event.get("ports_scanned", []),
            "threshold": alert.get("threshold", {}),
            "logsource": event.get("logsource", "unknown"),
            "raw_log": event.get("raw_log", ""),
            "username": event.get("username", ""),
            # FIM-specific fields
            "file": event.get("file", ""),
            "event_desc": event.get("event_desc", ""),
            "previous_hash": event.get("previous_hash", ""),
            "current_hash": event.get("current_hash", ""),
            "owner": event.get("owner", ""),
            "permissions": event.get("permissions", ""),
            # Threat Intelligence
            "threat_intel": {
                "matched": ti.get("matched", False),
                "country": ti.get("country", "Unknown"),
                "isp": ti.get("isp", "Unknown"),
                "asn": ti.get("asn", "Unknown"),
                "malicious_score": ti.get("malicious_score", 0),
                "known_botnet": ti.get("known_botnet", False),
                "abuse_reports": ti.get("abuse_reports", 0),
                "feed": ti.get("feed", ""),
            },
            "status": "Active",
        }

        logger.info(f"Pushing alert to dashboard: {formatted['rule_title']}")
        push_alert(formatted)

    def handle_event(self, event: dict):
        """Push raw normalized events to the dashboard for the network counter."""
        from api.server import push_event

        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        formatted = {
            "time": timestamp,
            "logsource": event.get("logsource", "unknown"),
            "event_type": event.get("event_type", "unknown"),
            "ip": event.get("ip", "N/A"),
            "dst_ip": event.get("dst_ip", "N/A"),
            "sport": event.get("sport", "N/A"),
            "dport": event.get("dport", event.get("dst_port", "N/A")),
            "protocol": "TCP" if "tcp" in event.get("event_type", "") else "UDP" if ("udp" in event.get("event_type", "") or "dns" in event.get("event_type", "")) else "ICMP" if "icmp" in event.get("event_type", "") else "ARP" if "arp" in event.get("event_type", "") else "N/A",
            "flags": event.get("flags", "N/A"),
            "query": event.get("query", "N/A"),
        }
        push_event(formatted)
