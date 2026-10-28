import os
import yaml
import time
import uuid
import threading
from collections import defaultdict
from core.logger import setup_logger
from core.event_bus import EventBus

logger = setup_logger(__name__)

class RuleEngine:
    def __init__(self, event_bus: EventBus, rules_dir: str = "rules/"):
        self.event_bus = event_bus
        self.rules_dir = rules_dir
        self.rules = []
        self.state = defaultdict(dict)  # { rule_id: { ip: [timestamps] } }
        self._lock = threading.Lock()
        
        self.load_rules()
        self.event_bus.subscribe("normalized_event", self.evaluate_event)

    def load_rules(self):
        if not os.path.exists(self.rules_dir):
            logger.warning(f"Rules directory {self.rules_dir} not found.")
            return

        for filename in sorted(os.listdir(self.rules_dir)):
            if filename.endswith(".yaml") or filename.endswith(".yml"):
                filepath = os.path.join(self.rules_dir, filename)
                try:
                    with open(filepath, 'r') as f:
                        rule = yaml.safe_load(f)
                        self.rules.append(rule)
                        logger.info(f"Loaded rule: {rule.get('title')}")
                except Exception as e:
                    logger.error(f"Failed to load rule {filename}: {e}")

    def evaluate_event(self, event: dict):
        for rule in self.rules:
            # 1. Match Log Source
            if rule.get('logsource') != event.get('logsource'):
                continue
                
            # 2. Match Selection Condition
            selection = rule.get('detection', {}).get('selection', {})
            match = True
            for k, v in selection.items():
                if event.get(k) != v:
                    match = False
                    break
                    
            if not match:
                continue

            # 3. Check Thresholds (keyed by field value, e.g. source IP)
            threshold = rule.get('detection', {}).get('threshold')
            if threshold:
                field_val = event.get(threshold['field'])
                if not field_val:
                    continue
                
                rule_id = rule.get('id')
                now = time.time()
                trigger_needed = False

                with self._lock:
                    if field_val not in self.state[rule_id]:
                        self.state[rule_id][field_val] = []
                    
                    self.state[rule_id][field_val].append(now)
                    
                    # Cleanup events older than timeframe
                    timeframe = threshold['timeframe']
                    self.state[rule_id][field_val] = [
                        t for t in self.state[rule_id][field_val] 
                        if now - t <= timeframe
                    ]
                    
                    if len(self.state[rule_id][field_val]) >= threshold['count']:
                        trigger_needed = True
                        # Clear state for this specific IP to avoid immediate spamming
                        self.state[rule_id][field_val].clear()

                if trigger_needed:
                    self._trigger_alert(rule, event)
            else:
                # No threshold, immediate trigger
                self._trigger_alert(rule, event)

    def _trigger_alert(self, rule: dict, event: dict):
        from utils.threat_intel import ThreatIntel
        from utils.risk_scorer import RiskScorer

        ip = event.get('ip')
        threat_intel_result = ThreatIntel.check_ip(ip) if ip else {"matched": False, "feed": None, "risk_increase": 0}
        
        level = rule.get('level', 'Low')
        risk_score = RiskScorer.calculate_score(level, threat_intel_result)
        alert_id = f"alert-{int(time.time() * 1000)}-{uuid.uuid4().hex[:6]}"

        alert = {
            "id": alert_id,
            "rule_title": rule.get('title'),
            "level": level,
            "action": rule.get('action'),
            "threshold": rule.get('detection', {}).get('threshold', {}),
            "event": dict(event),
            "threat_intel": dict(threat_intel_result),
            "risk_score": risk_score
        }

        # Clear structured debug logging for Threat Intelligence pipeline
        logger.info(f"[TI] Event ID: {alert_id}")
        logger.info(f"[TI] Source IP: {ip or 'N/A'}")
        logger.info(f"[TI] Provider: {threat_intel_result.get('feed', 'None')}")
        logger.info(f"[TI] Country: {threat_intel_result.get('country', 'Unknown')}")
        score_val = f"{risk_score:.0f}" if isinstance(risk_score, (int, float)) else str(risk_score)
        logger.info(f"[TI] Risk Score: {score_val}")

        logger.warning(
            f"ALERT TRIGGERED: {alert['rule_title']} - Level: {alert['level']} - Target: {ip} - Risk Score: {score_val}"
        )
        self.event_bus.publish("alert_triggered", alert)
