import time
import re
import os
import select
import threading
from core.logger import setup_logger
from core.event_bus import EventBus

logger = setup_logger(__name__)

class BaseCollector(threading.Thread):
    def __init__(self, event_bus: EventBus, log_file: str):
        super().__init__(daemon=True)
        self.event_bus = event_bus
        self.log_file = log_file
        self.running = True

    def stop(self):
        self.running = False

    def run(self):
        target_path = self.log_file
        if not os.path.exists(target_path):
            local_fallback = os.path.basename(self.log_file)
            if os.path.exists(local_fallback):
                target_path = local_fallback
                logger.info(f"Primary log file {self.log_file} not found. Falling back to local file {target_path}")
            else:
                logger.warning(f"Log file not found: {self.log_file} (or local {local_fallback}). Monitoring will wait until file exists.")
                return

        logger.info(f"Started monitoring {target_path}")
        try:
            with open(target_path, "r") as f:
                f.seek(0, 2)
                while self.running:
                    line = f.readline()
                    if not line:
                        time.sleep(0.5)
                        continue
                    self.process_line(line)
        except Exception as e:
            logger.error(f"Error reading {self.log_file}: {e}")

    def process_line(self, line: str):
        pass


class AuthLogCollector(BaseCollector):
    def __init__(self, event_bus: EventBus, log_file: str = "auth.log"):
        super().__init__(event_bus, log_file)
        self.fail_pattern = r"Failed .*? for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)"
        self.success_pattern = r"Accepted .* for (\S+) from (\d+\.\d+\.\d+\.\d+)"

    def process_line(self, line: str):
        fail_match = re.search(self.fail_pattern, line)
        if fail_match:
            username = fail_match.group(1)
            ip = fail_match.group(2)
            event = {
                "logsource": "auth",
                "event_type": "failed_login",
                "ip": ip,
                "username": username,
                "raw_log": line.strip()
            }
            logger.info(f"LogCollector parsed event: {event['event_type']} for user {username} from {ip}")
            self.event_bus.publish("normalized_event", event)


class SnortLogCollector(BaseCollector):
    def __init__(self, event_bus: EventBus, log_file: str = "snort.alert.fast"):
        super().__init__(event_bus, log_file)
        self.ip_regex = r'(\d+\.\d+\.\d+\.\d+)'

    def process_line(self, line: str):
        ip_match = re.findall(self.ip_regex, line)
        if ip_match:
            attacker_ip = ip_match[0]
            event = {
                "logsource": "snort",
                "event_type": "snort_alert",
                "ip": attacker_ip,
                "raw_log": line.strip()
            }
            logger.info(f"LogCollector parsed event: {event['event_type']} from {attacker_ip}")
            self.event_bus.publish("normalized_event", event)
