import time
import os
import hashlib
import stat
import threading
from core.logger import setup_logger
from core.event_bus import EventBus

logger = setup_logger(__name__)

class FIMCollector(threading.Thread):
    def __init__(self, event_bus: EventBus, targets: list, check_interval: int = 60):
        super().__init__(daemon=True)
        self.event_bus = event_bus
        self.targets = targets
        self.check_interval = check_interval
        self.running = True
        self.baseline = {}
        
        # Create baseline on startup
        self._create_baseline()

    def stop(self):
        self.running = False

    def _hash_file(self, filepath: str) -> str:
        sha256 = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                while chunk := f.read(8192):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except FileNotFoundError:
            return None
        except PermissionError:
            logger.warning(f"[WARNING] FIM: Permission denied reading {filepath}. Run as root for full FIM coverage.")
            return None
        except Exception as e:
            logger.warning(f"FIM: Error reading {filepath}: {e}")
            return None

    def _get_file_info(self, filepath: str) -> dict:
        try:
            st = os.stat(filepath)
            return {
                "hash": self._hash_file(filepath),
                "permissions": oct(stat.S_IMODE(st.st_mode)),
                "owner_uid": st.st_uid,
                "exists": True
            }
        except FileNotFoundError:
            return {"exists": False}
        except PermissionError:
            logger.warning(f"[WARNING] FIM: Permission denied inspecting {filepath}. Skipping.")
            return {"exists": False}
        except Exception as e:
            logger.warning(f"FIM: Error inspecting {filepath}: {e}")
            return {"exists": False}

    def _create_baseline(self):
        logger.info(f"FIM: Creating baseline for {len(self.targets)} files...")
        for filepath in self.targets:
            self.baseline[filepath] = self._get_file_info(filepath)
            
    def _check_files(self):
        for filepath in self.targets:
            current = self._get_file_info(filepath)
            base = self.baseline.get(filepath, {"exists": False})
            
            if not base["exists"] and current["exists"]:
                self._trigger_violation(filepath, "File Created", base, current)
            elif base["exists"] and not current["exists"]:
                self._trigger_violation(filepath, "File Deleted", base, current)
            elif base["exists"] and current["exists"]:
                if base["hash"] != current["hash"]:
                    self._trigger_violation(filepath, "File Modified", base, current)
                elif base["permissions"] != current["permissions"]:
                    self._trigger_violation(filepath, "Permissions Changed", base, current)
                elif base["owner_uid"] != current["owner_uid"]:
                    self._trigger_violation(filepath, "Ownership Changed", base, current)
                    
            # Update baseline
            self.baseline[filepath] = current

    def _trigger_violation(self, filepath: str, event_desc: str, base: dict, current: dict):
        # Resolve UID to owner name (basic attempt, defaults to root or uid)
        owner_name = "root" if current.get("owner_uid") == 0 else str(current.get("owner_uid", "Unknown"))
        
        event = {
            "logsource": "fim",
            "event_type": "fim_violation",
            "file": filepath,
            "event_desc": event_desc,
            "previous_hash": base.get("hash", "N/A"),
            "current_hash": current.get("hash", "N/A"),
            "owner": owner_name,
            "permissions": current.get("permissions", "N/A").replace('0o', '') if current.get("permissions") else "N/A",
            "raw_log": f"FIM Violation: {filepath} - {event_desc}"
        }
        
        logger.warning(f"FIM VIOLATION DETECTED: {filepath} ({event_desc})")
        self.event_bus.publish("normalized_event", event)

    def run(self):
        logger.info(f"Started FIMCollector. Polling every {self.check_interval} seconds.")
        while self.running:
            time.sleep(self.check_interval)
            self._check_files()
