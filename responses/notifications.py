import time
from core.logger import setup_logger
from core.event_bus import EventBus

logger = setup_logger(__name__)

# Cooldown period in seconds — only 1 email per rule+IP within this window
EMAIL_COOLDOWN_SECONDS = 300  # 5 minutes

class EmailResponse:
    def __init__(self, event_bus: EventBus, admin_email: str = "ashikrasul888@gmail.com"):
        self.event_bus = event_bus
        self.admin_email = admin_email
        self._last_sent = {}  # (rule_title, ip) -> timestamp of last email sent
        self.event_bus.subscribe("alert_triggered", self.handle_alert)

    def handle_alert(self, alert: dict):
        # Trigger email on High, Very High, or Critical alerts
        level = alert.get("level")
        if level in ["High", "Very High", "Critical"]:
            self.send_email(alert)

    def _is_on_cooldown(self, rule_title: str, ip: str) -> bool:
        """Return True if an email for this rule+IP was already sent within the cooldown window."""
        key = (rule_title, ip)
        now = time.time()
        last = self._last_sent.get(key, 0)
        if now - last < EMAIL_COOLDOWN_SECONDS:
            return True
        self._last_sent[key] = now
        return False

    def send_email(self, alert: dict):
        rule_title = alert.get('rule_title')
        event = alert.get("event", {})
        ip = event.get("ip", "Unknown")

        # ── Rate-limit: 1 email per rule + IP per cooldown window ──
        if self._is_on_cooldown(rule_title, ip):
            logger.debug(f"Email suppressed (cooldown active) for '{rule_title}' / IP {ip}")
            return

        logger.info(f"SOAR ACTION: Sending email alert to {self.admin_email} for '{rule_title}'")
        
        risk_score = alert.get("risk_score", 0)
        ti = alert.get("threat_intel", {})
        ti_str = f"[BLACKLISTED - {ti['feed']}]" if ti.get("matched") else ""

        severity = alert.get("level", "High")
        
        import datetime
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if "SSH Brute Force" in rule_title:
            count = alert.get("threshold", {}).get("count", 5)
            timeframe_sec = alert.get("threshold", {}).get("timeframe", 120)
            timeframe_min = timeframe_sec // 60 if timeframe_sec % 60 == 0 else round(timeframe_sec / 60, 1)
            username = event.get("username", "Unknown")
            
            ti_table = ""
            if ti.get("matched"):
                ti_table = f"""
╔══════════════════════════════════╗
║      THREAT INTELLIGENCE         ║
╠══════════════════════════════════╣
║ IP:              {ip:<15} ║
║ Country:         {ti.get('country', 'Unknown'):<15} ║
║ ISP:             {ti.get('isp', 'Unknown')[:15]:<15} ║
║ ASN:             {ti.get('asn', 'Unknown'):<15} ║
║ Malicious Score: {str(ti.get('malicious_score', 0)) + '%':<15} ║
║ Known Botnet:    {'YES' if ti.get('known_botnet') else 'NO':<15} ║
║ Abuse Reports:   {str(ti.get('abuse_reports', 0)):<15} ║
╚══════════════════════════════════╝
"""
            message = f"""🚨 **BRUTE FORCE ATTACK DETECTED**

**Detection:** {count} failed login attempts detected within {timeframe_min} minutes.
**Time:** {timestamp}
**Source IP:** {ip} {ti_str}
**Target:** {username}
**Severity:** 🔴 **{severity}** (Risk Score: {risk_score}/100)
{ti_table}
⚠️ **Immediate Security Check Required**

Owl Monitor has detected a possible SSH brute-force attack. Please perform an immediate security check and verify the source IP, affected account, and recent authentication activity.
"""
        elif "File Integrity Violation" in rule_title:
            fim_file = event.get("file", "Unknown")
            fim_event = event.get("event_desc", "Unknown")
            prev_hash = event.get("previous_hash", "Unknown")
            curr_hash = event.get("current_hash", "Unknown")
            owner = event.get("owner", "Unknown")
            perms = event.get("permissions", "Unknown")
            
            message = f"""[OWL MONITOR] CRITICAL - File Integrity Violation Detected

Owl Monitor detected an unauthorized change to a monitored
system file.

File: {fim_file}
Event: {fim_event}
Severity: 🔴 **CRITICAL**
Time: {timestamp}
Previous Hash: {prev_hash}
Current Hash: {curr_hash}
Owner: {owner}
Permissions: {perms}

The change should be investigated immediately to determine
whether it was caused by legitimate system administration,
software updates, or malicious activity.

Owl Monitor has recorded this event for further investigation.
"""
        else:
            raw_log = event.get("raw_log", "No raw log available")
            
            # Format Threat Intelligence Summary if matched
            if ti.get("matched"):
                subject_prefix = "CRITICAL - Malicious IP Detected"
                ti_table = f"""
╔══════════════════════════════════╗
║      THREAT INTELLIGENCE         ║
╠══════════════════════════════════╣
║ IP:              {ip:<15} ║
║ Country:         {ti.get('country', 'Unknown'):<15} ║
║ ISP:             {ti.get('isp', 'Unknown')[:15]:<15} ║
║ ASN:             {ti.get('asn', 'Unknown'):<15} ║
║ Malicious Score: {str(ti.get('malicious_score', 0)) + '%':<15} ║
║ Known Botnet:    {'YES' if ti.get('known_botnet') else 'NO':<15} ║
║ Abuse Reports:   {str(ti.get('abuse_reports', 0)):<15} ║
╚══════════════════════════════════╝

Recommendation:
Immediately investigate the source IP and
review related network and authentication events.
"""
            else:
                subject_prefix = f"ALERT: {rule_title}"
                ti_table = ""

            message = f"""⚠️ **SECURITY INCIDENT DETECTED**

**Rule:** {rule_title}
**Time:** {timestamp}
**Source IP:** {ip} {ti_str}
**Severity:** 🔴 **{severity}** (Risk Score: {risk_score:.1f}/100)

**Details:**
{raw_log}
{ti_table}
Owl Monitor has triggered an automatic response and logged this activity. Please review the network logs and host state.
"""

        # Escape single quotes for the bash command
        message_escaped = message.replace("'", "'\\''")
        
        # Determine subject based on rule_title for FIM and SSH, otherwise use the prefix
        if "File Integrity Violation" in rule_title:
            subject = f"CRITICAL - File Integrity Violation Detected [Risk: {risk_score:.1f}]"
        elif "SSH Brute Force" in rule_title:
            subject = f"ALERT: {rule_title} [Risk: {risk_score:.1f}]"
        else:
            subject = f"{subject_prefix} [Risk: {risk_score:.1f}]"
            
        import subprocess, shutil
        if not shutil.which("mail"):
            logger.warning("[WARNING] Email alert skipped: 'mail' command-line utility not found on host system.")
            return
            
        try:
            subprocess.call(f"echo '{message_escaped}' | mail -s '{subject}' {self.admin_email}", shell=True)
        except Exception as e:
            logger.warning(f"Failed to send email alert via mail command: {e}")
