# Owl Monitor - AI Handoff & Context

## Welcome!
If you are an AI assistant reading this, you are working on the **Owl Monitor** project. This document provides the essential context you need to seamlessly continue development.

## Project Summary
Owl Monitor is a custom **Intrusion Detection System (IDS)** and **Security Orchestration, Automation, and Response (SOAR)** tool built in Python for Linux environments. It actively monitors system logs (Auth, Snort) and sniffs live network traffic (using Scapy) to detect anomalies.

## Architecture

1. **Core:** 
   - `core/event_bus.py`: The heart of the system. Publishers emit events, Subscribers react.
   - `config/settings.yaml`: The central configuration file.

2. **Collectors (Ingestion):**
   - `AuthLogCollector`: Parses SSH logins from `/var/log/auth.log`.
   - `SnortLogCollector`: Parses secondary IDS alerts.
   - `NetworkCollector`: Sniffs traffic to detect Port Scans, SYN Floods, Beaconing, ARP Spoofing, and DNS Tunneling.
   - `FIMCollector` (File Integrity Monitoring): Watches critical files like `/etc/passwd` for unauthorized changes (hashes, ownership, permissions).

3. **Detection Engine (`engine/rule_engine.py`):**
   - Loads Sigma-style YAML rules from the `rules/` directory.
   - Tracks stateful thresholds (e.g., 5 failed logins within 120 seconds).
   - Generates alerts when conditions are met.

4. **Threat Intelligence (`utils/threat_intel.py`):**
   - Implements a `TIProvider` interface (AbuseIPDB, OTX, VirusTotal, MockProvider).
   - Enriches alerts with external IP reputation data.
   - Calculates a risk score via `utils/risk_scorer.py`.

5. **Responses (SOAR):**
   - `FirewallResponse`: Blocks IPs instantly using `iptables`.
   - `EmailResponse`: Sends detailed alert emails with TI context, using a 5-minute cooldown per IP/Rule.

6. **Web Dashboard (Frontend):**
   - Located in the `web-ui/` directory.
   - Built using Vite, Vanilla JS, and Vanilla CSS (no React/Vue/Tailwind) to ensure maximum design control and a clean SOC (Security Operations Center) aesthetic.
   - Currently populated with mock data for aesthetic validation.

## Current State & Next Steps
We have just finished designing the beautiful, dark-themed frontend Dashboard in `web-ui/` using mock data. 

**Future Priorities:**
1. **API Integration:** Add a FastAPI server to `main.py` (or a separate `api.py`) to expose endpoints for the frontend.
2. **WebSockets:** Implement real-time WebSocket streaming from the `EventBus` to the web dashboard so alerts appear live without refreshing.
3. **Database:** Introduce SQLite or Redis for persistent storage of alerts and Threat Intelligence caches.

When the user asks you to implement a new feature, refer to this architecture and maintain the existing patterns (especially the decoupled `EventBus` approach).
