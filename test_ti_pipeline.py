import sys
import os
import time

def run_tests():
    print("=" * 60)
    print("       OWL MONITOR — THREAT INTELLIGENCE TEST SUITE      ")
    print("=" * 60)

    # 1. Initialize EventBus, Config, ThreatIntel
    from core.event_bus import EventBus
    from core.config_loader import ConfigLoader
    from utils.threat_intel import ThreatIntel
    from engine.rule_engine import RuleEngine
    from responses.web_dashboard import WebDashboardResponse
    from collectors.log_collector import AuthLogCollector
    from api.server import get_store

    config = ConfigLoader.load()
    ThreatIntel.initialize(config)
    event_bus = EventBus()
    web_dashboard = WebDashboardResponse(event_bus)
    rule_engine = RuleEngine(event_bus, rules_dir="rules/")
    auth_collector = AuthLogCollector(event_bus, log_file="auth.log")

    test_ips = [
        ("45.227.254.12", "Russia", 98, True, 1234),
        ("185.220.101.1", "USA", 91, True, 876),
        ("1.2.3.4", "China", 95, True, 1021),
        ("5.9.158.75", "Germany", 87, False, 542),
        ("177.54.147.1", "Brazil", 93, True, 765),
        ("103.25.45.10", "India", 82, False, 321),
    ]

    print("\n--- PHASE 1: DIRECT THREAT INTEL LOOKUP TEST ---")
    ti_success_count = 0
    for ip, expected_country, expected_score, expected_botnet, expected_reports in test_ips:
        res = ThreatIntel.check_ip(ip)
        assert res["matched"] is True, f"Failed match for {ip}"
        assert res["country"] == expected_country, f"Expected {expected_country}, got {res['country']}"
        assert res["malicious_score"] == expected_score, f"Expected {expected_score}, got {res['malicious_score']}"
        assert res["known_botnet"] == expected_botnet, f"Expected {expected_botnet}, got {res['known_botnet']}"
        assert res["abuse_reports"] == expected_reports, f"Expected {expected_reports}, got {res['abuse_reports']}"
        ti_success_count += 1
        print(f"[OK] {ip:<15} -> {res['country']:<10} Score: {res['malicious_score']}% Botnet: {res['known_botnet']} Reports: {res['abuse_reports']}")

    assert ti_success_count == 6, f"Expected 6 successful TI lookups, got {ti_success_count}"

    print("\n--- PHASE 2: ARBITRARY ATTACKER IP TEST ---")
    arb_ip = "84.17.45.99"
    arb_res = ThreatIntel.check_ip(arb_ip)
    assert arb_res["matched"] is True, "Arbitrary IP should have dynamic TI match"
    print(f"[OK] Dynamic IP {arb_ip:<15} -> {arb_res['country']} Score: {arb_res['malicious_score']}% (Dynamic support works)")

    print("\n--- PHASE 3: SIMULATE 6 ATTACKERS (5 ATTEMPTS EACH) ---")
    # Feed 5 failed login lines for each of the 6 IPs
    for ip, country, score, botnet, reports in test_ips:
        for attempt in range(1, 6):
            log_line = f"Failed password for invalid user admin from {ip} port 22 ssh2"
            auth_collector.process_line(log_line)

    store = get_store()
    alerts = store.get("alerts", [])
    ti_map = store.get("threat_intel", {})

    print(f"\nTotal alerts triggered: {len(alerts)}")
    print(f"Total TI entries stored: {len(ti_map)}")

    # Verify every IP generated its own alert
    alert_ips = [a.get("ip") for a in alerts]
    print(f"Alerted IPs: {alert_ips}")

    for ip, country, score, botnet, reports in test_ips:
        assert ip in alert_ips, f"Missing alert for IP {ip}"
        matching_alert = next(a for a in alerts if a.get("ip") == ip)
        ti_data = matching_alert.get("threat_intel", {})
        assert ti_data.get("matched") is True, f"TI not matched in alert for {ip}"
        assert ti_data.get("country") == country, f"Expected country {country}, got {ti_data.get('country')}"
        assert ti_data.get("malicious_score") == score, f"Expected score {score}, got {ti_data.get('malicious_score')}"
        print(f"[OK] Alert Verified: {ip} -> Country: {country}, Risk Score: {matching_alert['risk_score']:.1f}")

    print("\n--- PHASE 4: REGRESSION TEST - SINGLE IP DETECTION ---")
    single_ip = "45.227.254.12"
    for attempt in range(1, 6):
        auth_collector.process_line(f"Failed password for invalid user admin from {single_ip} port 22 ssh2")
    
    updated_store = get_store()
    latest_alert = updated_store["alerts"][0]
    assert latest_alert["ip"] == single_ip
    assert latest_alert["threat_intel"]["country"] == "Russia"
    print(f"[OK] Single-IP regression passed for {single_ip} (Country: {latest_alert['threat_intel']['country']})")

    print("\n" + "=" * 60)
    print("             OWL MONITOR - THREAT INTELLIGENCE              ")
    print("=" * 60)
    print(f"{'IP':<18} {'COUNTRY':<12} {'MALICIOUS':<12} {'BOTNET':<10}")
    print("-" * 60)
    for ip, country, score, botnet, reports in test_ips:
        ti = ti_map.get(ip, {})
        botnet_text = "YES" if ti.get("known_botnet") else "NO"
        print(f"{ip:<18} {ti.get('country', country):<12} {str(ti.get('malicious_score', score)) + '%':<12} {botnet_text:<10}")
    print("-" * 60)
    print(f"Total attackers: {len(test_ips)}")
    print(f"TI lookups:      {len(test_ips)}")
    print("=" * 60)
    print("ALL TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    run_tests()
