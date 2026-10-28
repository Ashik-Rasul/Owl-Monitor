import zlib
from abc import ABC, abstractmethod
from core.logger import setup_logger

logger = setup_logger(__name__)

class TIProvider(ABC):
    @abstractmethod
    def query(self, ip: str) -> dict:
        """
        Query the Threat Intelligence provider for a specific IP.
        Returns a normalized dictionary.
        """
        pass

class MockProvider(TIProvider):
    """
    Mock Threat Intelligence Provider for testing and local demonstration.
    Contains pre-configured profiles for multi-country testing and a dynamic
    fallback generator to support an arbitrary number of test IPs.
    """
    MALICIOUS_IPS = {
        # Configured test IPs for multi-country demonstration
        "45.227.254.12": {
            "country": "Russia",
            "isp": "Rostelecom ISP",
            "asn": "AS12345",
            "known_botnet": True,
            "malicious_score": 98,
            "abuse_reports": 1234
        },
        "185.220.101.1": {
            "country": "USA",
            "isp": "Tor Exit Node Inc",
            "asn": "AS60729",
            "known_botnet": True,
            "malicious_score": 91,
            "abuse_reports": 876
        },
        "1.2.3.4": {
            "country": "China",
            "isp": "China Telecom / APNIC",
            "asn": "AS4589",
            "known_botnet": True,
            "malicious_score": 95,
            "abuse_reports": 1021
        },
        "5.9.158.75": {
            "country": "Germany",
            "isp": "Hetzner Online GmbH",
            "asn": "AS24940",
            "known_botnet": False,
            "malicious_score": 87,
            "abuse_reports": 542
        },
        "177.54.147.1": {
            "country": "Brazil",
            "isp": "Claro Telecom S.A.",
            "asn": "AS28573",
            "known_botnet": True,
            "malicious_score": 93,
            "abuse_reports": 765
        },
        "103.25.45.10": {
            "country": "India",
            "isp": "Bharti Airtel Limited",
            "asn": "AS55836",
            "known_botnet": False,
            "malicious_score": 82,
            "abuse_reports": 321
        },
        # Additional standard mock IPs
        "8.8.8.8": {
            "country": "US",
            "isp": "Google LLC",
            "asn": "AS15169",
            "known_botnet": False,
            "malicious_score": 90,
            "abuse_reports": 500
        },
        "192.168.1.99": {
            "country": "Local",
            "isp": "Internal",
            "asn": "N/A",
            "known_botnet": False,
            "malicious_score": 75,
            "abuse_reports": 10
        },
        "203.0.113.50": {
            "country": "Unknown",
            "isp": "Unknown",
            "asn": "Unknown",
            "known_botnet": True,
            "malicious_score": 100,
            "abuse_reports": 5000
        },
        "198.51.100.11": {
            "country": "Unknown",
            "isp": "Unknown",
            "asn": "Unknown",
            "known_botnet": True,
            "malicious_score": 100,
            "abuse_reports": 800
        }
    }

    def _is_local_ip(self, ip: str) -> bool:
        if not ip or ip in ("0.0.0.0", "127.0.0.1", "::1", "localhost", "N/A", "Unknown"):
            return True
        octets = ip.split(".")
        if len(octets) == 4 and all(o.isdigit() for o in octets):
            o1, o2 = int(octets[0]), int(octets[1])
            if o1 == 10 or (o1 == 172 and 16 <= o2 <= 31) or (o1 == 192 and o2 == 168):
                return True
        return False

    def _generate_dynamic_ti(self, ip: str) -> dict:
        """
        Deterministically generates realistic Threat Intel data for arbitrary external IPs.
        Ensures the architecture supports an arbitrary number of attacker IPs independently.
        """
        seed = zlib.crc32(ip.encode("utf-8"))
        countries = [
            ("United States", "US-Comcast", "AS7922"),
            ("United Kingdom", "BT Group", "AS2856"),
            ("France", "Orange S.A.", "AS3215"),
            ("Netherlands", "KPN B.V.", "AS1136"),
            ("Japan", "NTT Communications", "AS2914"),
            ("Canada", "Rogers Communications", "AS812"),
            ("Australia", "Telstra Corp", "AS1221"),
            ("Singapore", "Singtel", "AS7473"),
        ]
        country_data = countries[seed % len(countries)]
        score = 75 + (seed % 25)  # 75 to 99
        reports = 100 + (seed % 1500)
        botnet = (seed % 2 == 1)

        return {
            "matched": True,
            "country": country_data[0],
            "isp": country_data[1],
            "asn": country_data[2],
            "malicious_score": score,
            "known_botnet": botnet,
            "abuse_reports": reports
        }

    def query(self, ip: str) -> dict:
        # Check explicit pre-configured table
        if ip in self.MALICIOUS_IPS:
            data = self.MALICIOUS_IPS[ip]
            return {
                "matched": True,
                "country": data.get("country", "Unknown"),
                "isp": data.get("isp", "Mock ISP"),
                "asn": data.get("asn", "AS0000"),
                "malicious_score": data.get("malicious_score", data.get("score", 85)),
                "known_botnet": data.get("known_botnet", data.get("botnet", False)),
                "abuse_reports": data.get("abuse_reports", data.get("reports", 100))
            }

        # Ignore local and loopback addresses
        if self._is_local_ip(ip):
            return {"matched": False}

        # Dynamic fallback for arbitrary public test IPs
        return self._generate_dynamic_ti(ip)

class AbuseIPDBProvider(TIProvider):
    def __init__(self, api_key: str):
        self.api_key = api_key

    def query(self, ip: str) -> dict:
        if not self.api_key:
            return {"matched": False}
        try:
            import requests
            response = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": self.api_key, "Accept": "application/json"},
                timeout=5
            )
            if response.status_code == 200:
                res_data = response.json().get("data", {})
                score = res_data.get("abuseConfidenceScore", 0)
                if score > 0:
                    return {
                        "matched": True,
                        "country": res_data.get("countryCode", "Unknown"),
                        "isp": res_data.get("isp", "Unknown"),
                        "asn": f"AS{res_data.get('asn', '')}",
                        "malicious_score": score,
                        "known_botnet": score > 80,
                        "abuse_reports": res_data.get("totalReports", 0)
                    }
        except Exception as e:
            logger.debug(f"AbuseIPDB query failed for {ip}: {e}")
        return {"matched": False}

class ThreatIntel:
    _providers = []
    _initialized = False

    @classmethod
    def initialize(cls, config: dict):
        if cls._initialized:
            return
            
        cls._providers = []
        # Always add MockProvider for demonstration and test suites
        cls._providers.append(MockProvider())
        
        ti_config = config.get("threat_intel", {})
        abuse_key = ti_config.get("abuseipdb", {}).get("api_key")
        if abuse_key:
            cls._providers.append(AbuseIPDBProvider(abuse_key))
            
        cls._initialized = True

    @classmethod
    def check_ip(cls, ip: str) -> dict:
        """
        Check if an IP address is present in Threat Intelligence.
        Accepts the IP explicitly per call with no global IP state.
        Queries all configured providers and returns the highest severity match.
        """
        if not cls._initialized:
            cls.initialize({})

        logger.info(f"[TI] Checking IP: {ip}")

        best_match = {
            "matched": False,
            "feed": None,
            "country": "Unknown",
            "isp": "Unknown",
            "asn": "Unknown",
            "malicious_score": 0,
            "known_botnet": False,
            "abuse_reports": 0
        }

        if not ip:
            return best_match

        for provider in cls._providers:
            result = provider.query(ip)
            if result.get("matched"):
                if result.get("malicious_score", 0) > best_match.get("malicious_score", 0):
                    best_match.update(result)
                    best_match["feed"] = provider.__class__.__name__

        if best_match.get("matched"):
            botnet_str = "YES" if best_match.get("known_botnet") else "NO"
            logger.info(
                f"[TI] Result: {best_match.get('country')} | "
                f"Malicious: {best_match.get('malicious_score')}% | "
                f"Botnet: {botnet_str} | "
                f"Abuse Reports: {best_match.get('abuse_reports')}"
            )
        else:
            logger.info(f"[TI] Result: {ip} - No Threat Intel match")

        return best_match
