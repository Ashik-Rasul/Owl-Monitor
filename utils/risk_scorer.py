class RiskScorer:
    # Base scores for various alert levels
    SEVERITY_BASE_SCORES = {
        "Critical": 85,
        "Very High": 70,
        "High": 55,
        "Medium": 35,
        "Low": 15,
        "Informational": 5
    }

    @classmethod
    def calculate_score(cls, level: str, threat_intel_result: dict) -> float:
        """
        Calculate a final risk score (0-100) based on the alert severity level
        and the detailed threat intelligence lookup metrics.
        """
        # Get base score based on severity level, defaulting to Low (15)
        base_score = cls.SEVERITY_BASE_SCORES.get(level, 15)
        
        if threat_intel_result.get("matched", False):
            # Mathematically adjust the score based on TI metrics
            ti_score = threat_intel_result.get("malicious_score", 0)
            reports = threat_intel_result.get("abuse_reports", 0)
            
            # Convert 0-100 malicious score to a +0 to +30 risk increase
            risk_increase = (ti_score / 100.0) * 30
            
            # Add up to +15 based on the volume of abuse reports (capping at 1000 reports)
            report_penalty = min(reports / 1000.0, 1.0) * 15
            
            # Add +10 if it's a known botnet
            if threat_intel_result.get("known_botnet"):
                risk_increase += 10
                
            base_score += risk_increase + report_penalty
            
        # Clamp the score to ensure it falls strictly in the 0-100 range
        return min(max(base_score, 0), 100)
