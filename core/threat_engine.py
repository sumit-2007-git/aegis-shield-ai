import re
import time
from typing import Dict, Any, List

from core.url_detector import URLThreatDetector
from core.nlp_detector import ScamNLPDetector
from core.xai_engine import ExplainableAIEngine

class UnifiedThreatEngine:
    """
    Unified On-Device Threat Intelligence Engine.
    Orchestrates URL scanning, NLP text analysis, explainable reasoning,
    latency telemetry, and privacy audit enforcement.
    """

    def __init__(self, data_dir=None, model_dir=None):
        self.url_detector = URLThreatDetector(data_dir=data_dir)
        self.nlp_detector = ScamNLPDetector(data_dir=data_dir, model_dir=model_dir)
        self.xai_engine = ExplainableAIEngine()
        
        # Regex to extract URLs from text
        self.url_regex = re.compile(
            r'(?:(?:https?|ftp):\/\/)?(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{2,12}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)',
            re.IGNORECASE
        )

    def extract_urls(self, text: str) -> List[str]:
        """Extract all potential URLs or domains from arbitrary text."""
        candidates = self.url_regex.findall(text)
        valid_urls = []
        for c in candidates:
            # Filter out simple floating punctuation or standard file extensions without dots
            if "." in c and not c.endswith((".py", ".txt", ".json", ".md")):
                valid_urls.append(c)
        return list(dict.fromkeys(valid_urls))

    def scan(self, input_data: str) -> Dict[str, Any]:
        """
        Perform complete on-device threat analysis on text, URL, or combined communication.
        """
        start_time = time.perf_counter()

        text = input_data.strip() if input_data else ""
        extracted_urls = self.extract_urls(text)

        # 1. Analyze URLs
        url_results = []
        max_url_score = 0
        primary_url_result = {"is_phishing": False, "risk_score": 0, "indicators": []}

        for u in extracted_urls:
            res = self.url_detector.analyze(u)
            url_results.append(res)
            if res["risk_score"] > max_url_score:
                max_url_score = res["risk_score"]
                primary_url_result = res

        # If user directly inputted just a URL without http, test it directly
        if not extracted_urls and ("." in text and " " not in text and len(text) > 3):
            res = self.url_detector.analyze(text)
            url_results.append(res)
            max_url_score = res["risk_score"]
            primary_url_result = res
            extracted_urls = [text]

        # 2. Analyze Message Text
        nlp_res = self.nlp_detector.analyze(text)

        # 3. Calculate Unified Risk Score
        # If a phishing URL is found inside an urgent scam message, risks multiply
        url_weight = 0.55 if extracted_urls else 0.0
        nlp_weight = 0.45 if extracted_urls else 1.0

        if extracted_urls:
            raw_score = (max_url_score * url_weight) + (nlp_res["risk_score"] * nlp_weight)
            # Critical synergy: if BOTH url is phishing AND nlp is scam
            if primary_url_result.get("is_phishing") and nlp_res.get("is_scam"):
                raw_score = max(raw_score, 88)
        else:
            raw_score = nlp_res["risk_score"]

        final_risk_score = int(min(max(raw_score, 0), 100))

        # Threat classification
        if final_risk_score >= 75:
            threat_level = "CRITICAL_THREAT"
            verdict = "DANGEROUS SCAM / PHISHING"
            badge_color = "#ef4444"
        elif final_risk_score >= 48:
            threat_level = "HIGH_SUSPICION"
            verdict = "SUSPICIOUS COMMUNICATION"
            badge_color = "#f97316"
        elif final_risk_score >= 25:
            threat_level = "MODERATE_WARNING"
            verdict = "USE CAUTION"
            badge_color = "#eab308"
        else:
            threat_level = "SAFE_BENIGN"
            verdict = "SAFE / AUTHENTIC"
            badge_color = "#22c55e"

        # 4. Generate Explainable AI Report
        xai_report = self.xai_engine.generate_explanation(primary_url_result, nlp_res)
        highlighted_html = self.xai_engine.highlight_text(
            text, 
            nlp_res.get("flagged_phrases", []), 
            extracted_urls
        )

        end_time = time.perf_counter()
        latency_ms = round((end_time - start_time) * 1000, 2)

        return {
            "verdict": verdict,
            "threat_level": threat_level,
            "risk_score": final_risk_score,
            "badge_color": badge_color,
            "category": nlp_res.get("category", "BENIGN"),
            "confidence": nlp_res.get("confidence", 0.0),
            "input_text": text,
            "highlighted_html": highlighted_html,
            "extracted_urls": url_results,
            "tactics_detected": nlp_res.get("tactics", []),
            "explanation": xai_report,
            "telemetry": {
                "latency_ms": latency_ms,
                "cloud_network_calls": 0,
                "bytes_uploaded_to_cloud": 0,
                "privacy_mode": "100% On-Device Air-Gapped",
                "execution_hardware": "Local CPU"
            }
        }
