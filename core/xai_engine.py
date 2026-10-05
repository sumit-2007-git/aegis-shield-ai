import re

class ExplainableAIEngine:
    """
    Explainable AI (XAI) engine for transparent security decision reasoning.
    Transforms raw ML & heuristic outputs into clear, educational explanations,
    visual text annotations, and proactive defensive recommendations.
    """

    RECOMMENDATIONS = {
        "KYC_BANKING_FRAUD": [
            "Never click SMS links to update KYC, PAN, or Aadhaar details.",
            "Official banks (SBI, HDFC, etc.) NEVER suspend accounts via SMS with third-party link updates.",
            "If in doubt, open the official mobile banking app directly or visit your physical bank branch.",
            "Report fraudulent messages immediately to National Cyber Crime Helpline (1930 in India)."
        ],
        "UTILITY_DISCONNECTION_SCAM": [
            "Electricity distribution companies NEVER send SMS threatening sudden disconnection within hours.",
            "Official bill payment notices always come via your official electricity consumer portal/bills.",
            "Never call personal phone numbers provided in urgent disconnection SMS.",
            "Pay bills exclusively through official bill portals or registered utility apps."
        ],
        "LOTTERY_JACKPOT_FRAUD": [
            "Legitimate organizations never ask for advance fees, taxes, or personal documents to claim prizes.",
            "If you did not enter a lottery ticket, you CANNOT win a lottery.",
            "Never send personal ID copies (Aadhaar/PAN/Passports) over WhatsApp or Telegram."
        ],
        "PART_TIME_JOB_SCAM": [
            "Legitimate companies never pay high daily returns for simple tasks like 'liking YouTube videos'.",
            "Scammers initially pay small sums, then demand large deposits (task-fraud trap).",
            "Do not join unofficial Telegram groups offering quick UPI money."
        ],
        "MALICIOUS_APP_FRAUD": [
            "Never download or install APK files or unknown apps from web links in SMS or email.",
            "Malicious APKs can steal SMS OTPs, passwords, and banking screens remotely.",
            "Install applications strictly from official app stores (Google Play Store / Apple App Store)."
        ],
        "DIGITAL_ARREST_SCAM": [
            "Law enforcement agencies, CBI, Police, or Courts NEVER conduct arrests or legal trials via WhatsApp video calls.",
            "Government officials will never demand money transfers or penalties to personal accounts to drop charges.",
            "Immediately report digital arrest intimidation to cybercrime.gov.in."
        ],
        "GENERAL_PHISHING": [
            "Inspect the domain name carefully: verify spelling, extension, and presence of HTTPS.",
            "Never enter passwords or OTPs on pages opened directly from unsolicited messages.",
            "Bookmark verified official websites and only navigate using your bookmarks."
        ],
        "SAFE_COMMUNICATION": [
            "This communication exhibits standard authentic attributes with no deceptive triggers detected.",
            "Remember to always verify the sender before taking any financial action."
        ]
    }

    def generate_explanation(self, url_result: dict, nlp_result: dict) -> dict:
        """
        Synthesize URL analysis and NLP findings into a human-readable explanation breakdown.
        """
        reasons = []
        is_threat = url_result.get("is_phishing", False) or nlp_result.get("is_scam", False)
        category = nlp_result.get("category", "GENERAL_PHISHING")

        # 1. Evaluate URL findings
        if url_result.get("is_phishing"):
            for ind in url_result.get("indicators", []):
                reasons.append({
                    "title": ind["type"].replace("_", " ").title(),
                    "severity": ind["severity"],
                    "explanation": ind["description"]
                })

        # 2. Evaluate NLP Tactics if threat is identified
        if is_threat:
            for tactic in nlp_result.get("tactics", []):
                reasons.append({
                    "title": tactic["label"],
                    "severity": "HIGH",
                    "explanation": tactic["detail"]
                })

        # 3. Choose category-specific recommendations
        if not is_threat:
            recommendations = self.RECOMMENDATIONS.get("SAFE_COMMUNICATION", [])
            summary_statement = "No suspicious coercion, spoofing, or credential harvesting patterns were detected. Communication appears benign."
        else:
            if category in ["SAFE_COMMUNICATION", "LEGITIMATE_SAFE"] and url_result.get("is_phishing"):
                category = "GENERAL_PHISHING"
            recommendations = self.RECOMMENDATIONS.get(category, self.RECOMMENDATIONS.get("GENERAL_PHISHING", []))
            summary_statement = f"This communication was flagged as {category.replace('_', ' ').title()} because it exhibits clear deceptive patterns and manipulation tactics designed to compromise your safety."

        return {
            "summary_statement": summary_statement,
            "reasons": reasons,
            "recommendations": recommendations
        }

    def highlight_text(self, text: str, flagged_phrases: list, extracted_urls: list) -> str:
        """
        Wrap suspicious phrases and URLs in highlighted HTML spans for visual inspection.
        """
        if not text:
            return ""

        annotated = text

        # Highlight URLs first
        for u in extracted_urls:
            pattern = re.escape(u)
            annotated = re.sub(
                pattern,
                f'<mark class="threat-url-highlight" title="Suspicious Link">{u}</mark>',
                annotated,
                flags=re.IGNORECASE
            )

        # Highlight NLP phrases
        for phrase in sorted(flagged_phrases, key=len, reverse=True):
            if len(phrase.strip()) < 3:
                continue
            pattern = re.escape(phrase)
            annotated = re.sub(
                pattern,
                f'<mark class="threat-phrase-highlight" title="Psychological Pressure / Red Flag">{phrase}</mark>',
                annotated,
                flags=re.IGNORECASE
            )

        return annotated
