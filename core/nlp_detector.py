import re
import json
import os
import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.calibration import CalibratedClassifierCV

class ScamNLPDetector:
    """
    On-device NLP threat classifier for scam SMS, phishing emails, and social engineering messages.
    Features:
    - Zero cloud dependency (100% on-device).
    - Sub-10ms inference.
    - Intent & Scam Category Classifier.
    - Social Engineering Rule Multipliers (Urgency, Coercion, Credential Harvesting).
    - Feature Attribution for Explainable AI (XAI).
    """

    def __init__(self, data_dir=None, model_dir=None):
        base_dir = os.path.dirname(os.path.dirname(__file__))
        self.data_dir = data_dir or os.path.join(base_dir, "data")
        self.model_dir = model_dir or os.path.join(base_dir, "models")
        self.model_path = os.path.join(self.model_dir, "scam_classifier.joblib")
        
        self.model = None
        self.category_model = None

        # Threat patterns for social engineering analysis
        self.patterns = {
            "URGENCY_PRESSURE": [
                r"\b(immediately|urgent|urgently|within \d+ (hours?|mins?|days?)|tonight|blocked|suspended|deactivated|expire[sd]?|action required|final warning|last chance)\b",
                r"\b(cut off|disconnect(?:ed|ion)?|power disconnect)\b"
            ],
            "FINANCIAL_COERCION_OR_GREED": [
                r"\b(lottery|won|winner|jackpot|prize|kbc|reward|cashback|refund|earn daily|part-time|work from home|free gift|credited rs|deposit)\b",
                r"\b(penalty|fine of rs|arrest|police case|money laundering|cbi officer|digital arrest)\b"
            ],
            "CREDENTIAL_OR_KYC_HARVESTING": [
                r"\b(kyc|pan card|aadhaar|biometric|net banking|password|pin|cvv|otp|share otp|verify bank|update details)\b",
                r"\b(install apk|download app|\.apk|update yono)\b"
            ],
            "SUSPICIOUS_COMMUNICATION_CHANNEL": [
                r"\b(telegram|t\.me/|whatsapp|wa\.me/|contact manager|call electricity officer|send photo)\b"
            ],
            "LEGITIMATE_AUTHENTICATION_INDICATORS": [
                r"\b(do not share otp|valid for \d+ mins|never share this otp|for official use|irctc|pnr|scheduled to depart)\b"
            ]
        }

        self._initialize_models()

    def _initialize_models(self):
        """Train or load local model."""
        if os.path.exists(self.model_path):
            try:
                saved_data = joblib.load(self.model_path)
                self.model = saved_data["model"]
                self.category_model = saved_data.get("category_model")
                return
            except Exception:
                pass

        # Train on-device if not saved yet
        self._train_local_model()

    def _train_local_model(self):
        """Train lightweight pipeline on local dataset."""
        dataset_path = os.path.join(self.data_dir, "scam_dataset.json")
        if not os.path.exists(dataset_path):
            return

        with open(dataset_path, "r", encoding="utf-8") as f:
            dataset = json.load(f)

        texts = [item["text"] for item in dataset]
        labels = [1 if item["label"] == "scam" else 0 for item in dataset]
        categories = [item.get("category", "UNKNOWN") for item in dataset]

        # Group categories for clean classification
        category_map = {
            "KYC_BANKING_FRAUD": "BANKING_KYC_FRAUD",
            "UTILITY_DISCONNECTION_SCAM": "UTILITY_DISCONNECTION_SCAM",
            "LOTTERY_JACKPOT_FRAUD": "LOTTERY_OR_JOB_SCAM",
            "PART_TIME_JOB_SCAM": "LOTTERY_OR_JOB_SCAM",
            "TAX_REFUND_FRAUD": "GOV_TAX_OR_DELIVERY_FRAUD",
            "COURIER_DELIVERY_SCAM": "GOV_TAX_OR_DELIVERY_FRAUD",
            "MALICIOUS_APP_FRAUD": "MALICIOUS_APK_FRAUD",
            "SIM_SWAP_FRAUD": "BANKING_KYC_FRAUD",
            "TRANSACTION_PANIC_SCAM": "BANKING_KYC_FRAUD",
            "ACCOUNT_TAKEOVER_PHISHING": "BANKING_KYC_FRAUD",
            "IMPERSONATION_FAMILY_EMERGENCY": "IMPERSONATION_FRAUD",
            "SUBSCRIPTION_PHISHING": "SUBSCRIPTION_FRAUD",
            "LOAN_ADVANCE_FEE_SCAM": "LOTTERY_OR_JOB_SCAM",
            "DIGITAL_ARREST_SCAM": "DIGITAL_ARREST_SCAM",
            "BANK_OTP_AUTHENTICATION": "LEGITIMATE_SAFE",
            "BANK_TRANSACTION_ALERT": "LEGITIMATE_SAFE",
            "PERSONAL_COMMUNICATION": "LEGITIMATE_SAFE",
            "ECOMMERCE_SHIPPING": "LEGITIMATE_SAFE",
            "SECURITY_NOTIFICATION": "LEGITIMATE_SAFE",
            "TRAVEL_NOTIFICATION": "LEGITIMATE_SAFE",
            "APPOINTMENT_REMINDER": "LEGITIMATE_SAFE",
            "UTILITY_BILL_STATEMENT": "LEGITIMATE_SAFE",
            "WORKPLACE_COMMUNICATION": "LEGITIMATE_SAFE",
            "DEVELOPER_NOTIFICATION": "LEGITIMATE_SAFE"
        }
        mapped_categories = [category_map.get(c, "GENERAL_SUSPICIOUS") for c in categories]

        # Binary Scam vs Benign Model
        vec = TfidfVectorizer(ngram_range=(1, 2), max_features=1200, sublinear_tf=True)
        clf = LogisticRegression(C=2.0, class_weight="balanced", max_iter=200)
        self.model = Pipeline([("vectorizer", vec), ("classifier", clf)])
        self.model.fit(texts, labels)

        # Multi-class category classifier
        cat_vec = TfidfVectorizer(ngram_range=(1, 2), max_features=1200, sublinear_tf=True)
        cat_clf = LogisticRegression(C=1.5, max_iter=200)
        self.category_model = Pipeline([("vectorizer", cat_vec), ("classifier", cat_clf)])
        self.category_model.fit(texts, mapped_categories)

        os.makedirs(self.model_dir, exist_ok=True)
        joblib.dump({
            "model": self.model,
            "category_model": self.category_model
        }, self.model_path)

    def extract_tactics(self, text: str) -> list:
        """Extract explicit psychological manipulation tactics found in message."""
        tactics = []
        lower = text.lower()

        # Check urgency
        for pat in self.patterns["URGENCY_PRESSURE"]:
            matches = re.findall(pat, lower)
            if matches:
                tactics.append({
                    "tactic": "URGENCY_INDUCEMENT",
                    "label": "Artificial Urgency & Fear",
                    "detail": "Forces victim to panic and act impulsively without verification (e.g., countdowns, immediate disconnect)."
                })
                break

        # Check financial temptation / coercion
        for pat in self.patterns["FINANCIAL_COERCION_OR_GREED"]:
            matches = re.findall(pat, lower)
            if matches:
                tactics.append({
                    "tactic": "FINANCIAL_BAIT_OR_COERCION",
                    "label": "Greed Bait or Financial Coercion",
                    "detail": "Uses promises of unexpected money/jobs or threats of fines/police arrest."
                })
                break

        # Check credential harvesting (exclude authentic "do not share OTP" warnings)
        cred_text = re.sub(r"\b(do not|never)\s+share\s+(?:this\s+)?otp\b", "", lower, flags=re.IGNORECASE)
        for pat in self.patterns["CREDENTIAL_OR_KYC_HARVESTING"]:
            matches = re.findall(pat, cred_text)
            if matches:
                tactics.append({
                    "tactic": "CREDENTIAL_HARVESTING",
                    "label": "Identity & Credential Solicitation",
                    "detail": "Directly requests sensitive identity documents (Aadhaar, PAN), KYC re-validation, or APK app installation."
                })
                break

        # Check redirect channels
        for pat in self.patterns["SUSPICIOUS_COMMUNICATION_CHANNEL"]:
            matches = re.findall(pat, lower)
            if matches:
                tactics.append({
                    "tactic": "UNOFFICIAL_CHANNEL_REDIRECT",
                    "label": "Unverified Contact Redirection",
                    "detail": "Diverts communication to unofficial Telegram channels or personal phone numbers."
                })
                break

        return tactics

    def analyze(self, text: str) -> dict:
        """
        Analyze communication text.
        Returns: scam probability, risk score, detected category, tactics, and flagged tokens.
        """
        if not text or not text.strip():
            return {
                "is_scam": False,
                "confidence": 0.0,
                "risk_score": 0,
                "category": "EMPTY_INPUT",
                "tactics": [],
                "flagged_phrases": []
            }

        # 1. Run local ML model
        ml_prob = 0.5
        predicted_category = "GENERAL_SUSPICIOUS"
        
        if self.model:
            prob_dist = self.model.predict_proba([text])[0]
            ml_prob = float(prob_dist[1])  # probability of class 1 (scam)
            
        if self.category_model:
            predicted_category = self.category_model.predict([text])[0]

        # 2. Extract psychological tactics
        tactics = self.extract_tactics(text)

        # 3. Rule-based heuristic modulation
        heuristic_score = len(tactics) * 22
        
        # Check if legitimate safety indicator is present (e.g. "Do not share OTP")
        is_legit_otp = bool(re.search(r"do not share otp|never share this otp", text, re.IGNORECASE))
        if is_legit_otp and len(tactics) <= 1:
            heuristic_score = max(0, heuristic_score - 40)
            ml_prob = min(ml_prob, 0.15)
            predicted_category = "BANK_OTP_AUTHENTICATION"

        # Blended risk score (0-100)
        blended_score = int((ml_prob * 60) + (heuristic_score * 0.4))
        blended_score = min(max(blended_score, 0), 100)

        is_scam = blended_score >= 48

        # 4. Refine category for scam intent
        final_category = predicted_category
        lower_text = text.lower()
        if is_scam:
            if any(k in lower_text for k in ["kyc", "pan", "aadhaar", "yono", "bank", "account suspended", "deactivated"]):
                final_category = "KYC_BANKING_FRAUD"
            elif any(k in lower_text for k in ["electricity", "power", "bill", "disconnect", "bijli"]):
                final_category = "UTILITY_DISCONNECTION_SCAM"
            elif any(k in lower_text for k in ["lottery", "kbc", "winner", "jackpot", "25,00,000"]):
                final_category = "LOTTERY_JACKPOT_FRAUD"
            elif any(k in lower_text for k in ["part-time", "job", "earn daily", "like youtube", "telegram"]):
                final_category = "PART_TIME_JOB_SCAM"
            elif any(k in lower_text for k in ["cbi", "police", "arrest", "money laundering"]):
                final_category = "DIGITAL_ARREST_SCAM"
            elif any(k in lower_text for k in ["apk", "download app", "install"]):
                final_category = "MALICIOUS_APP_FRAUD"
            elif any(k in lower_text for k in ["delivery", "package", "parcel", "india post", "address"]):
                final_category = "COURIER_DELIVERY_SCAM"
            elif final_category in ["LEGITIMATE_SAFE", "GENERAL_SUSPICIOUS"]:
                final_category = "GENERAL_PHISHING"
        else:
            final_category = "BANK_OTP_AUTHENTICATION" if is_legit_otp else "SAFE_COMMUNICATION"

        # 5. Highlight flagged keywords for explainability
        flagged_phrases = []
        for category_keys in ["URGENCY_PRESSURE", "FINANCIAL_COERCION_OR_GREED", "CREDENTIAL_OR_KYC_HARVESTING"]:
            for pat in self.patterns[category_keys]:
                for match in re.finditer(pat, text, re.IGNORECASE):
                    flagged_phrases.append(match.group(0))

        flagged_phrases = list(dict.fromkeys(flagged_phrases))

        return {
            "is_scam": is_scam,
            "confidence": round(ml_prob * 100, 1),
            "risk_score": blended_score,
            "category": final_category,
            "tactics": tactics,
            "flagged_phrases": flagged_phrases
        }
