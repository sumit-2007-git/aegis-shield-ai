import re
import math
import json
import os
from urllib.parse import urlparse

class URLThreatDetector:
    """
    100% On-Device URL & Domain Phishing Threat Detector.
    Detects typosquatting, homograph/punycode attacks, suspicious TLDs,
    entropy anomalies, brand impersonation, and phishing lexical patterns.
    """
    
    def __init__(self, data_dir=None):
        if data_dir is None:
            data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
        
        brand_path = os.path.join(data_dir, "brand_database.json")
        if os.path.exists(brand_path):
            with open(brand_path, "r", encoding="utf-8") as f:
                config = json.load(f)
                self.brands = config.get("brands", [])
                self.suspicious_tlds = set(config.get("suspicious_tlds", []))
                self.phishing_keywords = set(config.get("phishing_keywords", []))
        else:
            self.brands = []
            self.suspicious_tlds = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".click"}
            self.phishing_keywords = {"verify", "secure", "update", "kyc", "login", "suspended", "banking"}

        # Shorteners
        self.url_shorteners = {
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", 
            "buff.ly", "adf.ly", "cutt.ly", "rb.gy", "shorturl.at"
        }

        # Cyrillic/Greek lookalikes often used in homograph attacks
        self.homograph_map = {
            'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y',
            'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w'
        }

    def _shannon_entropy(self, s: str) -> float:
        """Calculate Shannon entropy to detect algorithmically generated domains."""
        if not s:
            return 0.0
        prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(s)]
        return -sum([p * math.log2(p) for p in prob])

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Compute edit distance between two strings."""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]

    def _extract_domain(self, url: str) -> str:
        """Clean and extract hostname from URL."""
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        try:
            parsed = urlparse(url)
            netloc = parsed.netloc.lower()
            if ":" in netloc:
                netloc = netloc.split(":")[0]
            return netloc
        except Exception:
            return url.lower()

    def analyze(self, raw_url: str) -> dict:
        """
        Analyze a URL for phishing and brand impersonation.
        Returns risk score (0-100), threat level, and detailed explanation points.
        """
        indicators = []
        risk_score = 0
        is_phishing = False
        domain = self._extract_domain(raw_url)
        clean_url = raw_url.lower().strip()

        # 1. IP Address as host check
        ip_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
        if re.match(ip_pattern, domain):
            risk_score += 45
            indicators.append({
                "type": "IP_BASED_URL",
                "severity": "HIGH",
                "description": f"URL uses raw IP address ({domain}) instead of a trusted domain name. Legitimate services virtually never use raw IPs."
            })

        # 2. Homograph / Punycode Attack check
        has_homograph = False
        replaced_domain = []
        for char in domain:
            if char in self.homograph_map:
                has_homograph = True
                replaced_domain.append(self.homograph_map[char])
            else:
                replaced_domain.append(char)
        
        if domain.startswith("xn--") or has_homograph:
            risk_score += 55
            indicators.append({
                "type": "HOMOGRAPH_PUNYCODE_ATTACK",
                "severity": "CRITICAL",
                "description": "Domain contains deceptive lookalike Unicode/Cyrillic characters (IDN Homograph attack) designed to visually mimic authentic brand domains."
            })

        # 3. Suspicious Top-Level Domain (TLD)
        for tld in self.suspicious_tlds:
            if domain.endswith(tld):
                risk_score += 25
                indicators.append({
                    "type": "HIGH_RISK_TLD",
                    "severity": "MEDIUM",
                    "description": f"Domain utilizes high-abuse extension '{tld}', frequently exploited for disposable phishing campaigns."
                })
                break

        # 4. URL Shortener Warning
        for shortener in self.url_shorteners:
            if shortener in domain:
                risk_score += 20
                indicators.append({
                    "type": "URL_SHORTENER_OBFUSCATION",
                    "severity": "MEDIUM",
                    "description": f"Uses URL shortener service ({shortener}) which hides the real destination and avoids preliminary link inspection."
                })
                break

        # 5. Phishing Keywords in URL Path/Subdomain
        found_keywords = [kw for kw in self.phishing_keywords if kw in clean_url]
        if found_keywords:
            weight = min(len(found_keywords) * 12, 35)
            risk_score += weight
            indicators.append({
                "type": "DECEPTIVE_SECURITY_KEYWORDS",
                "severity": "HIGH",
                "description": f"URL contains security-bait keywords: {', '.join(found_keywords[:4])}. Phishing sites use these to create false trust."
            })

        # 6. Typosquatting & Brand Impersonation Analysis
        impersonated_brand = None
        main_part = domain.split(".")[0] if "." in domain else domain

        for brand in self.brands:
            official_domain = brand["domain"].lower()
            official_host = official_domain.split(".")[0]
            
            # If domain is literally the official domain, this is likely safe
            if domain == official_domain or domain.endswith("." + official_domain):
                # Benign authentic brand domain
                risk_score = max(0, risk_score - 50)
                indicators.append({
                    "type": "OFFICIAL_VERIFIED_DOMAIN",
                    "severity": "SAFE",
                    "description": f"Matches legitimate official domain of {brand['name']} ({official_domain})."
                })
                impersonated_brand = None
                break

            # Check if domain tries to copy brand name (e.g., sbi-online, hdfc-security)
            for alias in brand["aliases"]:
                # Check substring match with unauthorized domain
                if alias in domain and domain != official_domain and not domain.endswith("." + official_domain):
                    impersonated_brand = brand["name"]
                    risk_score += 50
                    indicators.append({
                        "type": "BRAND_IMPERSONATION",
                        "severity": "CRITICAL",
                        "description": f"Domain mimics {brand['name']} ('{alias}' keyword in unverified domain '{domain}'). Official domain is '{official_domain}'."
                    })
                    break

                # Check Levenshtein distance for typosquatting (whole part and individual hyphenated tokens)
                domain_tokens = [tok for tok in re.split(r'[-_.]', domain) if len(tok) >= 3]
                found_typo = False
                for candidate in [main_part] + domain_tokens:
                    if len(alias) >= 4 and len(candidate) >= 4:
                        dist = self._levenshtein_distance(candidate, alias)
                        if 1 <= dist <= 2 and abs(len(candidate) - len(alias)) <= 1:
                            impersonated_brand = brand["name"]
                            risk_score += 55
                            indicators.append({
                                "type": "TYPOSQUATTING_ATTACK",
                                "severity": "CRITICAL",
                                "description": f"Domain token '{candidate}' is a visual typo variation of '{brand['name']}' (Levenshtein distance: {dist} against '{alias}'). Likely spoofing {official_domain}."
                            })
                            found_typo = True
                            break
                if found_typo:
                    break
            
            if impersonated_brand:
                break

        # 7. Shannon Entropy Anomaly
        entropy = self._shannon_entropy(domain)
        if entropy > 4.2:
            risk_score += 20
            indicators.append({
                "type": "HIGH_ENTROPY_DOMAIN",
                "severity": "MEDIUM",
                "description": f"High character randomness detected (Shannon Entropy: {entropy:.2f}), typical of algorithmically generated domain fluxing."
            })

        # 8. Excessive Subdomains & Obfuscation
        subdomain_count = domain.count(".")
        if subdomain_count >= 3:
            risk_score += 15
            indicators.append({
                "type": "EXCESSIVE_SUBDOMAINS",
                "severity": "LOW",
                "description": f"Domain contains {subdomain_count} dot segments, often used to camouflage true top-level origin."
            })

        if "@" in clean_url:
            risk_score += 40
            indicators.append({
                "type": "USERINFO_DELIMITER_TRICK",
                "severity": "HIGH",
                "description": "URL contains '@' character which directs browsers to ignore everything preceding it, a classic credential disguise attack."
            })

        # Final score bounding
        risk_score = min(max(risk_score, 0), 100)
        
        # Threat classification
        if risk_score >= 70:
            level = "CRITICAL_THREAT"
            is_phishing = True
        elif risk_score >= 45:
            level = "HIGH_SUSPICION"
            is_phishing = True
        elif risk_score >= 20:
            level = "MODERATE_WARNING"
        else:
            level = "SAFE_BENIGN"

        return {
            "target": raw_url,
            "normalized_domain": domain,
            "is_phishing": is_phishing,
            "risk_score": risk_score,
            "threat_level": level,
            "indicators": indicators,
            "impersonated_brand": impersonated_brand,
            "entropy": round(entropy, 2)
        }
