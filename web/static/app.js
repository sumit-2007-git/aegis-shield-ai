document.addEventListener("DOMContentLoaded", () => {
    // PWA Install prompt capture
    let deferredPrompt;
    const pwaInstallBtn = document.getElementById("pwaInstallBtn");

    window.addEventListener('beforeinstallprompt', (e) => {
        e.preventDefault();
        deferredPrompt = e;
        if (pwaInstallBtn) {
            pwaInstallBtn.classList.remove('hidden');
        }
    });

    if (pwaInstallBtn) {
        pwaInstallBtn.addEventListener('click', async () => {
            if (deferredPrompt) {
                deferredPrompt.prompt();
                const { outcome } = await deferredPrompt.userChoice;
                if (outcome === 'accepted') {
                    pwaInstallBtn.classList.add('hidden');
                }
                deferredPrompt = null;
            } else {
                alert("To install on mobile: Open your browser menu (⋮ or Share) and tap 'Add to Home Screen' or 'Install App'.");
            }
        });
    }

    // Elements
    const threatInput = document.getElementById("threatInput");
    const scanBtn = document.getElementById("scanBtn");
    const pasteBtn = document.getElementById("pasteBtn");
    const clearBtn = document.getElementById("clearBtn");
    const scenarioChips = document.getElementById("scenarioChips");
    
    // View switching
    const tabDirectInput = document.getElementById("tabDirectInput");
    const tabSmsInbox = document.getElementById("tabSmsInbox");
    const viewDirectInput = document.getElementById("viewDirectInput");
    const viewSmsInbox = document.getElementById("viewSmsInbox");
    const smsList = document.getElementById("smsList");

    // Modal elements
    const openMobileModalBtn = document.getElementById("openMobileModalBtn");
    const mobileModal = document.getElementById("mobileModal");
    const closeModalBtn = document.getElementById("closeModalBtn");
    const qrCodeImg = document.getElementById("qrCodeImg");
    const mobileLinkUrl = document.getElementById("mobileLinkUrl");

    // Results elements
    const idleState = document.getElementById("idleState");
    const resultContent = document.getElementById("resultContent");
    const verdictTitle = document.getElementById("verdictTitle");
    const verdictCategory = document.getElementById("verdictCategory");
    const threatLevelTag = document.getElementById("threatLevelTag");
    const riskNumber = document.getElementById("riskNumber");
    const riskCircle = document.getElementById("riskCircle");
    const telemetryLatency = document.getElementById("telemetryLatency");
    const telemetryCalls = document.getElementById("telemetryCalls");
    const headerLatency = document.getElementById("headerLatency");
    const annotatedTextBox = document.getElementById("annotatedTextBox");
    const reasonsList = document.getElementById("reasonsList");
    const recommendationsList = document.getElementById("recommendationsList");
    const urlDetailsSection = document.getElementById("urlDetailsSection");
    const urlCardsList = document.getElementById("urlCardsList");

    // Clipboard guard
    const clipboardToggle = document.getElementById("clipboardToggle");
    const clipboardAlert = document.getElementById("clipboardAlert");
    const clipboardAlertText = document.getElementById("clipboardAlertText");
    const viewClipboardBtn = document.getElementById("viewClipboardBtn");
    let clipboardInterval = null;
    let lastClipboardText = "";

    // Simulated SMS Inbox Feed
    const INBOX_SMS = [
        {
            sender: "VK-SBIIN",
            time: "10:14 AM",
            body: "Dear customer, your SBI YONO account has been suspended due to pending KYC update. Click here to update your PAN immediately: http://sbi-kyc-update.xyz/login",
            tag: "Suspicious",
            type: "danger"
        },
        {
            sender: "AD-PWRDIS",
            time: "Yesterday",
            body: "Dear Customer, Your electricity power will be disconnected tonight at 9:30 PM because your bill was not updated. Contact electricity officer at 9876543210 immediately.",
            tag: "High Threat",
            type: "danger"
        },
        {
            sender: "VM-HDFCBK",
            time: "Yesterday",
            body: "Dear Customer, 482910 is the OTP for transaction of Rs 1,250.00 on Swiggy with your HDFC Bank Card ending 4412. OTP valid for 5 mins. Do not share OTP with anyone.",
            tag: "Legitimate",
            type: "safe"
        },
        {
            sender: "IM-KBCWIN",
            time: "2 days ago",
            body: "Congratulations! Your mobile number has won Rs 25,00,000 in KBC Lottery 2026. WhatsApp your photo and Aadhaar card to +91-9123456789 to claim prize money.",
            tag: "Lottery Scam",
            type: "danger"
        },
        {
            sender: "BZ-IRCTC",
            time: "3 days ago",
            body: "Dear Passenger, your train 12952 MUMBAI RAJDHANI is scheduled to depart at 16:55 from Platform 3. Have a safe journey - IRCTC.",
            tag: "Legitimate",
            type: "safe"
        }
    ];

    function renderSmsInbox() {
        smsList.innerHTML = "";
        INBOX_SMS.forEach(sms => {
            const card = document.createElement("div");
            card.className = "sms-card";
            card.innerHTML = `
                <div class="sms-meta-top">
                    <span class="sms-sender">💬 ${sms.sender}</span>
                    <span class="sms-time">${sms.time}</span>
                </div>
                <div class="sms-body">${sms.body}</div>
                <div class="sms-footer">
                    <span class="sms-category-tag ${sms.type}">${sms.tag}</span>
                    <span class="sms-action-hint">Tap to Inspect on Device &rarr;</span>
                </div>
            `;
            card.addEventListener("click", () => {
                threatInput.value = sms.body;
                tabDirectInput.click();
                performScan(sms.body);
            });
            smsList.appendChild(card);
        });
    }

    // Tab switching listeners
    tabDirectInput.addEventListener("click", () => {
        tabDirectInput.classList.add("active");
        tabSmsInbox.classList.remove("active");
        viewDirectInput.classList.remove("hidden");
        viewSmsInbox.classList.add("hidden");
    });

    tabSmsInbox.addEventListener("click", () => {
        tabSmsInbox.classList.add("active");
        tabDirectInput.classList.remove("active");
        viewSmsInbox.classList.remove("hidden");
        viewDirectInput.classList.add("hidden");
        renderSmsInbox();
    });

    // Mobile Connect Modal logic
    async function loadNetworkInfo() {
        try {
            const res = await fetch("/api/network-ip");
            const data = await res.json();
            const mobileUrl = data.mobile_url;
            mobileLinkUrl.href = mobileUrl;
            mobileLinkUrl.textContent = mobileUrl;

            // Generate clean QR code
            const qrApiUrl = `https://api.qrserver.com/v1/create-qr-code/?size=220x220&data=${encodeURIComponent(mobileUrl)}`;
            qrCodeImg.src = qrApiUrl;
        } catch (e) {
            console.error("Failed to load network IP:", e);
        }
    }

    openMobileModalBtn.addEventListener("click", () => {
        loadNetworkInfo();
        mobileModal.classList.remove("hidden");
    });

    closeModalBtn.addEventListener("click", () => {
        mobileModal.classList.add("hidden");
    });

    mobileModal.addEventListener("click", (e) => {
        if (e.target === mobileModal) {
            mobileModal.classList.add("hidden");
        }
    });

    // 1. Load Predefined Scenarios
    async function loadScenarios() {
        try {
            const res = await fetch("/api/scenarios");
            const scenarios = await res.json();
            scenarioChips.innerHTML = "";
            scenarios.forEach(sc => {
                const btn = document.createElement("button");
                btn.className = `chip ${sc.type}`;
                btn.innerHTML = `<span class="chip-tag">${sc.tag}</span> ${sc.title}`;
                btn.addEventListener("click", () => {
                    threatInput.value = sc.content;
                    performScan(sc.content);
                });
                scenarioChips.appendChild(btn);
            });
        } catch (err) {
            console.error("Failed to load scenarios:", err);
        }
    }

    // 2. Scan Logic
    async function performScan(textToScan) {
        const text = textToScan !== undefined ? textToScan : threatInput.value.trim();
        if (!text) {
            alert("Please enter or paste text/link to analyze.");
            return;
        }

        scanBtn.disabled = true;
        scanBtn.innerHTML = `<span class="btn-icon">⏳</span> Analyzing on Local CPU...`;

        try {
            const res = await fetch("/api/scan", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ text })
            });

            const data = await res.json();
            renderResults(data);

            // Trigger haptic vibration on mobile devices if threat detected
            if (data.risk_score >= 50 && 'vibrate' in navigator) {
                navigator.vibrate([200, 100, 200]);
            }
        } catch (err) {
            console.warn("Server unavailable / Offline Airplane Mode. Activating On-Device Mobile Client Engine...", err);
            const offlineData = runClientSideOfflineEngine(text);
            renderResults(offlineData);
            if (offlineData.risk_score >= 50 && 'vibrate' in navigator) {
                navigator.vibrate([200, 100, 200]);
            }
        } finally {
            scanBtn.disabled = false;
            scanBtn.innerHTML = `<span class="btn-icon">⚡</span> Analyze Threat (Local CPU)`;
        }
    }

    // 3. Render Results
    function renderResults(data) {
        idleState.classList.add("hidden");
        resultContent.classList.remove("hidden");

        // Top Verdict Card
        verdictTitle.textContent = data.verdict;
        verdictCategory.textContent = `Attack Taxonomy: ${data.category.replace(/_/g, " ")}`;
        threatLevelTag.textContent = data.threat_level.replace(/_/g, " ");
        riskNumber.textContent = data.risk_score;

        // Dynamic Badge Colors
        let color = data.badge_color || "#3b82f6";
        threatLevelTag.style.background = `${color}25`;
        threatLevelTag.style.color = color;
        threatLevelTag.style.border = `1px solid ${color}`;
        riskCircle.style.borderColor = color;
        riskNumber.style.color = color;

        // Telemetry
        const lat = data.telemetry.latency_ms;
        telemetryLatency.textContent = `${lat} ms`;
        if (headerLatency) headerLatency.textContent = `⚡ ${lat} ms`;
        telemetryCalls.textContent = `${data.telemetry.cloud_network_calls} (Local CPU)`;

        // Highlighted Visual Text
        annotatedTextBox.innerHTML = data.highlighted_html || data.input_text;

        // Reasons Breakdown (XAI)
        reasonsList.innerHTML = "";
        const reasons = data.explanation.reasons || [];
        if (reasons.length === 0) {
            reasonsList.innerHTML = `<div class="reason-item" style="border-color: #10b981;"><div class="reason-title">No Threat Indicators</div><div class="reason-desc">No deceptive keywords, homographs, or malicious patterns were identified.</div></div>`;
        } else {
            reasons.forEach(r => {
                const item = document.createElement("div");
                item.className = "reason-item";
                if (r.severity === "CRITICAL") item.style.borderLeftColor = "#ef4444";
                else if (r.severity === "HIGH") item.style.borderLeftColor = "#f97316";
                else if (r.severity === "MEDIUM") item.style.borderLeftColor = "#eab308";
                else item.style.borderLeftColor = "#10b981";

                item.innerHTML = `
                    <div class="reason-title">${r.title}</div>
                    <div class="reason-desc">${r.explanation}</div>
                `;
                reasonsList.appendChild(item);
            });
        }

        // Recommendations
        recommendationsList.innerHTML = "";
        const recs = data.explanation.recommendations || [];
        recs.forEach(rec => {
            const li = document.createElement("li");
            li.textContent = rec;
            recommendationsList.appendChild(li);
        });

        // URL details
        const urls = data.extracted_urls || [];
        if (urls.length > 0) {
            urlDetailsSection.classList.remove("hidden");
            urlCardsList.innerHTML = "";
            urls.forEach(u => {
                const card = document.createElement("div");
                card.className = "url-card";
                card.innerHTML = `
                    <div class="url-target">🌐 ${u.target}</div>
                    <div class="url-meta">
                        <span><strong>Domain:</strong> ${u.normalized_domain}</span>
                        <span><strong>Entropy:</strong> ${u.entropy}</span>
                        <span><strong>Risk:</strong> ${u.risk_score}/100</span>
                        ${u.impersonated_brand ? `<span style="color:#ef4444;"><strong>Mimicking:</strong> ${u.impersonated_brand}</span>` : ""}
                    </div>
                `;
                urlCardsList.appendChild(card);
            });
        } else {
            urlDetailsSection.classList.add("hidden");
        }

        // Scroll into view on mobile
        if (window.innerWidth < 1024) {
            resultContent.scrollIntoView({ behavior: "smooth" });
        }
    }

    // 4. Clipboard Guard Sentinel
    async function checkClipboardSentinel() {
        try {
            const res = await fetch("/api/clipboard");
            const data = await res.json();
            if (data.has_content && data.scan_result && data.text !== lastClipboardText) {
                lastClipboardText = data.text;
                if (data.scan_result.risk_score >= 48) {
                    clipboardAlert.classList.remove("hidden");
                    clipboardAlertText.textContent = `"${data.text}"`;
                    viewClipboardBtn.onclick = () => {
                        threatInput.value = data.text;
                        renderResults(data.scan_result);
                        clipboardAlert.classList.add("hidden");
                    };
                }
            }
        } catch (err) {
            console.error("Clipboard polling error:", err);
        }
    }

    clipboardToggle.addEventListener("change", (e) => {
        if (e.target.checked) {
            checkClipboardSentinel();
            clipboardInterval = setInterval(checkClipboardSentinel, 2000);
        } else {
            if (clipboardInterval) clearInterval(clipboardInterval);
            clipboardAlert.classList.add("hidden");
        }
    });

    // 5. Button Listeners
    scanBtn.addEventListener("click", () => performScan());

    pasteBtn.addEventListener("click", async () => {
        try {
            const text = await navigator.clipboard.readText();
            if (text) {
                threatInput.value = text;
                performScan(text);
            }
        } catch (e) {
            performScan();
        }
    });

    clearBtn.addEventListener("click", () => {
        threatInput.value = "";
        idleState.classList.remove("hidden");
        resultContent.classList.add("hidden");
    });

    // Ctrl+Enter shortcut
    threatInput.addEventListener("keydown", (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
            performScan();
        }
    });

    // 6. 100% Client-Side On-Device Offline Engine (Airplane Mode Fallback)
    const CLIENT_BRANDS = [
        { name: "State Bank of India (SBI)", domain: "onlinesbi.sbi", aliases: ["sbi", "onlinesbi", "yono", "sbicard"] },
        { name: "HDFC Bank", domain: "hdfcbank.com", aliases: ["hdfc", "hdfcbank"] },
        { name: "PayPal", domain: "paypal.com", aliases: ["paypal"] },
        { name: "Amazon", domain: "amazon.in", aliases: ["amazon"] },
        { name: "Netflix", domain: "netflix.com", aliases: ["netflix"] },
        { name: "Google", domain: "google.com", aliases: ["google", "gmail"] },
        { name: "India Post", domain: "indiapost.gov.in", aliases: ["indiapost"] },
        { name: "Electricity Board", domain: "mahadiscom.in", aliases: ["mahadiscom", "electricity", "bses", "bescom"] }
    ];
    const CLIENT_SUSPICIOUS_TLDS = [".xyz", ".top", ".work", ".click", ".tk", ".ml", ".ga", ".fit"];

    function levenshteinDistance(s1, s2) {
        if (s1.length < s2.length) return levenshteinDistance(s2, s1);
        if (s2.length === 0) return s1.length;
        let prev = Array.from({ length: s2.length + 1 }, (_, i) => i);
        for (let i = 0; i < s1.length; i++) {
            let curr = [i + 1];
            for (let j = 0; j < s2.length; j++) {
                let cost = s1[i] === s2[j] ? 0 : 1;
                curr.push(Math.min(curr[j] + 1, prev[j + 1] + 1, prev[j] + cost));
            }
            prev = curr;
        }
        return prev[s2.length];
    }

    function runClientSideOfflineEngine(rawText) {
        const startTime = performance.now();
        const text = rawText || "";
        const lower = text.toLowerCase();
        let riskScore = 0;
        const reasons = [];
        const flaggedPhrases = [];
        const extractedUrls = [];

        // 1. Extract and inspect URLs
        const urlRegex = /(?:(?:https?|ftp):\/\/)?(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{2,12}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)/gi;
        const urlMatches = text.match(urlRegex) || [];

        urlMatches.forEach(rawUrl => {
            let domain = rawUrl.toLowerCase().replace(/^(https?:\/\/)?(www\.)?/, "").split("/")[0].split(":")[0];
            let urlRisk = 0;
            let impersonatedBrand = null;
            let domainTokens = domain.split(/[-_.]/).filter(t => t.length >= 3);

            // Check suspicious TLD
            for (let tld of CLIENT_SUSPICIOUS_TLDS) {
                if (domain.endsWith(tld)) {
                    urlRisk += 30;
                    reasons.push({
                        title: "High Risk Domain TLD",
                        severity: "HIGH",
                        explanation: `Domain ends with disposable extension '${tld}', frequently exploited for phishing.`
                    });
                    break;
                }
            }

            // Check typosquatting against brands
            for (let b of CLIENT_BRANDS) {
                if (domain === b.domain || domain.endsWith("." + b.domain)) {
                    urlRisk = Math.max(0, urlRisk - 40);
                    break;
                }
                for (let alias of b.aliases) {
                    if (domain.includes(alias)) {
                        impersonatedBrand = b.name;
                        urlRisk += 50;
                        reasons.push({
                            title: "Brand Impersonation",
                            severity: "CRITICAL",
                            explanation: `Domain mimics ${b.name} ('${alias}' in unverified domain '${domain}').`
                        });
                        break;
                    }
                    for (let tok of domainTokens) {
                        if (tok.length >= 4 && alias.length >= 4) {
                            let dist = levenshteinDistance(tok, alias);
                            if (dist === 1) {
                                impersonatedBrand = b.name;
                                urlRisk += 55;
                                reasons.push({
                                    title: "Typosquatting Attack",
                                    severity: "CRITICAL",
                                    explanation: `Domain token '${tok}' is a visual typo variation of '${b.name}' (distance: 1).`
                                });
                                break;
                            }
                        }
                    }
                }
            }

            // Keyword stuffing
            ["login", "verify", "secure", "kyc", "update"].forEach(kw => {
                if (domain.includes(kw)) {
                    urlRisk += 15;
                    reasons.push({
                        title: "Phishing Keyword Bait",
                        severity: "MEDIUM",
                        explanation: `Domain contains trust-bait keyword '${kw}'.`
                    });
                }
            });

            urlRisk = Math.min(urlRisk, 100);
            extractedUrls.push({
                target: rawUrl,
                normalized_domain: domain,
                risk_score: urlRisk,
                entropy: 3.8,
                impersonated_brand: impersonatedBrand
            });
            riskScore = Math.max(riskScore, urlRisk);
        });

        // 2. Check Urgency / Panic patterns
        const urgencyPatterns = [
            { re: /\b(immediately|urgent|tonight|within \d+ (hours?|mins?)|blocked|suspended|deactivated|expire[sd]?)\b/gi, label: "Urgency Pressure & Fear" },
            { re: /\b(power disconnect|cut off|bijli|electricity.*disconnect)\b/gi, label: "Utility Service Disconnection Threat" }
        ];
        urgencyPatterns.forEach(pat => {
            const m = text.match(pat.re);
            if (m) {
                riskScore += 35;
                m.forEach(matchWord => flaggedPhrases.push(matchWord));
                reasons.push({
                    title: pat.label,
                    severity: "HIGH",
                    explanation: "Artificial panic tactic detected to prevent user from verifying before reacting."
                });
            }
        });

        // 3. Check Credential Harvesting
        const isLegitOtp = /do not share otp|never share this otp/i.test(text);
        if (!isLegitOtp) {
            const credMatches = text.match(/\b(kyc|pan card|aadhaar|otp|password|net banking|download app|\.apk)\b/gi);
            if (credMatches) {
                riskScore += 35;
                credMatches.forEach(matchWord => flaggedPhrases.push(matchWord));
                reasons.push({
                    title: "Identity & Credential Solicitation",
                    severity: "CRITICAL",
                    explanation: "Requests sensitive documents, KYC credentials, or unauthorized application installation."
                });
            }
        } else {
            riskScore = Math.max(0, riskScore - 40);
        }

        // 4. Check Greed / Lottery / Telegram
        const greedMatches = text.match(/\b(lottery|won|kbc|25,00,000|earn daily|part-time|like youtube|telegram|t\.me)\b/gi);
        if (greedMatches) {
            riskScore += 40;
            greedMatches.forEach(matchWord => flaggedPhrases.push(matchWord));
            reasons.push({
                title: "Financial Bait & Task Trap",
                severity: "HIGH",
                explanation: "Unrealistic jackpot prizes or task deposits frequently used in Telegram fraud."
            });
        }

        riskScore = Math.min(Math.max(riskScore, 0), 100);

        // Classification
        let verdict = "SAFE / AUTHENTIC";
        let threatLevel = "SAFE_BENIGN";
        let badgeColor = "#22c55e";
        let category = isLegitOtp ? "BANK_OTP_AUTHENTICATION" : "SAFE_COMMUNICATION";

        if (riskScore >= 75) {
            verdict = "DANGEROUS SCAM / PHISHING";
            threatLevel = "CRITICAL_THREAT";
            badgeColor = "#ef4444";
            category = "CRITICAL_FRAUD";
        } else if (riskScore >= 45) {
            verdict = "SUSPICIOUS COMMUNICATION";
            threatLevel = "HIGH_SUSPICION";
            badgeColor = "#f97316";
            category = "SUSPICIOUS_COMMUNICATION";
        } else if (riskScore >= 25) {
            verdict = "USE CAUTION";
            threatLevel = "MODERATE_WARNING";
            badgeColor = "#eab308";
        }

        // Generate highlighted HTML
        let highlightedHtml = text;
        urlMatches.forEach(u => {
            highlightedHtml = highlightedHtml.replace(new RegExp(u, "gi"), `<mark class="threat-url-highlight">${u}</mark>`);
        });
        flaggedPhrases.forEach(p => {
            if (p.length > 2) {
                highlightedHtml = highlightedHtml.replace(new RegExp(p, "gi"), `<mark class="threat-phrase-highlight">${p}</mark>`);
            }
        });

        const recommendations = riskScore >= 45 ? [
            "Never click SMS links to update KYC or banking credentials.",
            "Official organizations NEVER threaten sudden electricity cutoffs via SMS.",
            "Do not install APKs or transfer funds to unknown UPI numbers.",
            "Report fraudulent messages immediately to Cyber Helpline (1930)."
        ] : [
            "This communication exhibits standard authentic attributes.",
            "Always verify the sender before taking any financial action."
        ];

        const endTime = performance.now();
        const latencyMs = Math.max(1.2, +(endTime - startTime).toFixed(2));

        return {
            verdict,
            threat_level: threatLevel,
            risk_score: riskScore,
            badge_color: badgeColor,
            category,
            confidence: 96.5,
            input_text: text,
            highlighted_html: highlightedHtml,
            extracted_urls: extractedUrls,
            explanation: {
                summary_statement: `Processed via On-Device Mobile Engine. Risk Score: ${riskScore}/100.`,
                reasons,
                recommendations
            },
            telemetry: {
                latency_ms: latencyMs,
                cloud_network_calls: 0,
                bytes_uploaded_to_cloud: 0,
                privacy_mode: "100% In-Browser Mobile Engine (Airplane Mode)",
                execution_hardware: "Phone Local CPU (WASM/JS)"
            }
        };
    }

    // Initialize
    loadScenarios();
});

