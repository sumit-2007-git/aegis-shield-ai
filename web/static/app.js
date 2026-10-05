document.addEventListener("DOMContentLoaded", () => {
    // Service Worker Registration for PWA Mobile App
    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.register('/sw.js').catch(err => {
            console.log("Service Worker registration skipped:", err);
        });
    }

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
            console.error("Scan error:", err);
            alert("Analysis failed. Please verify that the local server is running.");
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

    // Initialize
    loadScenarios();
});
