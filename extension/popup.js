document.addEventListener("DOMContentLoaded", async () => {
  const activeTabUrlEl = document.getElementById("activeTabUrl");
  const scanActiveUrlBtn = document.getElementById("scanActiveUrlBtn");
  const extInput = document.getElementById("extInput");
  const scanExtTextBtn = document.getElementById("scanExtTextBtn");
  const extResult = document.getElementById("extResult");
  const extBadge = document.getElementById("extBadge");
  const extScore = document.getElementById("extScore");
  const extLatency = document.getElementById("extLatency");
  const extReason = document.getElementById("extReason");

  let currentUrl = "";

  // Query current tab
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs && tabs[0] && tabs[0].url) {
      currentUrl = tabs[0].url;
      activeTabUrlEl.textContent = currentUrl;
    } else {
      activeTabUrlEl.textContent = "No active page URL found";
    }
  } catch (e) {
    activeTabUrlEl.textContent = "Browser tab access restricted";
  }

  async function queryAegisLocal(payloadText) {
    extResult.classList.remove("hidden");
    extBadge.textContent = "ANALYZING...";
    extBadge.style.background = "#334155";
    extBadge.style.color = "#94a3b8";

    try {
      const res = await fetch("http://127.0.0.1:8000/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: payloadText })
      });
      const data = await res.json();

      extBadge.textContent = data.verdict;
      extBadge.style.background = data.badge_color;
      extBadge.style.color = "#ffffff";
      extScore.textContent = data.risk_score;
      extLatency.textContent = `⚡ Local Latency: ${data.telemetry.latency_ms} ms (0 Cloud Calls)`;
      
      const reasons = data.explanation.reasons || [];
      if (reasons.length > 0) {
        extReason.textContent = reasons[0].explanation;
      } else {
        extReason.textContent = "Verified safe with 0 deceptive threat indicators detected.";
      }
    } catch (err) {
      extBadge.textContent = "SERVER OFFLINE";
      extBadge.style.background = "#ef4444";
      extReason.textContent = "Ensure local AegisLocal server is running on http://127.0.0.1:8000";
    }
  }

  scanActiveUrlBtn.addEventListener("click", () => {
    if (currentUrl) {
      queryAegisLocal(currentUrl);
    }
  });

  scanExtTextBtn.addEventListener("click", () => {
    const text = extInput.value.trim();
    if (text) {
      queryAegisLocal(text);
    }
  });
});
