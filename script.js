const API_BASE = "http://localhost:5012";

// ---------- Tabs ----------
document.querySelectorAll(".tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".panel").forEach(p => p.classList.add("hidden"));
    tab.classList.add("active");
    document.getElementById(`tab-${tab.dataset.tab}`).classList.remove("hidden");
  });
});

// ---------- Backend health check ----------
async function checkBackend() {
  const pill = document.getElementById("backendStatus");
  try {
    const res = await fetch(`${API_BASE}/api/health`);
    if (res.ok) {
      pill.textContent = "";
      pill.innerHTML = `<span class="dot"></span> BACKEND: ONLINE`;
      pill.classList.add("online");
      pill.classList.remove("offline");
      return;
    }
    throw new Error();
  } catch {
    pill.innerHTML = `<span class="dot"></span> BACKEND: OFFLINE`;
    pill.classList.add("offline");
    pill.classList.remove("online");
  }
}
checkBackend();

// ---------- Helpers ----------
function severityBadgeRow(counts) {
  const order = ["critical", "high", "medium", "low", "info"];
  return order
    .filter(s => counts[s] > 0)
    .map(s => `<span class="count-badge ${s}">${s.toUpperCase()}: ${counts[s]}</span>`)
    .join("");
}

function renderFindings(container, findings) {
  if (!findings || findings.length === 0) {
    container.innerHTML = `<div class="empty-state">✅ Geen findings — geen problemen gevonden binnen de uitgevoerde checks.</div>`;
    return;
  }
  container.innerHTML = findings.map(f => `
    <div class="finding ${f.severity}">
      <div class="finding-head">
        <span class="finding-title">${escapeHtml(f.title)}</span>
        <span class="sev-tag ${f.severity}">${f.severity}</span>
      </div>
      <div class="finding-detail">${escapeHtml(f.detail)}</div>
      ${f.resource ? `<div class="finding-resource">→ ${escapeHtml(f.resource)}</div>` : ""}
    </div>
  `).join("");
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str ?? "";
  return div.innerHTML;
}

function showError(container, message) {
  container.innerHTML = `<div class="error-box">⚠ ${escapeHtml(message)}</div>`;
}

// ---------- AWS Scan ----------
const scanAwsBtn = document.getElementById("scanAwsBtn");
scanAwsBtn.addEventListener("click", async () => {
  const accessKey = document.getElementById("accessKey").value.trim();
  const secretKey = document.getElementById("secretKey").value.trim();
  const sessionToken = document.getElementById("sessionToken").value.trim();
  const region = document.getElementById("region").value;

  const checks = Array.from(document.querySelectorAll("#awsChecklist input:checked")).map(c => c.value);

  const findingsEl = document.getElementById("awsFindings");
  const summaryEl = document.getElementById("awsSummary");

  if (!accessKey || !secretKey) {
    showError(findingsEl, "Vul zowel Access Key ID als Secret Access Key in.");
    return;
  }
  if (checks.length === 0) {
    showError(findingsEl, "Selecteer minstens één check.");
    return;
  }

  scanAwsBtn.disabled = true;
  scanAwsBtn.innerHTML = `<span class="spinner"></span> SCANNEN...`;
  summaryEl.classList.add("hidden");
  findingsEl.innerHTML = `<div class="empty-state"><span class="spinner"></span> Bezig met scannen van AWS omgeving...</div>`;

  try {
    const res = await fetch(`${API_BASE}/api/scan/aws`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        access_key: accessKey,
        secret_key: secretKey,
        session_token: sessionToken,
        region: region,
        checks: checks,
      }),
    });

    const data = await res.json();

    if (!res.ok) {
      showError(findingsEl, data.error || "Onbekende fout tijdens scan.");
      return;
    }

    document.getElementById("awsIdentity").innerHTML =
      `Account: <strong>${escapeHtml(data.account_id)}</strong><br>Identity: ${escapeHtml(data.identity_arn)}<br>Checks uitgevoerd: ${data.checks_run.join(", ")}`;
    document.getElementById("awsCounts").innerHTML = severityBadgeRow(data.counts);
    summaryEl.classList.remove("hidden");

    renderFindings(findingsEl, data.findings);
  } catch (err) {
    showError(findingsEl, `Kon backend niet bereiken: ${err.message}. Draait de Python server op ${API_BASE}?`);
  } finally {
    scanAwsBtn.disabled = false;
    scanAwsBtn.innerHTML = `<span class="btn-icon">▶</span> START AWS SCAN`;
  }
});

// ---------- Endpoint Scan ----------
const scanEndpointBtn = document.getElementById("scanEndpointBtn");
scanEndpointBtn.addEventListener("click", async () => {
  const url = document.getElementById("endpointUrl").value.trim();
  const findingsEl = document.getElementById("endpointFindings");
  const summaryEl = document.getElementById("endpointSummary");

  if (!url) {
    showError(findingsEl, "Vul een URL in.");
    return;
  }

  scanEndpointBtn.disabled = true;
  scanEndpointBtn.innerHTML = `<span class="spinner"></span> SCANNEN...`;
  summaryEl.classList.add("hidden");
  findingsEl.innerHTML = `<div class="empty-state"><span class="spinner"></span> Bezig met scannen van endpoint...</div>`;

  try {
    const res = await fetch(`${API_BASE}/api/scan/endpoint`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });

    const data = await res.json();

    if (!res.ok) {
      showError(findingsEl, data.error || "Onbekende fout tijdens scan.");
      return;
    }

    document.getElementById("endpointIdentity").innerHTML =
      `URL: <strong>${escapeHtml(data.url)}</strong><br>Status code: ${data.status_code ?? "n/a"}`;
    document.getElementById("endpointCounts").innerHTML = severityBadgeRow(data.counts);
    summaryEl.classList.remove("hidden");

    renderFindings(findingsEl, data.findings);
  } catch (err) {
    showError(findingsEl, `Kon backend niet bereiken: ${err.message}. Draait de Python server op ${API_BASE}?`);
  } finally {
    scanEndpointBtn.disabled = false;
    scanEndpointBtn.innerHTML = `<span class="btn-icon">▶</span> START ENDPOINT SCAN`;
  }
});
