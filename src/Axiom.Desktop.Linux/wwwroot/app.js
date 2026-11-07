// SPDX-License-Identifier: GPL-3.0-or-later
// Loopback-only UI for Axiom.Service. The token arrives in the URL fragment, is kept in
// sessionStorage and is sent as a header; it is never placed in a query string or a cookie.
(() => {
  "use strict";

  const params = new URLSearchParams(location.hash.replace(/^#/, ""));
  const incoming = params.get("t");
  if (incoming) {
    sessionStorage.setItem("axiomToken", incoming);
    history.replaceState(null, "", location.pathname);
  }

  // A token link opened in a tab that already loaded the UI changes only the
  // fragment; reload so the new token replaces the stale one.
  window.addEventListener("hashchange", () => location.reload());

  const token = sessionStorage.getItem("axiomToken") || "";
  const state = document.getElementById("service-state");
  let snapshot = null;
  let historyOffset = 0;
  let historyTotal = 0;
  let historyRequest = 0;

  const HISTORY_PAGE = 200;

  // Both the service and the History page labels report UTC; render it explicitly so a
  // timestamp is never silently shown in the viewer's local zone.
  const utcTimestamp = (value) => {
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? "" : parsed.toISOString().slice(0, 19).replace("T", " ");
  };

  const esc = (value) => String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");

  async function readJson(response) {
    const body = await response.json().catch(() => ({}));
    if (response.status === 401) {
      const error = new Error(
        "Session token missing or expired. Reopen the Axiom UI link that contains #t=… " +
        "(the UI prints it on startup, for the unit: journalctl -u axiom-ui).");
      error.code = "unauthorized";
      throw error;
    }
    if (!response.ok) {
      const error = new Error(body.message || body.error || `HTTP ${response.status}`);
      error.code = body.error;
      throw error;
    }
    return body;
  }

  async function api(path) {
    const response = await fetch(path, { headers: { "X-Axiom-Token": token } });
    return readJson(response);
  }

  function setState(text, cssClass) {
    state.textContent = text;
    state.className = `state ${cssClass || ""}`;
  }

  function showAuthNote(message) {
    const note = document.getElementById("auth-note");
    note.textContent = message;
    note.hidden = !message;
  }

  function card(label, value, cssClass) {
    return `<div class="card"><div class="label">${esc(label)}</div><div class="value ${cssClass || ""}">${esc(value)}</div></div>`;
  }

  async function loadOverview() {
    try {
      const data = await api("/api/status");
      const h = data.health;
      setState(`service ${h.status}`, "ok");
      showAuthNote("");
      document.getElementById("overview-cards").innerHTML = [
        card("Source", h.sourceName),
        card("Connections", h.connectionCount),
        card("Processes", h.processCount),
        card("Uptime", `${Math.floor(h.uptimeSeconds / 60)} min`),
        card("Poll interval", `${h.pollIntervalSeconds}s`),
        card("Last capture (UTC)", h.lastCaptureUtc ? utcTimestamp(h.lastCaptureUtc) : "pending"),
      ].join("");
      document.getElementById("limitations").innerHTML =
        (h.limitations || []).map((item) => `<li>${esc(item)}</li>`).join("") ||
        "<li>No limitations reported.</li>";
      document.getElementById("about-list").innerHTML = Object.entries({
        "Service endpoint": data.endpoint,
        "Protocol version": data.capabilities.protocolVersion,
        "Milestone": data.capabilities.milestone,
        "Firewall writes": data.capabilities.firewallWrites ? "enabled by explicit gate" : "disabled (default)",
        "Commands": (data.capabilities.commands || []).join(", "),
      }).map(([key, value]) => `<dt>${esc(key)}</dt><dd>${esc(value)}</dd>`).join("");
    } catch (error) {
      setState(error.code === "service_unavailable" ? "service unavailable" : "error", "bad");
      showAuthNote(error.code === "unauthorized" ? error.message : "");
      document.getElementById("overview-cards").innerHTML = card(
        "Service",
        error.code === "unauthorized" ? "session expired" : error.message,
        "bad");
    }
  }

  async function loadConnections() {
    try {
      snapshot = await api("/api/connections");
      renderConnections();
    } catch (error) {
      setState("snapshot unavailable", "bad");
      document.getElementById("connections-body").innerHTML =
        `<tr><td colspan="8">${esc(error.message)}</td></tr>`;
    }
  }

  function renderConnections() {
    if (!snapshot) return;
    const filter = document.getElementById("conn-filter").value.trim().toLowerCase();
    const newOnly = document.getElementById("conn-new-only").checked;
    const rows = (snapshot.connections || []).filter((row) => {
      if (newOnly && !row.isNew) return false;
      if (!filter) return true;
      return [row.appDisplayName, row.appPath, row.localEndpoint, row.remoteEndpoint, row.state,
        row.direction, row.protocol, row.processId].join(" ").toLowerCase().includes(filter);
    });

    document.getElementById("conn-count").textContent =
      `${rows.length} of ${snapshot.connections.length} sockets, ${snapshot.processCount} processes`;
    document.getElementById("connections-body").innerHTML = rows.map((row) => `
      <tr>
        <td class="wrap">${esc(row.appDisplayName)}<br><span class="muted">${esc(row.appPath)}</span></td>
        <td>${esc(row.processId)}</td>
        <td>${esc(row.protocol)}</td>
        <td>${esc(row.localEndpoint)}</td>
        <td>${esc(row.remoteEndpoint)}</td>
        <td>${esc(row.state)}</td>
        <td>${esc(row.direction)}</td>
        <td>${esc(row.quality)}</td>
      </tr>`).join("") || `<tr><td colspan="8" class="muted">No matching sockets.</td></tr>`;
  }

  async function loadHistory() {
    const search = document.getElementById("history-search").value.trim();
    const hours = document.getElementById("history-hours").value;
    const offset = historyOffset;
    // A slower, older query must not overwrite the newer selection's rows and paging state.
    const request = ++historyRequest;
    const url = `/api/history?hours=${encodeURIComponent(hours)}&limit=${HISTORY_PAGE}&offset=${offset}` +
      (search ? `&search=${encodeURIComponent(search)}` : "");

    try {
      const page = await api(url);
      if (request !== historyRequest) return;
      historyTotal = page.totalCount;
      document.getElementById("history-info").textContent = page.rows.length === 0
        ? `0 of ${historyTotal}`
        : `${offset + 1}-${Math.min(offset + page.rows.length, historyTotal)} of ${historyTotal}`;
      document.getElementById("history-prev").disabled = offset === 0;
      document.getElementById("history-next").disabled = offset + HISTORY_PAGE >= historyTotal;
      document.getElementById("history-db").textContent = page.databasePath;
      document.getElementById("history-body").innerHTML = page.rows.map((row) => `
        <tr>
          <td class="wrap">${esc(row.appDisplayName)}<br><span class="muted">${esc(row.appPath)}</span></td>
          <td>${esc(row.protocol)}</td>
          <td>${esc(row.localEndpoint)}</td>
          <td>${esc(row.remoteEndpoint)}</td>
          <td>${esc(row.direction)}</td>
          <td>${esc(utcTimestamp(row.firstSeenUtc))}</td>
          <td>${esc(utcTimestamp(row.lastSeenUtc))}</td>
        </tr>`).join("") || `<tr><td colspan="7" class="muted">No stored rows in this window.</td></tr>`;
    } catch (error) {
      if (request !== historyRequest) return;
      document.getElementById("history-body").innerHTML = `<tr><td colspan="7">${esc(error.message)}</td></tr>`;
    }
  }

  async function loadFirewall() {
    try {
      const data = await api("/api/firewall");
      const capability = data.capability || {};
      const cls = capability.status === "available" ? "ok" : "bad";
      document.getElementById("firewall-summary").innerHTML = [
        card("Backend", capability.status),
        card("Owned rules", capability.managedRuleCount ?? 0),
        card("Writes", data.writesEnabled ? "gate open" : "gate closed"),
      ].join("");
      document.getElementById("firewall-note").textContent = capability.reason || "";
      document.getElementById("firewall-note").className = `notes ${cls}`;
      document.getElementById("firewall-body").innerHTML = (data.rules || []).map((rule) => `
        <tr>
          <td>${esc(rule.osRuleName)}</td>
          <td>${esc(rule.spec.direction)}</td>
          <td>${esc(rule.spec.action)}</td>
          <td class="wrap">${esc(rule.spec.appPath)}</td>
          <td>${esc(rule.state)}</td>
        </tr>`).join("") || `<tr><td colspan="5" class="muted">No owned rules.</td></tr>`;
    } catch (error) {
      document.getElementById("firewall-body").innerHTML = `<tr><td colspan="5">${esc(error.message)}</td></tr>`;
    }
  }

  async function loadAi() {
    try {
      const data = await api("/api/ai");
      document.getElementById("ai-enabled").checked = !!data.settings.enabled;
      document.getElementById("ai-endpoint").value = data.settings.endpoint || "";
      document.getElementById("ai-model").value = data.settings.model || "";
      document.getElementById("ai-redact").checked = data.settings.redactPaths !== false;
      const available = !!data.credential.available;
      document.getElementById("ai-status").textContent =
        `credential backend: ${data.credential.backend} (${available ? "available" : "unavailable"}), key stored: ${data.credential.hasKey ? "yes" : "no"}` +
        (available ? "" : " — no keyring, so the key cannot be stored on this host");
      // A store that cannot succeed is disabled with the reason above instead of failing on click.
      document.getElementById("ai-key").disabled = !available;
      document.getElementById("ai-key-save").disabled = !available;
      document.getElementById("ai-key-delete").disabled = !available;
    } catch (error) {
      document.getElementById("ai-status").textContent = error.message;
    }
  }

  async function loadReputation() {
    const status = document.getElementById("reputation-status");
    try {
      const data = await api("/api/reputation");
      const available = !!data.credential.available;
      status.textContent =
        `credential backend: ${data.credential.backend} (${available ? "available" : "unavailable"}), key stored: ${data.credential.hasKey ? "yes" : "no"}` +
        (available ? "" : " — no keyring, so the key cannot be stored on this host");
      document.getElementById("reputation-key").disabled = !available;
      document.getElementById("reputation-key-save").disabled = !available;
      document.getElementById("reputation-key-delete").disabled = !available;
    } catch (error) {
      status.textContent = error.message;
    }
  }

  async function loadAutostart() {
    try {
      const data = await api("/api/autostart");
      const toggle = document.getElementById("autostart-enabled");
      toggle.checked = !!data.enabled;
      toggle.disabled = !data.supported;
      toggle.title = data.supported ? "" : "Run the installed desktop binary to manage autostart.";
    } catch (error) {
      document.getElementById("autostart-enabled").disabled = true;
      document.getElementById("autostart-enabled").title = error.message;
    }
  }

  async function loadPrivacy() {
    try {
      const status = await api("/api/privacy");
      document.getElementById("privacy-summary").innerHTML = [
        card("Enabled", status.enabled ? "yes" : "no", status.enabled ? "ok" : ""),
        card("Listen", status.bindAddress || "not started"),
        card("Upstream", status.upstream || "none"),
        card("Queries", status.queries ?? 0),
        card("Blocked", status.blocked ?? 0),
        card("Errors", status.errors ?? 0, status.errors ? "warn" : ""),
      ].join("");
      document.getElementById("privacy-note").textContent = status.lastError || "";
    } catch (error) {
      document.getElementById("privacy-summary").innerHTML = card("Privacy Shield", error.message, "bad");
      document.getElementById("privacy-note").textContent = "";
    }
  }

  document.getElementById("nav").addEventListener("click", (event) => {
    const button = event.target.closest("button[data-page]");
    if (!button) return;
    for (const element of document.querySelectorAll("nav button")) element.classList.remove("active");
    button.classList.add("active");
    for (const page of document.querySelectorAll(".page")) page.classList.remove("active");
    document.getElementById(`page-${button.dataset.page}`).classList.add("active");

    if (button.dataset.page === "connections") loadConnections();
    if (button.dataset.page === "history") loadHistory();
    if (button.dataset.page === "firewall") loadFirewall();
    if (button.dataset.page === "privacy") loadPrivacy();
    if (button.dataset.page === "ai") { loadAi(); loadReputation(); }
    if (button.dataset.page === "about") { loadOverview(); loadAutostart(); }
  });

  document.getElementById("conn-filter").addEventListener("input", renderConnections);
  document.getElementById("conn-new-only").addEventListener("change", renderConnections);
  document.getElementById("history-run").addEventListener("click", () => {
    historyOffset = 0;
    loadHistory();
  });
  // A narrower window starts at the first page; keeping the old offset would show an empty page.
  document.getElementById("history-hours").addEventListener("change", () => {
    historyOffset = 0;
    loadHistory();
  });
  document.getElementById("history-search").addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      historyOffset = 0;
      loadHistory();
    }
  });
  document.getElementById("history-export").addEventListener("click", async () => {
    const hours = document.getElementById("history-hours").value;
    const search = document.getElementById("history-search").value.trim();
    const url = `/api/history.csv?hours=${encodeURIComponent(hours)}` +
      (search ? `&search=${encodeURIComponent(search)}` : "");
    const response = await fetch(url, { headers: { "X-Axiom-Token": sessionStorage.getItem("axiomToken") || "" } });
    if (!response.ok) {
      const detail = await response.json().catch(() => ({}));
      document.getElementById("history-info").textContent = response.status === 401
        ? "session expired — reopen the token link, then export again"
        : `export failed: ${detail.message || detail.error || `HTTP ${response.status}`}`;
      return;
    }
    const blob = await response.blob();
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "axiom-history.csv";
    link.click();
    URL.revokeObjectURL(link.href);
  });

  async function postJson(path, body, method) {
    const response = await fetch(path, {
      method: method || "POST",
      headers: {
        "X-Axiom-Token": sessionStorage.getItem("axiomToken") || "",
        "Content-Type": "application/json",
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return readJson(response);
  }

  document.getElementById("ai-save").addEventListener("click", async () => {
    try {
      await postJson("/api/ai/settings", {
        enabled: document.getElementById("ai-enabled").checked,
        endpoint: document.getElementById("ai-endpoint").value.trim(),
        model: document.getElementById("ai-model").value.trim(),
        redactPaths: document.getElementById("ai-redact").checked,
      });
      await loadAi();
    } catch (error) {
      document.getElementById("ai-status").textContent = error.message;
    }
  });

  document.getElementById("ai-key-save").addEventListener("click", async () => {
    try {
      await postJson("/api/ai/key", { key: document.getElementById("ai-key").value });
      document.getElementById("ai-key").value = "";
      await loadAi();
    } catch (error) {
      document.getElementById("ai-status").textContent = error.message;
    }
  });

  document.getElementById("ai-key-delete").addEventListener("click", async () => {
    try {
      await postJson("/api/ai/key", undefined, "DELETE");
      await loadAi();
    } catch (error) {
      document.getElementById("ai-status").textContent = error.message;
    }
  });

  document.getElementById("ai-analyze").addEventListener("click", async () => {
    document.getElementById("ai-output").textContent = "analyzing...";
    try {
      const finding = await postJson("/api/ai/analyze", {});
      document.getElementById("ai-output").textContent =
        `${finding.status} / ${finding.severity} / confidence ${finding.confidence}\n\n${finding.summary}` +
        ((finding.error) ? `\n\nerror: ${finding.error}` : "");
    } catch (error) {
      document.getElementById("ai-output").textContent = error.message;
    }
  });

  document.getElementById("reputation-key-save").addEventListener("click", async () => {
    const status = document.getElementById("reputation-status");
    try {
      await postJson("/api/reputation/key", { key: document.getElementById("reputation-key").value });
      document.getElementById("reputation-key").value = "";
      await loadReputation();
    } catch (error) {
      status.textContent = error.message;
    }
  });

  document.getElementById("reputation-key-delete").addEventListener("click", async () => {
    const status = document.getElementById("reputation-status");
    try {
      await postJson("/api/reputation/key", undefined, "DELETE");
      await loadReputation();
    } catch (error) {
      status.textContent = error.message;
    }
  });

  document.getElementById("reputation-run").addEventListener("click", async () => {
    document.getElementById("reputation-output").textContent = "hashing...";
    try {
      const result = await postJson("/api/reputation", { path: document.getElementById("reputation-path").value.trim() });
      document.getElementById("reputation-output").textContent = `${result.sha256}\n${result.report.summary}`;
    } catch (error) {
      document.getElementById("reputation-output").textContent = error.message;
    }
  });

  document.getElementById("autostart-enabled").addEventListener("change", async (event) => {
    try {
      await postJson("/api/autostart", { enabled: event.target.checked });
    } catch (error) {
      event.target.checked = !event.target.checked;
    }
    await loadAutostart();
  });

  document.getElementById("history-prev").addEventListener("click", () => {
    historyOffset = Math.max(0, historyOffset - HISTORY_PAGE);
    loadHistory();
  });
  document.getElementById("history-next").addEventListener("click", () => {
    if (historyOffset + HISTORY_PAGE < historyTotal) {
      historyOffset += HISTORY_PAGE;
      loadHistory();
    }
  });

  loadOverview();
  setInterval(() => {
    loadOverview();
    if (document.getElementById("page-connections").classList.contains("active")) loadConnections();
  }, 2000);
})();
