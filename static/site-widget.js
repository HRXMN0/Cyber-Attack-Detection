// =============================================================================
// site-widget.js — Embeddable Mini Dashboard for Monitored Sites
// Companies embed this to show their own attack data on their website
//
// Usage:
//   <script src="https://your-soc-server/static/site-widget.js"
//           data-site="gov-portal"
//           data-key="your-api-key"
//           data-position="bottom-right"></script>
// =============================================================================

(function () {
  "use strict";

  // ---- Config from script tag ----
  var scriptTag = document.currentScript ||
    (function () {
      var tags = document.getElementsByTagName("script");
      return tags[tags.length - 1];
    })();

  var SITE_ID   = scriptTag.getAttribute("data-site") || "unknown";
  var API_KEY   = scriptTag.getAttribute("data-key") || "";
  var POSITION  = scriptTag.getAttribute("data-position") || "bottom-right"; // top-left, top-right, bottom-left, bottom-right
  var SOC_URL   = scriptTag.src.replace(/\/static\/site-widget\.js.*/, "");
  var API_BASE  = SOC_URL + "/api";

  if (!API_KEY) {
    console.error("[SOC Widget] ERROR: data-key attribute is required");
    return;
  }

  // ---- Styles ----
  var STYLES = `
    .soc-widget {
      position: fixed;
      z-index: 999999;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Inter', sans-serif;
      font-size: 13px;
      line-height: 1.5;
      color: #e8eaf6;
      background: rgba(10, 14, 26, 0.95);
      border: 1px solid rgba(0, 229, 255, 0.2);
      border-radius: 12px;
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4), 0 0 20px rgba(0, 229, 255, 0.1);
      backdrop-filter: blur(16px);
      min-width: 320px;
      max-width: 380px;
      overflow: hidden;
      transition: transform 0.3s ease, opacity 0.3s ease;
    }
    .soc-widget.top-left { top: 20px; left: 20px; }
    .soc-widget.top-right { top: 20px; right: 20px; }
    .soc-widget.bottom-left { bottom: 20px; left: 20px; }
    .soc-widget.bottom-right { bottom: 20px; right: 20px; }

    .soc-widget-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 12px 16px;
      background: linear-gradient(135deg, rgba(0, 229, 255, 0.1), rgba(0, 229, 255, 0.05));
      border-bottom: 1px solid rgba(0, 229, 255, 0.15);
    }
    .soc-widget-title {
      display: flex;
      align-items: center;
      gap: 8px;
      font-weight: 700;
      font-size: 14px;
    }
    .soc-widget-shield { font-size: 16px; }
    .soc-widget-status {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      padding: 4px 10px;
      border-radius: 99px;
      background: rgba(0, 255, 136, 0.15);
      color: #00ff88;
      border: 1px solid rgba(0, 255, 136, 0.3);
    }
    .soc-widget-status.attack {
      background: rgba(255, 23, 68, 0.15);
      color: #ff1744;
      border-color: rgba(255, 23, 68, 0.3);
      animation: soc-pulse 1.5s ease-in-out infinite;
    }
    @keyframes soc-pulse {
      0%, 100% { box-shadow: 0 0 0 0 rgba(255, 23, 68, 0.3); }
      50% { box-shadow: 0 0 0 6px rgba(255, 23, 68, 0); }
    }
    .soc-dot {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: currentColor;
      box-shadow: 0 0 6px currentColor;
    }

    .soc-widget-stats {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 12px;
      padding: 16px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    }
    .soc-stat {
      text-align: center;
    }
    .soc-stat-value {
      font-size: 20px;
      font-weight: 800;
      color: #00e5ff;
      line-height: 1;
    }
    .soc-stat-value.danger { color: #ff1744; }
    .soc-stat-value.warning { color: #ff9100; }
    .soc-stat-label {
      font-size: 10px;
      color: #8892b0;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-top: 4px;
    }

    .soc-widget-section {
      padding: 12px 16px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    }
    .soc-widget-section:last-child { border-bottom: none; }
    .soc-section-title {
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: #8892b0;
      margin-bottom: 10px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .soc-live-badge {
      font-size: 9px;
      padding: 2px 6px;
      background: rgba(0, 255, 136, 0.15);
      color: #00ff88;
      border-radius: 99px;
    }

    .soc-attack-list {
      max-height: 150px;
      overflow-y: auto;
    }
    .soc-attack-item {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 8px 0;
      border-bottom: 1px solid rgba(255, 255, 255, 0.03);
      font-size: 12px;
    }
    .soc-attack-item:last-child { border-bottom: none; }
    .soc-attack-info { display: flex; flex-direction: column; gap: 2px; }
    .soc-attack-type { font-weight: 600; color: #e8eaf6; }
    .soc-attack-ip { font-size: 10px; color: #00e5ff; font-family: 'SF Mono', monospace; }
    .soc-attack-time { font-size: 10px; color: #4a5568; }
    .soc-severity {
      font-size: 10px;
      font-weight: 700;
      text-transform: uppercase;
      padding: 3px 8px;
      border-radius: 99px;
    }
    .soc-severity.critical { background: rgba(255, 23, 68, 0.15); color: #ff1744; }
    .soc-severity.high { background: rgba(255, 145, 0, 0.15); color: #ff9100; }
    .soc-severity.medium { background: rgba(255, 214, 0, 0.15); color: #ffd600; }
    .soc-severity.low { background: rgba(102, 187, 106, 0.15); color: #66bb6a; }
    .soc-severity.none { background: rgba(0, 255, 136, 0.1); color: #00ff88; }

    .soc-blocked-list {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      max-height: 80px;
      overflow-y: auto;
    }
    .soc-blocked-ip {
      font-size: 10px;
      font-family: 'SF Mono', monospace;
      padding: 4px 8px;
      background: rgba(255, 23, 68, 0.1);
      color: #ff5252;
      border: 1px solid rgba(255, 23, 68, 0.2);
      border-radius: 6px;
    }

    .soc-empty {
      text-align: center;
      padding: 20px;
      color: #4a5568;
      font-size: 12px;
    }

    .soc-widget-footer {
      padding: 10px 16px;
      background: rgba(0, 0, 0, 0.2);
      font-size: 10px;
      color: #4a5568;
      text-align: center;
    }
    .soc-widget-footer a {
      color: #00e5ff;
      text-decoration: none;
    }

    .soc-toggle-btn {
      position: fixed;
      z-index: 999998;
      width: 50px;
      height: 50px;
      border-radius: 50%;
      background: linear-gradient(135deg, #00b4d8, #00e5ff);
      border: none;
      color: #0a0e1a;
      font-size: 20px;
      cursor: pointer;
      box-shadow: 0 4px 20px rgba(0, 229, 255, 0.4);
      transition: transform 0.2s ease;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .soc-toggle-btn:hover { transform: scale(1.1); }
    .soc-toggle-btn.top-left { top: 20px; left: 20px; }
    .soc-toggle-btn.top-right { top: 20px; right: 20px; }
    .soc-toggle-btn.bottom-left { bottom: 20px; left: 20px; }
    .soc-toggle-btn.bottom-right { bottom: 20px; right: 20px; }

    .soc-widget.collapsed { transform: scale(0); opacity: 0; pointer-events: none; }
  `;

  // ---- Inject styles ----
  var styleEl = document.createElement("style");
  styleEl.textContent = STYLES;
  document.head.appendChild(styleEl);

  // ---- Create widget ----
  var widget = document.createElement("div");
  widget.className = "soc-widget " + POSITION;
  widget.innerHTML = `
    <div class="soc-widget-header">
      <div class="soc-widget-title">
        <span class="soc-widget-shield">🛡️</span>
        <span>Security Monitor</span>
      </div>
      <div class="soc-widget-status" id="soc-status">
        <span class="soc-dot"></span>
        <span>Secure</span>
      </div>
    </div>
    <div class="soc-widget-stats">
      <div class="soc-stat">
        <div class="soc-stat-value" id="soc-total-events">—</div>
        <div class="soc-stat-label">Events</div>
      </div>
      <div class="soc-stat">
        <div class="soc-stat-value" id="soc-attacks">—</div>
        <div class="soc-stat-label">Attacks</div>
      </div>
      <div class="soc-stat">
        <div class="soc-stat-value" id="soc-blocked">—</div>
        <div class="soc-stat-label">Blocked</div>
      </div>
    </div>
    <div class="soc-widget-section">
      <div class="soc-section-title">
        <span>⚔️ Recent Attacks</span>
        <span class="soc-live-badge">● LIVE</span>
      </div>
      <div class="soc-attack-list" id="soc-attack-list">
        <div class="soc-empty">Loading...</div>
      </div>
    </div>
    <div class="soc-widget-section">
      <div class="soc-section-title">🚫 Blocked IPs</div>
      <div class="soc-blocked-list" id="soc-blocked-list">
        <div class="soc-empty">No blocked IPs</div>
      </div>
    </div>
    <div class="soc-widget-footer">
      Protected by <a href="${SOC_URL}" target="_blank">AI Cyber SOC</a>
    </div>
  `;

  // ---- Create toggle button ----
  var toggleBtn = document.createElement("button");
  toggleBtn.className = "soc-toggle-btn " + POSITION;
  toggleBtn.innerHTML = "🛡️";
  toggleBtn.title = "Security Monitor";
  toggleBtn.onclick = function () {
    widget.classList.toggle("collapsed");
    toggleBtn.style.display = widget.classList.contains("collapsed") ? "flex" : "none";
  };

  // ---- Close widget when clicking outside ----
  widget.addEventListener("click", function (e) {
    if (e.target.closest(".soc-widget-header")) {
      widget.classList.add("collapsed");
      toggleBtn.style.display = "flex";
    }
  });

  // ---- Add to page ----
  document.body.appendChild(widget);
  document.body.appendChild(toggleBtn);

  // ---- Fetch data ----
  function fetchData() {
    fetch(API_BASE + "/widget/logs?site_id=" + encodeURIComponent(SITE_ID), {
      headers: {
        "X-Site-ID": SITE_ID,
        "X-API-Key": API_KEY
      }
    })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        updateWidget(data);
      })
      .catch(function (err) {
        console.error("[SOC Widget] Failed to fetch:", err);
      });
  }

  // ---- Update widget ----
  function updateWidget(data) {
    var logs = data.attack_log || [];
    var blocked = [];
    var attackCount = 0;

    // Count attacks and collect blocked IPs
    logs.forEach(function (log) {
      if (log.severity && log.severity !== "None") {
        attackCount++;
      }
      if (log.action && log.action.includes("block")) {
        blocked.push(log.ip);
      }
    });

    // Update stats
    document.getElementById("soc-total-events").textContent = logs.length;
    document.getElementById("soc-attacks").textContent = attackCount;
    document.getElementById("soc-blocked").textContent = blocked.length;

    // Update status
    var statusEl = document.getElementById("soc-status");
    if (attackCount > 0) {
      statusEl.className = "soc-widget-status attack";
      statusEl.innerHTML = '<span class="soc-dot"></span><span>Under Attack</span>';
    } else {
      statusEl.className = "soc-widget-status";
      statusEl.innerHTML = '<span class="soc-dot"></span><span>Secure</span>';
    }

    // Update attack list
    var attackList = document.getElementById("soc-attack-list");
    if (logs.length === 0) {
      attackList.innerHTML = '<div class="soc-empty">No recent events</div>';
    } else {
      attackList.innerHTML = logs.slice(-5).reverse().map(function (log) {
        var sevClass = (log.severity || "none").toLowerCase().replace(/\s/g, "");
        var time = new Date(log.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        return `
          <div class="soc-attack-item">
            <div class="soc-attack-info">
              <span class="soc-attack-type">${log.attack || "Unknown"}</span>
              <span class="soc-attack-ip">${log.ip || "—"}</span>
              <span class="soc-attack-time">${time}</span>
            </div>
            <span class="soc-severity ${sevClass}">${log.severity || "—"}</span>
          </div>
        `;
      }).join("");
    }

    // Update blocked IPs
    var blockedList = document.getElementById("soc-blocked-list");
    if (blocked.length === 0) {
      blockedList.innerHTML = '<div class="soc-empty">No blocked IPs</div>';
    } else {
      blockedList.innerHTML = [...new Set(blocked)].slice(0, 10).map(function (ip) {
        return `<span class="soc-blocked-ip">${ip}</span>`;
      }).join("");
    }
  }

  // ---- Initial fetch & poll ----
  fetchData();
  setInterval(fetchData, 10000); // Refresh every 10 seconds

})();
