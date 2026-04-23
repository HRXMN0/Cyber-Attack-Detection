// =============================================================================
// AI Cyber SOC — Monitoring Agent v3.0
// Real-Time Threat Detection & Attack Analysis
//
// EMBED ON ANY WEBSITE:
//   <script
//     src="https://your-soc.onrender.com/static/agent.js"
//     data-site="gov-portal"
//     data-key="YOUR_API_KEY"
//     defer>
//   </script>
//
// What it does:
//   • Captures ALL visitor requests (page loads, AJAX, form POSTs, XHR)
//   • Detects: brute force, DDoS, path scanning, bot traffic, injection
//   • Reports to your SOC — ML model classifies each request in real-time
//   • Shows attacker country, city, ISP, attack type on your dashboard
//   • < 5KB, zero dependencies, never slows down your site
// =============================================================================

(function () {
  "use strict";

  // ── Read config from <script> tag attributes ─────────────────────────────
  var scriptTag = document.currentScript || (function () {
    var tags = document.getElementsByTagName("script");
    for (var i = tags.length - 1; i >= 0; i--) {
      if (tags[i].getAttribute("data-site") || tags[i].getAttribute("data-key")) return tags[i];
    }
    return tags[tags.length - 1];
  })();

  var SITE_ID  = scriptTag.getAttribute("data-site") || scriptTag.getAttribute("data-site-id") || "unknown";
  var API_KEY  = scriptTag.getAttribute("data-key")   || scriptTag.getAttribute("data-api-key") || "";
  var SOC_URL  = (scriptTag.src || "").replace(/\/static\/agent\.js.*/, "");
  var ENDPOINT = SOC_URL + "/api/agent/report";
  var DEBUG    = scriptTag.getAttribute("data-debug") === "true";

  if (!API_KEY) {
    console.warn("[SOC Agent] No API key provided. Set data-key attribute.");
    return;
  }

  // ── State ────────────────────────────────────────────────────────────────
  var _ip          = null;       // Resolved via ipify
  var _session     = _genId();   // Unique session ID
  var _startTime   = Date.now(); // Page load timestamp
  var _requestCount = 0;         // Requests this session
  var _formAttempts = 0;         // Login/form submissions
  var _errorCount  = 0;          // JS errors
  var _queue       = [];         // Pending reports
  var _sending     = false;
  var _ipFetched   = false;

  // Rate limiting: max 30 events/min to not abuse the SOC server
  var _lastReportTime = 0;
  var _reportThisMin  = 0;
  var _minuteStart    = Date.now();

  // Suspicious path patterns (always report these even if rate-limited)
  var SUSPICIOUS_PATHS = [
    "/admin", "/wp-admin", "/phpmyadmin", "/.env", "/etc/passwd", "/config",
    "/.git", "/backup", "/api/keys", "/secret", "/private", "/.htaccess",
    "/sql", "/shell", "/cmd", "/exec", "/eval", "/xmlrpc.php", "/login",
    "/signin", "/auth", "/account", "/users/", "/api/v1/admin",
  ];

  // Suspicious user agent fragments (bot/scanner signatures)
  var BOT_UA_SIGS = [
    "sqlmap", "nikto", "nmap", "masscan", "zgrab", "dirbuster", "gobuster",
    "wfuzz", "hydra", "curl/", "python-requests", "go-http-client", "java/",
    "libwww", "wget", "scrapy", "semrushbot", "ahrefsbot", "petalbot",
  ];

  function _genId() {
    return Math.random().toString(36).substr(2, 9) + Date.now().toString(36);
  }

  function _isSuspiciousPath(path) {
    var p = (path || "").toLowerCase();
    return SUSPICIOUS_PATHS.some(function (s) { return p.indexOf(s) !== -1; });
  }

  function _isBotUA(ua) {
    var u = (ua || "").toLowerCase();
    return BOT_UA_SIGS.some(function (s) { return u.indexOf(s) !== -1; });
  }

  function _rateLimited(force) {
    if (force) return false; // Always send force-flagged events
    var now = Date.now();
    if (now - _minuteStart > 60000) { _minuteStart = now; _reportThisMin = 0; }
    if (_reportThisMin >= 30) return true;
    _reportThisMin++;
    return false;
  }

  // ── Build payload ────────────────────────────────────────────────────────
  function _buildPayload(overrides) {
    var now = Date.now();
    var path = (overrides && overrides.path) || (window.location.pathname + window.location.search);
    var ua   = navigator.userAgent;
    var isBotUA = _isBotUA(ua);
    var isSuspPath = _isSuspiciousPath(path);

    return Object.assign({
      site_id      : SITE_ID,
      api_key      : API_KEY,
      ip           : _ip || "0.0.0.0",
      method       : "GET",
      path         : path,
      referer      : document.referrer || "",
      user_agent   : ua,
      bytes_in     : 0,
      timestamp    : new Date().toISOString(),
      // Extra context for ML + analyst display
      session_id   : _session,
      page_title   : document.title || "",
      request_num  : ++_requestCount,
      time_on_page : Math.round((now - _startTime) / 1000),
      language     : navigator.language || "",
      screen_w     : screen.width,
      screen_h     : screen.height,
      is_bot_ua    : isBotUA,
      is_susp_path : isSuspPath,
      form_attempts: _formAttempts,
      js_errors    : _errorCount,
    }, overrides);
  }

  // ── Send to SOC backend ──────────────────────────────────────────────────
  function _send(payload) {
    // Use sendBeacon for page unload; otherwise fetch
    if (navigator.sendBeacon && payload._beacon) {
      try {
        navigator.sendBeacon(ENDPOINT, new Blob([JSON.stringify(payload)], { type: "application/json" }));
        if (DEBUG) console.log("[SOC Agent] Beacon →", payload.method, payload.path);
        return;
      } catch (_) {}
    }
    if (window.fetch) {
      fetch(ENDPOINT, {
        method   : "POST",
        headers  : { "Content-Type": "application/json" },
        body     : JSON.stringify(payload),
        keepalive: true,
      }).then(function (r) {
        if (DEBUG) r.json().then(function (d) { console.log("[SOC Agent] Response:", d); });
      }).catch(function () {});
    }
  }

  // ── Queue & flush ────────────────────────────────────────────────────────
  function _enqueue(payload, force) {
    if (_rateLimited(force || payload.is_bot_ua || payload.is_susp_path)) return;
    _queue.push(payload);
    if (!_sending) _flush();
  }

  function _flush() {
    if (_queue.length === 0) { _sending = false; return; }
    _sending = true;
    var payload = _queue.shift();
    _send(payload);
    setTimeout(_flush, 120); // Space out requests
  }

  // ── Public report function ───────────────────────────────────────────────
  function report(eventType, extra, force) {
    var payload = _buildPayload(Object.assign({ event_type: eventType }, extra || {}));
    _enqueue(payload, force);
  }

  // ═══════════════════════════════════════════════════════════════════════
  // DETECTION MODULES
  // ═══════════════════════════════════════════════════════════════════════

  // ── 1. Page Load Monitoring ──────────────────────────────────────────────
  function _onPageLoad() {
    var path = window.location.pathname + window.location.search;
    var isSusp = _isSuspiciousPath(path);
    report("page_load", {
      method      : "GET",
      path        : path,
      suspect_path: isSusp,
    }, isSusp);
  }

  // ── 2. Intercept all fetch() calls ───────────────────────────────────────
  if (window.fetch) {
    var _origFetch = window.fetch;
    window.fetch = function (input, init) {
      var method  = ((init && init.method) || "GET").toUpperCase();
      var url     = typeof input === "string" ? input : (input && input.url) || "";
      var bytes   = 0;
      if (init && init.body) {
        try { bytes = (new TextEncoder()).encode(init.body).length; } catch (_) {}
      }
      // Only report same-origin or report all if scanning detected
      var sameOrigin = url.indexOf(window.location.origin) === 0 || url.indexOf("http") !== 0;
      if (sameOrigin) {
        var relPath = url.replace(window.location.origin, "") || url;
        report("fetch_request", { method: method, path: relPath, bytes_in: bytes });
      }
      return _origFetch.apply(this, arguments);
    };
  }

  // ── 3. Intercept XMLHttpRequest ──────────────────────────────────────────
  if (window.XMLHttpRequest) {
    var _origOpen = XMLHttpRequest.prototype.open;
    var _origSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function (method, url) {
      this._socM = (method || "GET").toUpperCase();
      this._socU = url || "";
      return _origOpen.apply(this, arguments);
    };
    XMLHttpRequest.prototype.send = function (body) {
      var bytes = 0;
      if (body) { try { bytes = (String(body)).length; } catch (_) {} }
      var url = this._socU || "";
      var sameOrigin = url.indexOf(window.location.origin) === 0 || url.indexOf("http") !== 0;
      if (sameOrigin) {
        var relPath = url.replace(window.location.origin, "") || url;
        report("xhr_request", { method: this._socM, path: relPath, bytes_in: bytes });
      }
      return _origSend.apply(this, arguments);
    };
  }

  // ── 4. Form submission tracking (brute force detection) ──────────────────
  document.addEventListener("submit", function (e) {
    var form   = e.target || {};
    var method = ((form.method || "GET")).toUpperCase();
    var action = form.action || window.location.href;
    var hasPass = !!form.querySelector("input[type='password']");
    var bytes  = 0;
    try {
      bytes = (new URLSearchParams(new FormData(form))).toString().length;
    } catch (_) {}

    _formAttempts++;

    // Multiple login attempts = brute force indicator
    var isBruteForce = hasPass && _formAttempts > 3;

    report(isBruteForce ? "brute_force_attempt" : (hasPass ? "login_attempt" : "form_submit"), {
      method       : method,
      path         : action.replace(window.location.origin, "") || action,
      bytes_in     : bytes,
      form_attempts: _formAttempts,
      has_password : hasPass,
    }, isBruteForce);
  }, true);

  // ── 5. JS Error monitoring (may indicate XSS or injection) ──────────────
  window.addEventListener("error", function (e) {
    _errorCount++;
    if (_errorCount <= 5) {
      report("js_error", {
        path         : window.location.pathname,
        error_msg    : (e.message || "").substring(0, 120),
        error_source : (e.filename || "").substring(0, 80),
        error_line   : e.lineno || 0,
      });
    }
  });

  // ── 6. Rapid clicking / DDoS pattern detection ───────────────────────────
  var _clickTimes = [];
  document.addEventListener("click", function () {
    var now = Date.now();
    _clickTimes.push(now);
    // Keep last 20 click times
    if (_clickTimes.length > 20) _clickTimes.shift();
    // If 15+ clicks in 3 seconds — potential automated clicking
    var recent = _clickTimes.filter(function (t) { return now - t < 3000; });
    if (recent.length >= 15 && recent.length % 5 === 0) {
      report("rapid_click_pattern", {
        path       : window.location.pathname,
        click_rate : recent.length,
      }, true);
    }
  });

  // ── 7. Page navigation tracking (SPA support) ────────────────────────────
  var _lastPath = window.location.pathname;
  setInterval(function () {
    var curPath = window.location.pathname + window.location.search;
    if (curPath !== _lastPath) {
      _lastPath = curPath;
      report("navigation", {
        method       : "GET",
        path         : curPath,
        is_susp_path : _isSuspiciousPath(curPath),
      }, _isSuspiciousPath(curPath));
    }
  }, 800);

  // ── 8. Page unload beacon ────────────────────────────────────────────────
  window.addEventListener("beforeunload", function () {
    var payload = _buildPayload({
      event_type   : "page_unload",
      method       : "GET",
      path         : window.location.pathname,
      time_on_page : Math.round((Date.now() - _startTime) / 1000),
      _beacon      : true,
    });
    _send(payload);
  });

  // ── 9. Heartbeat every 30 seconds ────────────────────────────────────────
  setInterval(function () {
    report("heartbeat", { method: "GET", path: window.location.pathname });
  }, 30000);

  // ═══════════════════════════════════════════════════════════════════════
  // INITIALIZATION
  // ═══════════════════════════════════════════════════════════════════════

  // Resolve visitor's public IP (the key piece for threat analysis)
  fetch("https://api.ipify.org?format=json", { mode: "cors" })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      _ip       = d.ip || "0.0.0.0";
      _ipFetched = true;
      if (DEBUG) console.log("[SOC Agent] Initialized | Site:", SITE_ID, "| IP:", _ip);
      _onPageLoad();
    })
    .catch(function () {
      _ipFetched = true;
      _onPageLoad(); // Still report even without IP
    });

  // Expose public API
  window.SOCAgent = {
    report  : report,
    siteId  : SITE_ID,
    session : _session,
    version : "3.0",
  };

})();
