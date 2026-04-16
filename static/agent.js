// =============================================================================
// agent.js — Cyber Monitoring Agent Embed Snippet
// Drop this into any website's <head>:
//   <script src="https://your-soc-server/static/agent.js"
//           data-site="gov-portal-001"
//           data-key="your-api-key"></script>
//
// It silently collects request metadata and reports to the SOC backend.
// No UI changes, no cookies, < 5 KB.
// =============================================================================

(function () {
  "use strict";

  // ---- Read config from script tag ----
  var scriptTag = document.currentScript ||
    (function () {
      var tags = document.getElementsByTagName("script");
      return tags[tags.length - 1];
    })();

  var SITE_ID  = scriptTag.getAttribute("data-site") || "unknown";
  var API_KEY  = scriptTag.getAttribute("data-key")  || "";
  var SOC_URL  = scriptTag.src.replace(/\/static\/agent\.js.*/, "");
  var ENDPOINT = SOC_URL + "/api/agent/report";

  // ---- Queue ----
  var eventQueue = [];
  var sending    = false;

  // ---- Helpers ----
  function getVisitorIP(cb) {
    // Use a public API to get the visitor's public IP
    fetch("https://api.ipify.org?format=json")
      .then(function (r) { return r.json(); })
      .then(function (d) { cb(d.ip || "0.0.0.0"); })
      .catch(function ()  { cb("0.0.0.0"); });
  }

  function buildPayload(overrides) {
    return Object.assign({
      site_id    : SITE_ID,
      api_key    : API_KEY,
      ip         : window.__socAgentIP || "0.0.0.0",
      method     : "GET",
      path       : window.location.pathname + window.location.search,
      referer    : document.referrer || "",
      user_agent : navigator.userAgent,
      bytes_in   : 0,
      timestamp  : new Date().toISOString(),
    }, overrides);
  }

  function enqueue(payload) {
    eventQueue.push(payload);
    if (!sending) flushQueue();
  }

  function flushQueue() {
    if (eventQueue.length === 0) { sending = false; return; }
    sending = true;
    var payload = eventQueue.shift();

    fetch(ENDPOINT, {
      method : "POST",
      headers: { "Content-Type": "application/json" },
      body   : JSON.stringify(payload),
      keepalive: true,
    })
      .catch(function () { /* fail silently */ })
      .finally(function () { flushQueue(); });
  }

  // ---- Intercept fetch ----
  var _origFetch = window.fetch;
  window.fetch = function (input, init) {
    var method = (init && init.method) || "GET";
    var url    = (typeof input === "string") ? input : (input.url || "");
    var bytes  = 0;
    if (init && init.body) {
      try { bytes = (new TextEncoder().encode(init.body)).length; } catch (_) {}
    }
    // Only report same-origin requests
    if (url.indexOf("http") !== 0 || url.indexOf(window.location.origin) === 0) {
      enqueue(buildPayload({ method: method.toUpperCase(), path: url, bytes_in: bytes }));
    }
    return _origFetch.apply(this, arguments);
  };

  // ---- Intercept XMLHttpRequest ----
  var _origOpen = XMLHttpRequest.prototype.open;
  var _origSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (method, url) {
    this._socMethod = method;
    this._socUrl    = url;
    return _origOpen.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function (body) {
    var bytes = 0;
    if (body) {
      try { bytes = (typeof body === "string" ? body : JSON.stringify(body)).length; } catch (_) {}
    }
    var url = this._socUrl || "";
    if (!url || url.indexOf("http") !== 0 || url.indexOf(window.location.origin) === 0) {
      enqueue(buildPayload({
        method  : (this._socMethod || "GET").toUpperCase(),
        path    : url || window.location.pathname,
        bytes_in: bytes,
      }));
    }
    return _origSend.apply(this, arguments);
  };

  // ---- Page load event ----
  function reportPageLoad() {
    enqueue(buildPayload({
      method  : "GET",
      path    : window.location.pathname + window.location.search,
      bytes_in: 0,
    }));
  }

  // ---- Form submit events (capture POST-like actions) ----
  document.addEventListener("submit", function (e) {
    var form   = e.target;
    var method = (form.method || "GET").toUpperCase();
    var action = form.action || window.location.href;
    var bytes  = 0;
    try {
      var fd = new FormData(form);
      var qs = new URLSearchParams(fd).toString();
      bytes  = qs.length;
    } catch (_) {}
    enqueue(buildPayload({ method: method, path: action, bytes_in: bytes }));
  }, true);

  // ---- Init: get IP then report page load ----
  getVisitorIP(function (ip) {
    window.__socAgentIP = ip;
    reportPageLoad();
  });

  // ---- Periodic heartbeat every 30s ----
  setInterval(function () {
    enqueue(buildPayload({ method: "HEARTBEAT", path: window.location.pathname }));
  }, 30000);

})();
