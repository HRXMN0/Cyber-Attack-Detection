// =============================================================================
// script.js — SOC Dashboard Logic
// Live Feed + Site Monitor + Tab switching + realistic simulation
// =============================================================================

// Dynamic base URL — works on localhost AND on any deployed domain (Render, etc.)
const BASE_URL   = window.location.origin;
const API        = BASE_URL + "/dashboard";
const SITES_API  = BASE_URL + "/api/sites";
const LOGS_API   = BASE_URL + "/api/agent/logs";
const POLL_MS    = 5000;
// Admin key — must match SOC_ADMIN_KEY env var on the server
const ADMIN_KEY  = "soc-admin-secret-change-me";


// ---- State ----
let prevEventCount = 0;
let soundEnabled   = true;
let alertTimeout   = null;
let attackChart    = null;
let sevChart       = null;
let lineChart      = null;
let siteCountryChart = null;
let sitePathChart    = null;
let lineData       = [];
let packetSeqNum   = 10000 + Math.floor(Math.random() * 50000);
let activeSiteId   = "";
let activeTab      = "live";

// ---- DOM refs ----
let dom = {};

// ---- Realistic data pools ----
const COUNTRIES = [
  { code: "CN", flag: "🇨🇳", name: "China" },
  { code: "RU", flag: "🇷🇺", name: "Russia" },
  { code: "US", flag: "🇺🇸", name: "United States" },
  { code: "BR", flag: "🇧🇷", name: "Brazil" },
  { code: "IN", flag: "🇮🇳", name: "India" },
  { code: "DE", flag: "🇩🇪", name: "Germany" },
  { code: "KP", flag: "🇰🇵", name: "North Korea" },
  { code: "IR", flag: "🇮🇷", name: "Iran" },
  { code: "UA", flag: "🇺🇦", name: "Ukraine" },
  { code: "NG", flag: "🇳🇬", name: "Nigeria" },
];
const ATTACK_SIGNATURES = {
  "neptune":     { sig: "SYN flood — TCP flags: [SYN] repeated",          port: 80,   proto: "TCP" },
  "portsweep":   { sig: "Sequential port scan — ICMP unreachable replies",  port: 22,   proto: "ICMP" },
  "smurf":       { sig: "ICMP amplification — broadcast echo requests",     port: 0,    proto: "ICMP" },
  "satan":       { sig: "SATAN scan — probing well-known service ports",    port: 111,  proto: "UDP" },
  "ipsweep":     { sig: "Horizontal sweep — ARP requests across /24 range", port: 0,    proto: "ICMP" },
  "back":        { sig: "Apache URL overflow — malformed GET request",      port: 80,   proto: "TCP" },
  "warezclient": { sig: "FTP data exfiltration — large outbound transfer",  port: 21,   proto: "TCP" },
  "teardrop":    { sig: "Fragmented packet overlap — IP offset exploit",    port: 0,    proto: "UDP" },
  "pod":         { sig: "Ping of Death — oversize ICMP > 65535 bytes",      port: 0,    proto: "ICMP" },
  "nmap":        { sig: "Nmap stealth scan — TCP SYN half-open",            port: 443,  proto: "TCP" },
  "bruteforce":  { sig: "Credential stuffing — 500+ auth attempts/min",     port: 22,   proto: "TCP" },
  "normal":      { sig: "Benign request — no anomaly detected",             port: 443,  proto: "TCP" },
};
const REALISTIC_IPS = [
  "218.92.0.142","185.220.101.47","194.165.16.73","45.153.160.2",
  "89.163.252.230","104.244.76.52","62.210.115.87","5.188.206.44",
  "167.94.138.53","45.155.205.210","37.120.247.33","2.56.57.67",
];
const COMMON_PORTS = [21,22,23,25,53,80,110,135,139,143,443,445,3306,3389,8080,6379];
const TERMINAL_BACKGROUND_MESSAGES = [
  () => `IDS Engine: Inspecting packet seq=${++packetSeqNum} — TTL=${64+Math.floor(Math.random()*64)} len=${Math.floor(Math.random()*1400+64)} bytes`,
  () => `Firewall: iptables ACCEPT rule matched — src ${randIP()} via eth0`,
  () => `NetFilter: Connection tracking table ${Math.floor(Math.random()*12000+3000)}/65535 entries`,
  () => `BGP: Received UPDATE from AS${Math.floor(Math.random()*65000+1000)} — ${Math.floor(Math.random()*20+1)} new prefixes`,
  () => `SSL/TLS: Handshake completed — TLSv1.3 with ECDHE-RSA-AES256-GCM-SHA384`,
  () => `IDS Engine: Flow analytics updated — ${Math.floor(Math.random()*900+100)} flows/sec baseline`,
  () => `SIEM: Correlation rule #${Math.floor(Math.random()*9000+1000)} evaluated — no match`,
  () => `DNS: Resolved ${randDomain()} → ${randIP()} (TTL 300s)`,
  () => `ML Model: Feature vector scored — confidence ${(Math.random()*10+89).toFixed(2)}%`,
  () => `GeoIP: Lookup ${randIP()} → ${COUNTRIES[Math.floor(Math.random()*COUNTRIES.length)].name} (AS${Math.floor(Math.random()*65000)})`,
  () => `WAF: Request inspected — ModSecurity score 0/${Math.floor(Math.random()*5)} — PASS`,
  () => `PCAP: Captured ${Math.floor(Math.random()*500+100)} packets — buffer ${Math.floor(Math.random()*80+10)}% full`,
  () => `Rate-limiter: ${randIP()} — ${Math.floor(Math.random()*200+50)} req/min — within threshold`,
  () => `Entropy check: Payload randomness ${(Math.random()*0.4+0.5).toFixed(3)} bits/byte — benign`,
];
const SIMULATED_ALERT_EVENTS = [
  { type: "warn",  msg: (ip) => `Port scan detected — ${ip} probed ${Math.floor(Math.random()*200+50)} ports in ${(Math.random()*3+0.5).toFixed(1)}s` },
  { type: "warn",  msg: (ip) => `Unusual user-agent: 'python-requests/2.28' from ${ip} — possible bot` },
  { type: "error", msg: (ip) => `SYN flood threshold exceeded — ${ip} sent ${Math.floor(Math.random()*5000+1000)} SYN/s` },
  { type: "warn",  msg: (ip) => `Geo anomaly: ${ip} — new country origin (${COUNTRIES[Math.floor(Math.random()*COUNTRIES.length)].name})` },
  { type: "error", msg: (ip) => `Payload matched CVE-2021-44228 (Log4Shell) signature — src ${ip}` },
  { type: "warn",  msg: (ip) => `Repeated 404 errors (${Math.floor(Math.random()*100+20)}) from ${ip} — directory traversal suspected` },
  { type: "error", msg: (ip) => `SQL injection pattern detected in POST body — src ${ip}` },
  { type: "error", msg: (ip) => `XSS payload detected in GET param '?q=' from ${ip}` },
  { type: "warn",  msg: (ip) => `ICMP flood — ${ip} sending ${Math.floor(Math.random()*10000+1000)} pings/s` },
];

// ---- Utils ----
function randIP()    { return REALISTIC_IPS[Math.floor(Math.random()*REALISTIC_IPS.length)]; }
function randPort()  { return COMMON_PORTS[Math.floor(Math.random()*COMMON_PORTS.length)]; }
function randDomain(){ const t=["com","net","org","io","ru","cn"],w=["update","cdn","api","mail","proxy"]; return w[Math.floor(Math.random()*w.length)]+Math.floor(Math.random()*99)+"."+t[Math.floor(Math.random()*t.length)]; }
function randCountry(){ return COUNTRIES[Math.floor(Math.random()*COUNTRIES.length)]; }
function fmtBytes(b){ if(b>=1048576) return (b/1048576).toFixed(1)+" MB"; if(b>=1024) return (b/1024).toFixed(1)+" KB"; return b+" B"; }

// ---- Audio ----
function playAlertBeep() {
  if (!soundEnabled) return;
  try {
    const ctx=new(window.AudioContext||window.webkitAudioContext)(),osc=ctx.createOscillator(),gain=ctx.createGain();
    osc.type="square";osc.frequency.setValueAtTime(880,ctx.currentTime);osc.frequency.setValueAtTime(660,ctx.currentTime+0.1);osc.frequency.setValueAtTime(880,ctx.currentTime+0.2);
    gain.gain.setValueAtTime(0.15,ctx.currentTime);gain.gain.exponentialRampToValueAtTime(0.001,ctx.currentTime+0.4);
    osc.connect(gain).connect(ctx.destination);osc.start();osc.stop(ctx.currentTime+0.4);
  } catch(_){}
}

// ---- Theme ----
function toggleTheme() {
  const html=document.documentElement,next=html.getAttribute("data-theme")==="light"?"dark":"light";
  html.setAttribute("data-theme",next);dom.themeBtn.textContent=next==="light"?"🌙":"☀️";localStorage.setItem("soc-theme",next);
}
function initTheme() {
  const saved=localStorage.getItem("soc-theme")||"dark";
  document.documentElement.setAttribute("data-theme",saved);dom.themeBtn.textContent=saved==="light"?"🌙":"☀️";
}
function toggleSound(){ soundEnabled=!soundEnabled;dom.soundBtn.textContent=soundEnabled?"🔊":"🔇"; }

// ---- Severity helpers ----
function sevClass(s){ return s?s.toLowerCase().replace(/\s/g,""):"none"; }
function sevOrder(s){ return{none:0,low:1,medium:2,high:3,critical:4}[sevClass(s)]||0; }
function maxSeverity(logs){ let mx=0;for(const e of logs)mx=Math.max(mx,sevOrder(e.severity));return["None","Low","Medium","High","Critical"][mx]; }
function fmtTime(ts){ if(!ts)return"—"; try{const d=new Date(ts);return d.toLocaleTimeString([],{hour:"2-digit",minute:"2-digit",second:"2-digit"});}catch{return ts;} }

// ---- Tab switching ----
function switchTab(tabId) {
  activeTab = tabId;
  document.querySelectorAll(".tab-btn").forEach(b => b.classList.toggle("active", b.dataset.tab === tabId));
  document.querySelectorAll(".tab-content").forEach(c => c.classList.toggle("active", c.id === "tab-"+tabId));
  if (tabId === "sites") pollSites();
}

// ---- Render: Live Feed ----
function renderStats(data) {
  const logs=data.attack_log||[],totalEvents=data.total_events||logs.length;
  const attacks=logs.filter(e=>sevClass(e.severity)!=="none").length;
  const blockedCount=(data.blocked_ips||[]).length,threat=maxSeverity(logs);
  dom.statEvents.textContent=totalEvents;dom.statAttacks.textContent=attacks;
  dom.statBlocked.textContent=blockedCount;dom.statThreat.textContent=threat;
  dom.statThreat.className="value sev-"+sevClass(threat);
  const pct={None:5,Low:20,Medium:45,High:70,Critical:95}[threat]||5;
  const color={None:"var(--neon-green)",Low:"var(--sev-low)",Medium:"var(--neon-yellow)",High:"var(--neon-orange)",Critical:"var(--neon-red)"}[threat]||"var(--neon-green)";
  dom.threatFill.style.width=pct+"%";dom.threatFill.style.background=color;dom.threatFill.style.boxShadow="0 0 14px "+color;
  const underAttack=sevOrder(threat)>=3;
  dom.statusBadge.className="status-badge"+(underAttack?" danger":"");
  dom.statusText.textContent=underAttack?"⚠ UNDER ATTACK":"System Secure";
}

function renderTable(logs) {
  const tbody=dom.tableBody,fragment=document.createDocumentFragment();
  const display=[...logs].reverse().slice(0,100);
  for(const e of display){
    const tr=document.createElement("tr"),sev=sevClass(e.severity),isBlocked=sev==="critical"||sev==="high";
    const ipHash=(e.ip||"").split("").reduce((a,c)=>a+c.charCodeAt(0),0);
    const country=COUNTRIES[ipHash%COUNTRIES.length];
    const sig=ATTACK_SIGNATURES[(e.attack||"normal").toLowerCase()]||ATTACK_SIGNATURES["normal"];
    const port=sig.port||COMMON_PORTS[ipHash%COMMON_PORTS.length];
    const bytes=fmtBytes((ipHash*137%900+64)*1024);
    tr.innerHTML=`<td>${fmtTime(e.timestamp)}</td><td class="ip">${e.ip||"—"}</td><td title="${sig.sig}">${e.attack||"—"}</td><td><span class="sev-badge ${sev}">${e.severity||"—"}</span></td><td class="mono">${country.flag} ${country.code} · ${sig.proto}:${port}</td><td class="mono">${bytes}</td><td><span class="status-chip ${isBlocked?"blocked-chip":"allowed-chip"}">${isBlocked?"🚫 Blocked":"✅ Allowed"}</span></td>`;
    fragment.appendChild(tr);
  }
  tbody.innerHTML="";tbody.appendChild(fragment);
  if(tbody.firstChild)tbody.firstChild.classList.add("new-row");
}

function renderBlockedIPs(ips) {
  const list=dom.blockedList;
  if(!ips||ips.length===0){list.innerHTML='<div class="empty-state"><div class="icon">🛡️</div>No blocked IPs</div>';return;}
  list.innerHTML=ips.map(ip=>{
    const ipHash=ip.split("").reduce((a,c)=>a+c.charCodeAt(0),0);
    const country=COUNTRIES[ipHash%COUNTRIES.length];
    const port=COMMON_PORTS[ipHash%COMMON_PORTS.length];
    return`<div class="blocked-ip-item"><span class="dot"></span><span>${country.flag} <strong>${ip}</strong></span><span class="blocked-meta">port ${port} · ${country.name}</span></div>`;
  }).join("");
}

// ---- Terminal ----
function addTerminalLog(text, type="info") {
  const ts=new Date().toLocaleTimeString([],{hour:"2-digit",minute:"2-digit",second:"2-digit"});
  const line=document.createElement("div");
  line.className="log-line "+type;
  line.innerHTML=`<span class="ts">[${ts}]</span> <span class="tag">[${type.toUpperCase()}]</span> ${text}`;
  dom.terminal.appendChild(line);dom.terminal.scrollTop=dom.terminal.scrollHeight;
  while(dom.terminal.children.length>300)dom.terminal.removeChild(dom.terminal.firstChild);
}

// ---- Packet stream ----
function spawnPacketLine() {
  if(!dom.packetStream)return;
  const ip=randIP(),dport=randPort(),sport=Math.floor(Math.random()*60000+1025);
  const ttl=Math.floor(Math.random()*64+64),len=Math.floor(Math.random()*1400+64);
  const proto=Math.random()>0.3?"TCP":"UDP";
  const flags=proto==="TCP"?["[SYN]","[ACK]","[PSH ACK]","[FIN ACK]","[RST]"][Math.floor(Math.random()*5)]:"";
  const line=document.createElement("div");
  line.className="pkt-line";
  line.textContent=`${ip}:${sport} → 10.0.0.1:${dport}  ${proto} ${flags}  seq=${++packetSeqNum} TTL=${ttl} len=${len}`;
  dom.packetStream.appendChild(line);dom.packetStream.scrollTop=dom.packetStream.scrollHeight;
  while(dom.packetStream.children.length>80)dom.packetStream.removeChild(dom.packetStream.firstChild);
}

// ---- Charts ----
function initCharts() {
  const barCtx=document.getElementById("attackChart").getContext("2d");
  attackChart=new Chart(barCtx,{type:"bar",data:{labels:[],datasets:[{label:"Occurrences",data:[],backgroundColor:[],borderRadius:6,barThickness:28}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{ticks:{color:"#8892b0",font:{size:11}},grid:{display:false}},y:{ticks:{color:"#8892b0",stepSize:1},grid:{color:"rgba(255,255,255,0.04)"}}}}});
  const pieCtx=document.getElementById("sevChart").getContext("2d");
  sevChart=new Chart(pieCtx,{type:"doughnut",data:{labels:["None","Low","Medium","High","Critical"],datasets:[{data:[0,0,0,0,0],backgroundColor:["#00ff88","#66bb6a","#ffd600","#ff9100","#ff1744"],borderWidth:0,hoverOffset:8}]},options:{responsive:true,maintainAspectRatio:false,cutout:"62%",plugins:{legend:{position:"bottom",labels:{color:"#8892b0",padding:14,font:{size:11}}}}}});
  const lineEl=document.getElementById("trafficChart");
  if(lineEl){lineData=Array.from({length:20},()=>Math.floor(Math.random()*300+100));lineChart=new Chart(lineEl.getContext("2d"),{type:"line",data:{labels:lineData.map(()=>""),datasets:[{label:"Packets/s",data:lineData,borderColor:"#00e5ff",backgroundColor:"rgba(0,229,255,0.08)",borderWidth:2,pointRadius:0,tension:0.4,fill:true}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{display:false},y:{ticks:{color:"#8892b0",font:{size:10}},grid:{color:"rgba(255,255,255,0.04)"}}},animation:{duration:400}}});}
  // Site charts
  const scEl=document.getElementById("siteCountryChart");
  if(scEl){siteCountryChart=new Chart(scEl.getContext("2d"),{type:"bar",data:{labels:[],datasets:[{label:"Attacks",data:[],backgroundColor:"#00e5ff",borderRadius:4,barThickness:20}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{ticks:{color:"#8892b0",font:{size:10}},grid:{display:false}},y:{ticks:{color:"#8892b0",stepSize:1},grid:{color:"rgba(255,255,255,0.04)"}}}}});}
  const spEl=document.getElementById("sitePathChart");
  if(spEl){sitePathChart=new Chart(spEl.getContext("2d"),{type:"bar",data:{labels:[],datasets:[{label:"Hits",data:[],backgroundColor:"#d500f9",borderRadius:4,barThickness:20}]},options:{indexAxis:"y",responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{ticks:{color:"#8892b0",font:{size:10}},grid:{color:"rgba(255,255,255,0.04)"}},y:{ticks:{color:"#8892b0",font:{size:10}},grid:{display:false}}}}});}
}

function updateCharts(logs) {
  const typeCounts={};
  for(const e of logs){const t=e.attack||"unknown";typeCounts[t]=(typeCounts[t]||0)+1;}
  const sorted=Object.entries(typeCounts).sort((a,b)=>b[1]-a[1]).slice(0,10);
  const barColors=sorted.map(([t])=>{const s=logs.find(e=>e.attack===t)?.severity;return{None:"#00ff88",Low:"#66bb6a",Medium:"#ffd600",High:"#ff9100",Critical:"#ff1744"}[s]||"#00e5ff";});
  attackChart.data.labels=sorted.map(e=>e[0]);attackChart.data.datasets[0].data=sorted.map(e=>e[1]);attackChart.data.datasets[0].backgroundColor=barColors;attackChart.update("none");
  const sevCounts={None:0,Low:0,Medium:0,High:0,Critical:0};
  for(const e of logs)sevCounts[e.severity]=(sevCounts[e.severity]||0)+1;
  sevChart.data.datasets[0].data=[sevCounts.None,sevCounts.Low,sevCounts.Medium,sevCounts.High,sevCounts.Critical];sevChart.update("none");
  if(lineChart){const v=Math.floor(Math.random()*400+80);lineData.push(v);lineData.shift();lineChart.data.datasets[0].data=[...lineData];lineChart.update("none");}
}

// ---- Alerts ----
function showAlert(msg){ dom.alertText.textContent=msg;dom.alertBanner.classList.add("show");playAlertBeep();clearTimeout(alertTimeout);alertTimeout=setTimeout(()=>dom.alertBanner.classList.remove("show"),6000); }
function dismissAlert(){ dom.alertBanner.classList.remove("show");clearTimeout(alertTimeout); }

// ---- Background simulation ----
function runBackgroundSimulation() {
  const msgFn=TERMINAL_BACKGROUND_MESSAGES[Math.floor(Math.random()*TERMINAL_BACKGROUND_MESSAGES.length)];
  addTerminalLog(msgFn(),"info");
  if(Math.random()<0.35){const ev=SIMULATED_ALERT_EVENTS[Math.floor(Math.random()*SIMULATED_ALERT_EVENTS.length)];addTerminalLog(ev.msg(randIP()),ev.type);}
}

// ---- Site Monitor ----
async function pollSites() {
  try {
    const res  = await fetch(SITES_API);
    const sites= await res.json();

    // Render site cards
    const cards = document.getElementById("siteCards");
    if (!cards) return;
    if (!sites || sites.length === 0) {
      cards.innerHTML = '<div class="empty-state"><div class="icon">🌐</div>No sites registered</div>';
      return;
    }
    cards.innerHTML = sites.map(s => {
      const threatClass = s.total_attacks > 10 ? "critical" : s.total_attacks > 3 ? "high" : s.total_attacks > 0 ? "medium" : "safe";
      return `<div class="site-card ${threatClass}" onclick="selectSite('${s.id}')">
        <div class="site-card-name">🌐 ${s.name}</div>
        <div class="site-card-url">${s.url}</div>
        <div class="site-card-stats">
          <span class="site-stat events">${s.total_events} events</span>
          <span class="site-stat attacks">${s.total_attacks} attacks</span>
        </div>
        <div class="site-card-id">ID: ${s.id}</div>
      </div>`;
    }).join("");

    // Populate site select
    const sel = document.getElementById("siteSelect");
    if(sel){
      const cur = sel.value;
      sel.innerHTML = '<option value="">— Select a site —</option>' +
        sites.map(s => `<option value="${s.id}" ${s.id===cur?"selected":""}>${s.name}</option>`).join("");
    }
  } catch(e) { console.error("pollSites:", e); }
}

function selectSite(siteId) {
  activeSiteId = siteId;
  const sel = document.getElementById("siteSelect");
  if(sel) sel.value = siteId;
  pollSiteLogs();
}

async function pollSiteLogs() {
  const siteId = activeSiteId || document.getElementById("siteSelect")?.value;
  if(!siteId) return;
  activeSiteId = siteId;

  const badge = document.getElementById("siteBadge");
  if(badge) badge.textContent = "Loading…";

  try {
    const res  = await fetch(LOGS_API + "?site_id=" + encodeURIComponent(siteId), {
      headers: { "X-Admin-Key": ADMIN_KEY }
    });
    const data = await res.json();
    const logs = data.attack_log || [];

    if(badge) badge.textContent = logs.length + " events";

    renderSiteTable(logs);
    updateSiteCharts(logs);
  } catch(e) {
    console.error("pollSiteLogs:", e);
    if(badge) badge.textContent = "Error";
  }
}

function renderSiteTable(logs) {
  const tbody = document.getElementById("siteTableBody");
  if(!tbody) return;
  if(!logs.length){
    tbody.innerHTML='<tr><td colspan="10" class="empty-state"><div class="icon">🌐</div>No events for this site yet</td></tr>';
    return;
  }
  const COUNTRY_FLAGS = {CN:"🇨🇳",RU:"🇷🇺",US:"🇺🇸",BR:"🇧🇷",IN:"🇮🇳",DE:"🇩🇪",KP:"🇰🇵",IR:"🇮🇷",UA:"🇺🇦",NG:"🇳🇬"};
  const fragment = document.createDocumentFragment();
  for(const e of logs){
    const tr=document.createElement("tr"),sev=sevClass(e.severity),isBlocked=sev==="critical"||sev==="high";
    const flag=COUNTRY_FLAGS[e.country]||"🌐";
    const ua=(e.user_agent||"—").substring(0,40)+(e.user_agent&&e.user_agent.length>40?"…":"");
    const path=(e.path||"/").substring(0,30)+(e.path&&e.path.length>30?"…":"");
    const bytes=e.bytes_in?fmtBytes(e.bytes_in):"—";
    tr.innerHTML=`
      <td>${fmtTime(e.timestamp)}</td>
      <td class="ip">${e.ip||"—"}</td>
      <td>${e.attack||"—"}</td>
      <td><span class="sev-badge ${sev}">${e.severity||"—"}</span></td>
      <td class="mono">${e.method||"GET"} <span style="color:#00e5ff">${path}</span></td>
      <td>${flag} ${e.country||"—"} ${e.city?'<span class="mono">('+e.city+')</span>':""}</td>
      <td class="mono">${e.asn||"—"}</td>
      <td class="mono" title="${e.user_agent||""}">${ua}</td>
      <td class="mono">${bytes}</td>
      <td><span class="status-chip ${isBlocked?"blocked-chip":"allowed-chip"}">${isBlocked?"🚫 Blocked":"✅ Allowed"}</span></td>`;
    fragment.appendChild(tr);
  }
  tbody.innerHTML="";tbody.appendChild(fragment);
  if(tbody.firstChild)tbody.firstChild.classList.add("new-row");
}

function updateSiteCharts(logs) {
  if(!siteCountryChart||!sitePathChart) return;
  // Top countries
  const cc={};for(const e of logs){const c=e.country||"??";cc[c]=(cc[c]||0)+1;}
  const byCC=Object.entries(cc).sort((a,b)=>b[1]-a[1]).slice(0,8);
  const COUNTRY_FLAGS={CN:"🇨🇳",RU:"🇷🇺",US:"🇺🇸",BR:"🇧🇷",IN:"🇮🇳",DE:"🇩🇪",KP:"🇰🇵",IR:"🇮🇷",UA:"🇺🇦",NG:"🇳🇬"};
  siteCountryChart.data.labels=byCC.map(([c])=>(COUNTRY_FLAGS[c]||"🌐")+" "+c);
  siteCountryChart.data.datasets[0].data=byCC.map(e=>e[1]);siteCountryChart.update("none");
  // Top paths
  const pp={};for(const e of logs){const p=(e.path||"/").split("?")[0];pp[p]=(pp[p]||0)+1;}
  const byPath=Object.entries(pp).sort((a,b)=>b[1]-a[1]).slice(0,8);
  sitePathChart.data.labels=byPath.map(([p])=>p.substring(0,25));
  sitePathChart.data.datasets[0].data=byPath.map(e=>e[1]);sitePathChart.update("none");
}

// ---- Main Poll ----
async function poll() {
  try {
    const res=await fetch(API);if(!res.ok)throw new Error("HTTP "+res.status);
    const data=await res.json();const logs=data.attack_log||[];const newCount=data.total_events||logs.length;
    renderStats(data);renderTable(logs);renderBlockedIPs(data.blocked_ips);updateCharts(logs);
    if(newCount>prevEventCount){
      const newLogs=logs.slice(prevEventCount);
      for(const e of newLogs){
        const sev=sevClass(e.severity),logType=sev==="critical"||sev==="high"?"error":sev==="medium"?"warn":sev==="none"?"ok":"info";
        const sig=ATTACK_SIGNATURES[(e.attack||"normal").toLowerCase()]||ATTACK_SIGNATURES["normal"];
        const country=COUNTRIES[(e.ip||"0.0.0.0").split("").reduce((a,c)=>a+c.charCodeAt(0),0)%COUNTRIES.length];
        addTerminalLog(`[${sig.proto}:${sig.port}] ${e.attack} from ${e.ip} (${country.flag} ${country.name}) — ${e.severity} — ${sig.sig}`,logType);
        if(sev==="critical")showAlert(`🚨 CRITICAL: ${e.attack} from ${e.ip} (${country.flag}) — IP auto-blocked`);
        else if(sev==="high")showAlert(`⚠️ HIGH: ${e.attack} from ${e.ip} — temporary block applied`);
      }
      prevEventCount=newCount;
    }
    addTerminalLog(`Dashboard synced — ${newCount} total events — ${(data.blocked_ips||[]).length} blocked IPs`,"ok");
    // If site monitor is active, refresh it too
    if(activeTab==="sites" && activeSiteId) pollSiteLogs();
  } catch(err){ addTerminalLog("⛔ Backend unreachable — "+err.message+" — retrying in "+(POLL_MS/1000)+"s","error"); }
}

// ---- Init ----
document.addEventListener("DOMContentLoaded",()=>{
  dom={
    statEvents:document.getElementById("statEvents"),statAttacks:document.getElementById("statAttacks"),
    statBlocked:document.getElementById("statBlocked"),statThreat:document.getElementById("statThreat"),
    threatFill:document.getElementById("threatFill"),statusBadge:document.getElementById("statusBadge"),
    statusText:document.getElementById("statusText"),tableBody:document.getElementById("attackTableBody"),
    blockedList:document.getElementById("blockedList"),terminal:document.getElementById("terminal"),
    alertBanner:document.getElementById("alertBanner"),alertText:document.getElementById("alertText"),
    themeBtn:document.getElementById("themeToggle"),soundBtn:document.getElementById("soundToggle"),
    packetStream:document.getElementById("packetStream"),
  };
  dom.themeBtn.addEventListener("click",toggleTheme);
  dom.soundBtn.addEventListener("click",toggleSound);
  document.getElementById("alertClose").addEventListener("click",dismissAlert);
  // Tab buttons
  document.querySelectorAll(".tab-btn").forEach(btn=>btn.addEventListener("click",()=>switchTab(btn.dataset.tab)));
  // Site select
  const sel=document.getElementById("siteSelect");
  if(sel)sel.addEventListener("change",()=>{activeSiteId=sel.value;if(activeSiteId)pollSiteLogs();});

  initTheme();initCharts();

  // Load current user info into header
  fetch(BASE_URL + "/api/me").then(r=>r.json()).then(u=>{
    const nameEl = document.getElementById("userNameDisplay");
    const roleEl = document.getElementById("userRoleDisplay");
    if(nameEl) nameEl.textContent = u.name || "Analyst";
    if(roleEl) roleEl.textContent = (u.role || "analyst").toUpperCase();
  }).catch(()=>{});

  addTerminalLog("SOC Dashboard v2.0 initializing...","ok");
  addTerminalLog("Loading ML model: attack_model.pkl — RandomForest (500 estimators)","info");
  addTerminalLog("Database connected: SQLite @ ./cyber_attacks.db","info");
  addTerminalLog("Agent endpoint active: POST /api/agent/report","info");
  addTerminalLog("Snort rules loaded: 28,412 signatures","info");
  addTerminalLog("GeoIP database: GeoLite2-City.mmdb — 3.1M entries","info");
  setTimeout(()=>addTerminalLog("All systems operational — monitoring started","ok"),800);

  poll();
  setInterval(poll,POLL_MS);
  setInterval(runBackgroundSimulation,2500);
  setInterval(spawnPacketLine,400);
});
