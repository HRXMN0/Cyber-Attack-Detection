// =============================================================================
// AI CYBER SOC — Next-Gen 3D Dashboard Engine
// Three.js Globe | 2D Network Graph | AI Terminal | Live Feed | Auto-Defense
// =============================================================================

'use strict';

const BASE_URL  = window.location.origin;
const API       = BASE_URL + '/dashboard';
const SITES_API = BASE_URL + '/api/sites';
const POLL_MS   = 5000;

// ── Attacker country coordinates ────────────────────────────────────────────
const ATTACKERS = [
  { name:'China',       cc:'CN', flag:'🇨🇳', lat:35.86,  lon:104.19, color:'#ff4444', attacks:0 },
  { name:'Russia',      cc:'RU', flag:'🇷🇺', lat:61.52,  lon:105.31, color:'#ff6600', attacks:0 },
  { name:'North Korea', cc:'KP', flag:'🇰🇵', lat:40.33,  lon:127.51, color:'#ff2222', attacks:0 },
  { name:'Iran',        cc:'IR', flag:'🇮🇷', lat:32.42,  lon:53.68,  color:'#ff8800', attacks:0 },
  { name:'Ukraine',     cc:'UA', flag:'🇺🇦', lat:49.38,  lon:31.16,  color:'#ffaa00', attacks:0 },
  { name:'Brazil',      cc:'BR', flag:'🇧🇷', lat:-14.23, lon:-51.92, color:'#ff5500', attacks:0 },
  { name:'Nigeria',     cc:'NG', flag:'🇳🇬', lat:9.08,   lon:8.67,   color:'#ff3300', attacks:0 },
  { name:'USA',         cc:'US', flag:'🇺🇸', lat:37.09,  lon:-95.71, color:'#ffcc00', attacks:0 },
  { name:'Germany',     cc:'DE', flag:'🇩🇪', lat:51.16,  lon:10.45,  color:'#ff7700', attacks:0 },
  { name:'Vietnam',     cc:'VN', flag:'🇻🇳', lat:14.05,  lon:108.27, color:'#ff4400', attacks:0 },
];
const TARGET = { lat:28.6, lon:77.2, name:'Target Server (IND)' };

// ── Attack types & simulation data ──────────────────────────────────────────
const ATTACK_TYPES = ['neptune','portsweep','smurf','satan','ipsweep','back','bruteforce','nmap','teardrop','pod','normal'];
const ATTACK_SIGS  = {
  neptune:     'SYN flood — TCP [SYN] repeated',
  portsweep:   'Sequential port scan detected',
  smurf:       'ICMP amplification — broadcast echo',
  satan:       'SATAN scan — probing services',
  ipsweep:     'Horizontal sweep across /24',
  back:        'Apache URL overflow — GET overflow',
  bruteforce:  'Credential stuffing — 500+/min',
  nmap:        'Nmap stealth SYN half-open scan',
  teardrop:    'Fragmented packet IP offset exploit',
  pod:         'Ping of Death — ICMP >65535 bytes',
  normal:      'Benign request — no anomaly',
};
const REALISTIC_IPS = [
  '218.92.0.142','185.220.101.47','194.165.16.73','45.153.160.2',
  '89.163.252.230','104.244.76.52','62.210.115.87','5.188.206.44',
  '167.94.138.53','45.155.205.210','37.120.247.33','2.56.57.67',
];
const sevOrder = { none:0, low:1, medium:2, high:3, critical:4 };
const sevColor = { none:'#8892b0', low:'#64dd17', medium:'#ffd600', high:'#ff6d00', critical:'#ff1744' };

// ── State ────────────────────────────────────────────────────────────────────
let soundEnabled   = true;
let simRunning     = true;
let intensity      = 2;
let attackCount    = 0;
let blockedCount   = 0;
let prevDBCount    = 0;
let trafficHistory = Array(30).fill(0);
let sevCounts      = { none:0, low:0, medium:0, high:0, critical:0 };
let globe, netGraph, aiTerm, packetStream, trafficChartObj, sevChartObj;

// ─────────────────────────────────────────────────────────────────────────────
// GLOBE ENGINE
// ─────────────────────────────────────────────────────────────────────────────
class GlobeEngine {
  constructor(canvas) {
    this.canvas   = canvas;
    this.arcs     = [];
    this.rings    = [];
    this.drag     = false;
    this.rotY     = 0.4;
    this.rotX     = 0.15;
    this.targetRotY = 0.4;
    this.zoom     = 4.0;
    this.clock    = new THREE.Clock();
    this.markerDots = [];
    this.targetDot  = null;
    this.init();
  }

  init() {
    this.renderer = new THREE.WebGLRenderer({ canvas: this.canvas, antialias: true, alpha: true });
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    this.renderer.setClearColor(0x000000, 0);

    this.scene  = new THREE.Scene();
    this.camera = new THREE.PerspectiveCamera(45, 1, 0.1, 100);
    this.camera.position.set(0, 0, this.zoom);

    this.group = new THREE.Group();
    this.scene.add(this.group);

    this.addLights();
    this.buildGlobe();
    this.buildAtmosphere();
    this.buildStars();
    this.buildMarkers();
    this.setupMouse();
    this.resize();
    window.addEventListener('resize', () => this.resize());
    this.animate();
  }

  addLights() {
    this.scene.add(new THREE.AmbientLight(0x223355, 1.2));
    const sun = new THREE.DirectionalLight(0x4488ff, 1.8);
    sun.position.set(5, 3, 5);
    this.scene.add(sun);
    const fill = new THREE.DirectionalLight(0x001133, 0.5);
    fill.position.set(-5, -3, -5);
    this.scene.add(fill);
  }

  buildGlobe() {
    const geo = new THREE.SphereGeometry(1.5, 64, 64);
    this.earthMat = new THREE.MeshPhongMaterial({
      color: 0x0c1a2e, emissive: 0x040e1f,
      specular: 0x1a4488, shininess: 20,
    });
    this.earth = new THREE.Mesh(geo, this.earthMat);
    this.group.add(this.earth);

    // Try loading Earth texture
    const loader = new THREE.TextureLoader();
    loader.load(
      'https://cdn.jsdelivr.net/gh/mrdoob/three.js@r128/examples/textures/planets/earth_atmos_2048.jpg',
      tex => { this.earthMat.map = tex; this.earthMat.needsUpdate = true; },
      undefined,
      () => {} // fallback: keep dark color
    );

    // Major wireframe grid (lat/lon lines)
    const wGeo = new THREE.SphereGeometry(1.502, 36, 36);
    this.group.add(new THREE.Mesh(wGeo, new THREE.MeshBasicMaterial({ color:0x0a3a6a, wireframe:true, transparent:true, opacity:0.1 })));

    // Fine wireframe overlay
    const wGeo2 = new THREE.SphereGeometry(1.504, 72, 72);
    this.group.add(new THREE.Mesh(wGeo2, new THREE.MeshBasicMaterial({ color:0x00e5ff, wireframe:true, transparent:true, opacity:0.025 })));
  }

  buildAtmosphere() {
    // Outer glow (back-face, additive)
    const aOuter = new THREE.Mesh(
      new THREE.SphereGeometry(1.65, 32, 32),
      new THREE.MeshPhongMaterial({ color:0x2277ff, side:THREE.BackSide, transparent:true, opacity:0.13 })
    );
    this.scene.add(aOuter); // not in group — doesn't rotate

    // Inner rim glow
    const aInner = new THREE.Mesh(
      new THREE.SphereGeometry(1.55, 32, 32),
      new THREE.MeshBasicMaterial({ color:0x0066ff, transparent:true, opacity:0.04 })
    );
    this.scene.add(aInner);
  }

  buildStars() {
    const N = 2500;
    const pos = new Float32Array(N * 3);
    for (let i = 0; i < N * 3; i++) pos[i] = (Math.random() - 0.5) * 120;
    const geo = new THREE.BufferGeometry();
    geo.setAttribute('position', new THREE.BufferAttribute(pos, 3));
    const mat = new THREE.PointsMaterial({ color:0xffffff, size:0.04, transparent:true, opacity:0.55 });
    this.scene.add(new THREE.Points(geo, mat));
  }

  ll2v(lat, lon, r = 1.52) {
    const phi   = (90 - lat)  * Math.PI / 180;
    const theta = (lon + 180) * Math.PI / 180;
    return new THREE.Vector3(
      -r * Math.sin(phi) * Math.cos(theta),
       r * Math.cos(phi),
       r * Math.sin(phi) * Math.sin(theta)
    );
  }

  buildMarkers() {
    ATTACKERS.forEach(a => {
      const pos = this.ll2v(a.lat, a.lon, 1.53);
      const dot = new THREE.Mesh(
        new THREE.SphereGeometry(0.013, 8, 8),
        new THREE.MeshBasicMaterial({ color: new THREE.Color(a.color) })
      );
      dot.position.copy(pos);
      this.group.add(dot);
      this.markerDots.push({ dot, attacker: a });
    });

    // Target (our server) — glowing cyan
    const tPos = this.ll2v(TARGET.lat, TARGET.lon, 1.535);
    this.targetDot = new THREE.Mesh(
      new THREE.SphereGeometry(0.022, 8, 8),
      new THREE.MeshBasicMaterial({ color: 0x00ffff })
    );
    this.targetDot.position.copy(tPos);
    this.group.add(this.targetDot);
  }

  spawnArc(attackerIdx, severity='high') {
    const a = ATTACKERS[attackerIdx % ATTACKERS.length];
    const start = this.ll2v(a.lat, a.lon);
    const end   = this.ll2v(TARGET.lat, TARGET.lon);
    const mid   = start.clone().add(end).multiplyScalar(0.5).normalize().multiplyScalar(2.5);
    const curve = new THREE.QuadraticBezierCurve3(start, mid, end);

    const color = new THREE.Color(a.color);
    const lineMat = new THREE.LineBasicMaterial({ color, transparent:true, opacity:0.85 });
    const line = new THREE.Line(
      new THREE.BufferGeometry().setFromPoints([start]),
      lineMat
    );
    this.group.add(line);

    // Particle at front
    const partMat = new THREE.MeshBasicMaterial({ color });
    const particle = new THREE.Mesh(new THREE.SphereGeometry(0.016, 8, 8), partMat);
    this.group.add(particle);

    // Pulse ring at attacker origin
    this.spawnPulseAt(start, a.color);

    const arc = { curve, line, lineMat, particle, attacker:a, progress:0, speed: 0.18 + Math.random()*0.18, done:false };
    this.arcs.push(arc);
    a.attacks++;
    document.getElementById('globeActiveArcs').textContent = this.arcs.length;
    return arc;
  }

  spawnPulseAt(pos, color) {
    const ring = new THREE.Mesh(
      new THREE.RingGeometry(0.01, 0.02, 12),
      new THREE.MeshBasicMaterial({ color: new THREE.Color(color), transparent:true, opacity:1, side:THREE.DoubleSide })
    );
    ring.position.copy(pos);
    ring.lookAt(new THREE.Vector3(0,0,0));
    this.group.add(ring);
    this.rings.push({ ring, mat: ring.material, age:0, maxAge:1.2, type:'launch' });
  }

  spawnImpactRing(pos, color) {
    for (let i = 0; i < 3; i++) {
      const ring = new THREE.Mesh(
        new THREE.RingGeometry(0.01, 0.025, 16),
        new THREE.MeshBasicMaterial({ color: new THREE.Color(color), transparent:true, opacity:1-i*0.25, side:THREE.DoubleSide })
      );
      ring.position.copy(pos);
      ring.lookAt(new THREE.Vector3(0,0,0));
      this.group.add(ring);
      this.rings.push({ ring, mat:ring.material, age: i*0.15, maxAge:1.0+i*0.2, type:'impact', delay:i*0.12 });
    }
  }

  updateArcs(dt) {
    this.arcs = this.arcs.filter(arc => {
      arc.progress = Math.min(arc.progress + dt * arc.speed, 1);
      const t = arc.progress;
      // Grow line
      const pts = arc.curve.getPoints(Math.max(2, Math.floor(t * 60)));
      arc.line.geometry.dispose();
      arc.line.geometry = new THREE.BufferGeometry().setFromPoints(pts);
      arc.lineMat.opacity = t < 0.85 ? 0.85 : 0.85 * (1 - (t-0.85)/0.15);
      // Move particle
      arc.particle.position.copy(arc.curve.getPoint(t));
      if (t >= 1) {
        this.spawnImpactRing(arc.particle.position.clone(), '#' + arc.attacker.color.replace('#',''));
        this.group.remove(arc.line);
        this.group.remove(arc.particle);
        arc.line.geometry.dispose();
        arc.done = true;
        this.onImpact(arc.attacker);
        return false;
      }
      return true;
    });
    document.getElementById('globeActiveArcs').textContent = this.arcs.length;
  }

  updateRings(dt) {
    this.rings = this.rings.filter(r => {
      if (r.delay && r.delay > 0) { r.delay -= dt; return true; }
      r.age += dt;
      const t = r.age / r.maxAge;
      r.ring.scale.setScalar(1 + t * (r.type==='impact' ? 5 : 3));
      r.mat.opacity = Math.max(0, 1 - t);
      if (t >= 1) { this.group.remove(r.ring); r.ring.geometry.dispose(); return false; }
      return true;
    });
  }

  onImpact(attacker) {
    // Show impact flash
    const al = document.getElementById('impactAlert');
    const it = document.getElementById('impactText');
    it.textContent = `${attacker.flag} ${attacker.name.toUpperCase()} — ATTACK BLOCKED`;
    al.classList.add('show');
    setTimeout(() => al.classList.remove('show'), 1800);
    // Screen shake on high-severity
    document.body.classList.add('shaking');
    setTimeout(() => document.body.classList.remove('shaking'), 500);
    // Update top attacker
    const top = ATTACKERS.reduce((a, b) => a.attacks > b.attacks ? a : b);
    document.getElementById('globeTopAttacker').textContent = top.flag + ' ' + top.cc;
    const unique = ATTACKERS.filter(a => a.attacks > 0).length;
    document.getElementById('globeCountries').textContent = unique;
    // Firewall flash
    showFirewall(attacker.name);
  }

  setupMouse() {
    let px=0, py=0;
    this.canvas.addEventListener('mousedown', e => { this.drag=true; px=e.clientX; py=e.clientY; });
    window.addEventListener('mouseup',   () => { this.drag=false; });
    window.addEventListener('mousemove', e => {
      if (!this.drag) return;
      const dx=e.clientX-px, dy=e.clientY-py; px=e.clientX; py=e.clientY;
      this.rotY += dx*0.006;
      this.rotX  = Math.max(-1.2, Math.min(1.2, this.rotX + dy*0.006));
    });
    this.canvas.addEventListener('wheel', e => {
      this.zoom = Math.max(2.8, Math.min(7, this.zoom + e.deltaY*0.004));
    }, { passive:true });
  }

  resize() {
    const c = this.canvas.parentElement;
    const w = c.clientWidth, h = c.clientHeight;
    this.renderer.setSize(w, h);
    this.camera.aspect = w/h;
    this.camera.updateProjectionMatrix();
  }

  animate() {
    const loop = () => {
      requestAnimationFrame(loop);
      const dt = this.clock.getDelta();
      const t  = this.clock.getElapsedTime();
      if (!this.drag) this.rotY += dt * 0.04;
      this.group.rotation.y = this.rotY;
      this.group.rotation.x = this.rotX;
      this.camera.position.set(0, 0, this.zoom);
      if (this.targetDot) this.targetDot.scale.setScalar(1 + 0.35*Math.sin(t*3));
      this.updateArcs(dt);
      this.updateRings(dt);
      this.renderer.render(this.scene, this.camera);
    };
    loop();
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2D NETWORK GRAPH
// ─────────────────────────────────────────────────────────────────────────────
class NetworkGraph {
  constructor(canvas) {
    this.canvas = canvas;
    this.ctx    = canvas.getContext('2d');
    this.nodes  = [];
    this.edges  = [];
    this.t      = 0;
    this.init();
  }

  init() {
    const { width: W, height: H } = this.resize();
    const NODE_DEFS = [
      { id:'fw',    label:'Firewall',   type:'firewall', x:W/2,    y:H*0.22 },
      { id:'rt',    label:'Router',     type:'router',   x:W/2,    y:H*0.5  },
      { id:'srv1',  label:'WebSrv',     type:'server',   x:W*0.25, y:H*0.65 },
      { id:'srv2',  label:'DB',         type:'server',   x:W*0.75, y:H*0.65 },
      { id:'srv3',  label:'API',        type:'server',   x:W*0.5,  y:H*0.82 },
      { id:'atk1',  label:'Atk-1',      type:'attacker', x:W*0.1,  y:H*0.08 },
      { id:'atk2',  label:'Atk-2',      type:'attacker', x:W*0.9,  y:H*0.08 },
      { id:'bot1',  label:'Bot',        type:'bot',      x:W*0.15, y:H*0.38 },
      { id:'bot2',  label:'Bot',        type:'bot',      x:W*0.85, y:H*0.38 },
      { id:'cl1',   label:'Client-1',   type:'client',   x:W*0.2,  y:H*0.88 },
      { id:'cl2',   label:'Client-2',   type:'client',   x:W*0.8,  y:H*0.88 },
    ];
    const COLOR = { firewall:'#00e5ff', router:'#aa00ff', server:'#00ff88', attacker:'#ff1744', bot:'#ff6d00', client:'#8892b0' };
    this.nodes = NODE_DEFS.map(n => ({
      ...n, vx:0, vy:0, threat:0,
      color: COLOR[n.type],
      baseX: n.x, baseY: n.y
    }));
    this.edges = [
      ['fw','rt','normal'],['fw','atk1','attack'],['fw','atk2','attack'],
      ['rt','srv1','normal'],['rt','srv2','normal'],['rt','srv3','normal'],
      ['bot1','fw','attack'],['bot2','fw','attack'],
      ['cl1','srv1','normal'],['cl2','srv2','normal'],
    ];
    this.animate();
  }

  resize() {
    this.canvas.width  = this.canvas.offsetWidth;
    this.canvas.height = this.canvas.offsetHeight;
    return { width: this.canvas.width, height: this.canvas.height };
  }

  getNode(id) { return this.nodes.find(n => n.id === id); }

  animate() {
    const loop = () => {
      requestAnimationFrame(loop);
      this.t += 0.016;
      this.draw();
    };
    loop();
  }

  draw() {
    const ctx = this.ctx;
    const W = this.canvas.width, H = this.canvas.height;
    ctx.clearRect(0, 0, W, H);

    // Draw edges
    this.edges.forEach(([aId, bId, type]) => {
      const a = this.getNode(aId), b = this.getNode(bId);
      if (!a || !b) return;
      const isAttack = type === 'attack';
      const pulse    = 0.4 + 0.6 * Math.abs(Math.sin(this.t * (isAttack ? 4 : 1.5)));
      ctx.beginPath();
      ctx.moveTo(a.x, a.y);
      ctx.lineTo(b.x, b.y);
      ctx.strokeStyle = isAttack ? `rgba(255,23,68,${pulse*0.6})` : `rgba(0,229,255,${pulse*0.3})`;
      ctx.lineWidth   = isAttack ? 1.2 : 0.8;
      ctx.stroke();
      // Animated packet dot along edge
      const prog = (this.t * (isAttack ? 1.8 : 0.8) % 1);
      const dx = b.x, dy = b.y, sx = a.x, sy = a.y;
      ctx.beginPath();
      ctx.arc(sx + (dx-sx)*prog, sy+(dy-sy)*prog, 2, 0, Math.PI*2);
      ctx.fillStyle = isAttack ? 'rgba(255,23,68,0.9)' : 'rgba(0,229,255,0.7)';
      ctx.fill();
    });

    // Draw nodes
    this.nodes.forEach(n => {
      const r   = n.type === 'firewall' ? 10 : (n.type === 'router' ? 8 : 6);
      const thr = n.threat > 0 ? Math.abs(Math.sin(this.t * 5)) : 0;
      ctx.beginPath();
      ctx.arc(n.x, n.y, r + thr*3, 0, Math.PI*2);
      ctx.fillStyle   = n.color + '22';
      ctx.strokeStyle = n.color;
      ctx.lineWidth   = 1.5;
      ctx.fill();
      ctx.stroke();
      // Glow  
      ctx.shadowColor = n.color;
      ctx.shadowBlur  = 8 + thr*12;
      ctx.beginPath();
      ctx.arc(n.x, n.y, r*0.5, 0, Math.PI*2);
      ctx.fillStyle = n.color + 'aa';
      ctx.fill();
      ctx.shadowBlur = 0;
      // Label
      ctx.fillStyle = 'rgba(136,146,176,0.8)';
      ctx.font      = '8px Share Tech Mono, monospace';
      ctx.textAlign = 'center';
      ctx.fillText(n.label, n.x, n.y + r + 10);
    });
  }

  setNodeThreat(nodeId, level) {
    const n = this.getNode(nodeId);
    if (n) n.threat = level;
  }

  flashAttack() {
    ['fw','atk1','atk2','bot1','bot2'].forEach((id, i) => {
      setTimeout(() => { this.setNodeThreat(id, 1); }, i * 60);
      setTimeout(() => { this.setNodeThreat(id, 0); }, 1500 + i*60);
    });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// AI TERMINAL
// ─────────────────────────────────────────────────────────────────────────────
class AITerminal {
  constructor(el) {
    this.el    = el;
    this.queue = [];
    this.busy  = false;
    this.MAX   = 80;
    this.bootMessages();
  }

  bootMessages() {
    const boot = [
      ['ok',   'SOC Dashboard v3.0 — Next-Gen Command Center initializing...'],
      ['info', 'Loading RandomForest ML model: attack_model.pkl (500 estimators)'],
      ['info', 'Database connected: SQLite @ ./cyber_attacks.db'],
      ['info', 'Three.js Globe Engine v1.0 — 3D radar initialized'],
      ['info', 'Snort IDS rules loaded: 28,412 signatures'],
      ['info', 'GeoIP database: GeoLite2-City.mmdb — 3.1M entries'],
      ['info', 'Firewall: iptables rules active (1,247 entries)'],
      ['ok',   'All systems OPERATIONAL — real-time monitoring ACTIVE'],
    ];
    boot.forEach(([lvl, msg], i) => {
      setTimeout(() => this.add(lvl, msg), 400 + i * 180);
    });
  }

  add(level, message, glitch = false) {
    this.queue.push({ level, message, glitch });
    if (!this.busy) this.flush();
  }

  flush() {
    if (!this.queue.length) { this.busy = false; return; }
    this.busy = true;
    const { level, message, glitch } = this.queue.shift();
    this.render(level, message, glitch);
    setTimeout(() => this.flush(), 60);
  }

  render(level, message, glitch) {
    const line = document.createElement('div');
    line.className = `term-line ${level}` + (glitch ? ' glitch' : '');
    const now  = new Date();
    const ts   = now.toTimeString().split(' ')[0];
    const lvlMap = { ok:'[ OK ]', info:'[INFO]', warn:'[WARN]', error:'[ERR!]', ai:'[AI ] ' };
    line.innerHTML =
      `<span class="term-time">${ts}</span>` +
      `<span class="term-lvl ${level}">${lvlMap[level]||'[LOG]'}</span>` +
      `<span class="term-msg">${message}</span>`;
    this.el.appendChild(line);
    // Trim old
    while (this.el.children.length > this.MAX) this.el.removeChild(this.el.firstChild);
    this.el.scrollTop = this.el.scrollHeight;
  }

  logAttack(ip, type, severity, action) {
    const glitch = severity === 'critical' || severity === 'high';
    this.add('warn',  `Incoming: ${ip} — attack_type=${type} severity=${severity}`, false);
    this.add('ai',    `ML analyzing: feature vector scored — confidence ${(88+Math.random()*11).toFixed(1)}%`, false);
    this.add('ai',    `Prediction: ${type.toUpperCase()} | Risk: ${severity.toUpperCase()}`, false);
    if (action === 'blocked' || severity === 'critical') {
      this.add('error', `AUTO-DEFENSE: IP ${ip} → QUARANTINED. Firewall rule added.`, glitch);
    } else {
      this.add('ok', `Action: MONITOR — ${ip} flagged for analysis`, false);
    }
  }

  logStatus(msg) { this.add('info', msg); }
}

// ─────────────────────────────────────────────────────────────────────────────
// PACKET STREAM
// ─────────────────────────────────────────────────────────────────────────────
class PacketStream {
  constructor(el) {
    this.el  = el;
    this.MAX = 40;
    this.seq = 10000 + Math.floor(Math.random() * 50000);
  }

  add(ip, type, severity, bytes, proto, port) {
    const cat   = severity === 'none' ? 'normal' : (severity === 'low' || severity === 'medium' ? 'suspicious' : 'attack');
    const icon  = { normal:'🟢', suspicious:'🟡', attack:'🔴' }[cat];
    const pkt   = document.createElement('div');
    pkt.className = `packet ${cat}`;
    pkt.innerHTML =
      `<span class="pkt-type">${icon}</span>` +
      `<span class="pkt-ip">${ip}</span>` +
      `<span class="pkt-info">${proto}:${port} seq=${++this.seq} ${type}</span>` +
      `<span class="pkt-bytes">${bytes}</span>`;
    this.el.prepend(pkt);
    while (this.el.children.length > this.MAX) this.el.removeChild(this.el.lastChild);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// SOUND ENGINE
// ─────────────────────────────────────────────────────────────────────────────
class SoundEngine {
  constructor() { this.ctx = null; }

  getCtx() {
    if (!this.ctx) this.ctx = new (window.AudioContext || window.webkitAudioContext)();
    return this.ctx;
  }

  beep(freq=880, dur=0.15, vol=0.08, type='sine') {
    if (!soundEnabled) return;
    try {
      const ctx = this.getCtx();
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = type; osc.frequency.value = freq;
      gain.gain.setValueAtTime(vol, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + dur);
      osc.connect(gain).connect(ctx.destination);
      osc.start(); osc.stop(ctx.currentTime + dur);
    } catch(_) {}
  }

  alarm() {
    [880, 0.06, 660, 0.06, 880, 0.06].forEach((v, i) => {
      if (i % 2 === 0) setTimeout(() => this.beep(v, 0.08, 0.12, 'square'), Math.floor(i/2)*120);
    });
  }

  success() { this.beep(1200, 0.1, 0.06, 'sine'); }
}

// ─────────────────────────────────────────────────────────────────────────────
// CHARTS
// ─────────────────────────────────────────────────────────────────────────────
function initCharts() {
  const baseOpts = { animation:{ duration:400 }, responsive:true, maintainAspectRatio:false };
  const gridOpt  = { color:'rgba(255,255,255,0.05)' };

  // Traffic line chart
  trafficChartObj = new Chart(document.getElementById('trafficChart'), {
    type: 'line', data: {
      labels: trafficHistory.map((_, i) => ''),
      datasets:[{ label:'Requests/s', data:[...trafficHistory],
        borderColor:'#00e5ff', backgroundColor:'rgba(0,229,255,0.08)',
        borderWidth:1.5, fill:true, tension:0.4, pointRadius:0,
      }],
    },
    options: { ...baseOpts, plugins:{ legend:{ display:false } },
      scales:{ x:{ display:false }, y:{ grid:gridOpt, ticks:{ color:'#4a6080', font:{size:8} }, border:{ display:false } } },
    },
  });

  // Severity doughnut
  sevChartObj = new Chart(document.getElementById('sevChart'), {
    type: 'doughnut', data: {
      labels:['None','Low','Medium','High','Critical'],
      datasets:[{ data:[1,0,0,0,0],
        backgroundColor:['#4a608044','#64dd1744','#ffd60044','#ff6d0044','#ff174444'],
        borderColor:    ['#4a6080','#64dd17','#ffd600','#ff6d00','#ff1744'],
        borderWidth: 1.5,
      }],
    },
    options: { ...baseOpts, cutout:'68%',
      plugins:{ legend:{ display:false }, tooltip:{ callbacks:{ label: ctx => ` ${ctx.label}: ${ctx.raw}` } } },
    },
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// UI HELPERS
// ─────────────────────────────────────────────────────────────────────────────
function showToast(msg, type = 'info', dur = 3500) {
  const tc = document.getElementById('toastContainer');
  const t  = document.createElement('div');
  t.className = `toast ${type}`;
  t.textContent = msg;
  tc.appendChild(t);
  setTimeout(() => { t.style.animation = 'toastOut .3s ease forwards'; setTimeout(() => t.remove(), 300); }, dur);
}

function showFirewall(attackerName) {
  const fw  = document.getElementById('fwOverlay');
  const msg = document.getElementById('fwMsg');
  msg.textContent = `${attackerName.toUpperCase()} — IP BLOCKED SUCCESSFULLY`;
  fw.classList.add('show');
  setTimeout(() => fw.classList.remove('show'), 1600);
}

function fmtTime(ts) {
  if (!ts) return '—';
  try { return new Date(ts).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit'}); }
  catch { return ts; }
}

function fmtBytes(b) {
  if (b >= 1048576) return (b/1048576).toFixed(1)+' MB';
  if (b >= 1024)    return (b/1024).toFixed(1)+' KB';
  return b+' B';
}

function randFrom(arr) { return arr[Math.floor(Math.random()*arr.length)]; }

function sevClass(s) { return (s||'none').toLowerCase().replace(/\s/g,''); }

// ─────────────────────────────────────────────────────────────────────────────
// DASHBOARD DATA UPDATER
// ─────────────────────────────────────────────────────────────────────────────
const PROTOCOLS = ['TCP','UDP','ICMP','HTTP','HTTPS','DNS','SMTP'];
const PORTS     = [21,22,23,25,53,80,110,135,139,143,443,445,3306,3389,8080];
const ATTACK_SIGS_SHORT = { neptune:'SYN Flood', portsweep:'Port Scan', smurf:'ICMP Amp', satan:'SATAN Scan', ipsweep:'IP Sweep', back:'Apache OVF', bruteforce:'Brute Force', nmap:'Nmap Scan', teardrop:'Teardrop', pod:'Ping of Death', normal:'Normal' };

function updateDashboard(data) {
  const logs     = data.attack_log || [];
  const blocked  = data.blocked_ips || [];
  const total    = data.total_events || 0;
  const attacks  = logs.filter(e => sevClass(e.severity) !== 'none').length;
  blockedCount   = blocked.length;

  // Header quick stats
  document.getElementById('hdrEvents').textContent  = total;
  document.getElementById('hdrAttacks').textContent = attacks;
  document.getElementById('hdrBlocked').textContent = blockedCount;

  // New events since last poll → spawn globe arcs
  const newCount = total - prevDBCount;
  prevDBCount = total;
  if (newCount > 0) {
    for (let i = 0; i < Math.min(newCount, 3); i++) {
      const idx = Math.floor(Math.random() * ATTACKERS.length);
      globe.spawnArc(idx);
    }
  }

  // Threat level
  let maxSev = 'none';
  logs.forEach(e => { if (sevOrder[sevClass(e.severity)] > sevOrder[maxSev]) maxSev = sevClass(e.severity); });
  updateThreatLevel(maxSev, attacks);

  // Update attack table (last 40 events)
  updateTable(logs.slice(-40).reverse());

  // Blocked IPs
  updateBlockedList(blocked);

  // Update sev counts for doughnut
  sevCounts = { none:0, low:0, medium:0, high:0, critical:0 };
  logs.forEach(e => { const s = sevClass(e.severity); if (sevCounts[s] !== undefined) sevCounts[s]++; });
  sevChartObj.data.datasets[0].data = [sevCounts.none, sevCounts.low, sevCounts.medium, sevCounts.high, sevCounts.critical];
  sevChartObj.update('none');

  // Traffic history
  trafficHistory.push(Math.max(1, newCount));
  if (trafficHistory.length > 30) trafficHistory.shift();
  trafficChartObj.data.datasets[0].data = [...trafficHistory];
  trafficChartObj.update('none');

  // AI panel
  if (logs.length > 0) {
    const latest = logs[logs.length - 1];
    updateAIPanel(latest);
  }

  // Count badge
  document.getElementById('blockedCount').textContent = blockedCount;
}

function updateThreatLevel(sev, attackCount) {
  const pct    = { none:3, low:20, medium:45, high:70, critical:95 }[sev] || 3;
  const color  = { none:'#00ff88', low:'#64dd17', medium:'#ffd600', high:'#ff6d00', critical:'#ff1744' }[sev] || '#00ff88';
  const label  = sev.toUpperCase();
  const el     = document.querySelector('.attack-status');
  const tf     = document.getElementById('threatFill');
  const tt     = document.getElementById('threatText');
  const sl     = document.getElementById('statusLabel');

  tf.style.width      = pct+'%';
  tf.style.background = color;
  tf.style.boxShadow  = `0 0 12px ${color}`;
  tt.textContent = label;
  tt.style.color = color;

  if (sev === 'critical' || sev === 'high') {
    el.classList.add('danger');
    document.getElementById('statusIcon').textContent = '▲';
    sl.textContent = '⚠ UNDER ATTACK';
    document.getElementById('socHeader').style.boxShadow = `0 0 30px rgba(255,23,68,0.25)`;
  } else {
    el.classList.remove('danger');
    document.getElementById('statusIcon').textContent = '●';
    sl.textContent = 'SYSTEM SECURE';
    document.getElementById('socHeader').style.boxShadow = '';
  }
}

function updateTable(logs) {
  const tbody = document.getElementById('attackTableBody');
  if (!logs.length) { tbody.innerHTML = '<tr><td colspan="5" class="empty-row">No events yet…</td></tr>'; return; }

  const frag = document.createDocumentFragment();
  logs.forEach((e, idx) => {
    const tr   = document.createElement('tr');
    if (idx === 0) tr.classList.add('new-row');
    const sev  = sevClass(e.severity);
    const isBlocked = sev === 'critical' || sev === 'high';
    const ipHash = (e.ip||'').split('').reduce((a,c)=>a+c.charCodeAt(0),0);
    const attacker = ATTACKERS[ipHash % ATTACKERS.length];
    const proto  = PROTOCOLS[ipHash % PROTOCOLS.length];
    const port   = PORTS[ipHash % PORTS.length];
    const bytes  = fmtBytes((ipHash*137%900+64)*1024);
    tr.innerHTML =
      `<td>${fmtTime(e.timestamp)}</td>` +
      `<td>${e.ip||'—'}&nbsp;<span style="font-size:.55rem;color:#4a6080">${attacker.flag}</span></td>` +
      `<td>${ATTACK_SIGS_SHORT[e.attack]||e.attack||'—'}</td>` +
      `<td><span class="sev-badge ${sev}">${e.severity||'—'}</span></td>` +
      `<td><span class="status-chip ${isBlocked?'blocked-chip':'allowed-chip'}">${isBlocked?'🚫 Blocked':'✅ Allow'}</span></td>`;
    frag.appendChild(tr);
  });
  tbody.innerHTML = '';
  tbody.appendChild(frag);
}

function updateBlockedList(ips) {
  const list = document.getElementById('blockedList');
  if (!ips.length) { list.innerHTML = '<div class="empty-state-sm">No blocked IPs</div>'; return; }
  list.innerHTML = ips.slice(-6).reverse().map(ip => {
    const ipHash = ip.split('').reduce((a,c)=>a+c.charCodeAt(0),0);
    const flag   = ATTACKERS[ipHash%ATTACKERS.length].flag;
    return `<div class="blocked-item">
      <span class="bi-icon">🔒</span>
      <span class="bi-ip">${ip}&nbsp;${flag}</span>
      <span class="bi-time">QUARANTINED</span>
    </div>`;
  }).join('');
}

function updateAIPanel(event) {
  const sev  = sevClass(event.severity);
  const conf = (85 + Math.random()*14).toFixed(1)+'%';
  const risk = { none:'MINIMAL', low:'LOW', medium:'ELEVATED', high:'HIGH', critical:'CRITICAL' }[sev] || '—';
  const clr  = sevColor[sev] || '#8892b0';

  document.getElementById('aiScore').textContent = { none:5, low:22, medium:48, high:74, critical:97 }[sev] || 5;
  document.getElementById('aiScore').style.color = clr;
  document.getElementById('aiConfidence').textContent = conf;
  document.getElementById('aiAttackType').textContent = (event.attack||'normal').toUpperCase();
  document.getElementById('aiRiskLevel').textContent  = risk;
  document.getElementById('aiRiskLevel').style.color  = clr;
  document.getElementById('aiResponse').textContent   = sev === 'none' ? 'MONITOR' : sev === 'critical' ? 'AUTO-BLOCK' : 'ANALYZE';

  const pct = { none:5, low:22, medium:48, high:74, critical:97 }[sev] || 5;
  const circ = 213.6;
  document.getElementById('aiRingFill').style.strokeDashoffset = circ - (circ * pct / 100);
  document.getElementById('aiRingFill').style.stroke = clr;

  // Flash thinking animation
  const think = document.getElementById('aiThinking');
  think.classList.add('show');
  setTimeout(() => think.classList.remove('show'), 2000);

  // Update mlBlockStatus
  if (sev === 'critical' || sev === 'high') {
    document.getElementById('mlBlockStatus').textContent = 'ACTIVE';
    document.getElementById('mlBlockStatus').style.color = '#ff1744';
  } else {
    document.getElementById('mlBlockStatus').textContent = 'READY';
    document.getElementById('mlBlockStatus').style.color = '';
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// ATTACK SIMULATION ENGINE
// ─────────────────────────────────────────────────────────────────────────────
class SimEngine {
  constructor() {
    this.running = true;
    this.baseInterval = 2500;
    this.schedule();
    this.bgLoop();
  }

  schedule() {
    const spawn = () => {
      if (this.running) this.spawnAttack();
      const delay = (this.baseInterval / intensity) * (0.6 + Math.random()*0.8);
      setTimeout(spawn, delay);
    };
    setTimeout(spawn, 1500);
  }

  spawnAttack() {
    const idx      = Math.floor(Math.random() * ATTACKERS.length);
    const typeIdx  = Math.floor(Math.random() * ATTACK_TYPES.length);
    const type     = ATTACK_TYPES[typeIdx];
    const isNormal = type === 'normal';
    const sevList  = isNormal ? ['none'] : ['low','medium','high','critical'];
    const sevW     = isNormal ? [1] : [3,4,3,2]; // weighted
    const sev      = this.weightedRand(sevList, sevW);
    const ip       = REALISTIC_IPS[Math.floor(Math.random()*REALISTIC_IPS.length)];
    const port     = PORTS[Math.floor(Math.random()*PORTS.length)];
    const proto    = PROTOCOLS[Math.floor(Math.random()*PROTOCOLS.length)];
    const bytes    = fmtBytes(Math.floor(Math.random()*900+64)*1024);

    // Globe arc
    globe.spawnArc(idx, sev);

    // Packet stream
    packetStream.add(ip, type, sev, bytes, proto, port);

    // Network flash on attack
    if (!isNormal) netGraph.flashAttack();

    // Terminal log
    if (!isNormal) aiTerm.logAttack(ip, type, sev, sev==='critical'?'blocked':'monitor');
    else aiTerm.add('info', `Normal request: ${ip} → ${proto}:${port} — no anomaly`);

    // Sound
    if (sev==='critical' || sev==='high') { sound.alarm(); showToast(`🔴 ${type.toUpperCase()} from ${ip}`, 'danger'); }
    else if (sev==='medium') sound.beep(660, 0.08, 0.06, 'square');
    else sound.beep(880, 0.05);

    // Update attack count stat  
    attackCount++;
    document.getElementById('hdrAttacks').textContent = attackCount;

    // Periodic terminal status messages
    if (Math.random() < 0.15) {
      const msgs = [
        `Firewall: iptables ACCEPT — src ${REALISTIC_IPS[Math.floor(Math.random()*REALISTIC_IPS.length)]} via eth0`,
        `SSL/TLS: Handshake completed — TLSv1.3 ECDHE-RSA-AES256-GCM-SHA384`,
        `GeoIP: ${ATTACKERS[idx].name} → ${ip} (AS${Math.floor(Math.random()*65000)})`,
        `SIEM: Correlation rule #${Math.floor(Math.random()*9000+1000)} — pattern match`,
        `ML Model: batch scored ${Math.floor(Math.random()*200+50)} events — ${(Math.random()*5+1).toFixed(1)}/s`,
      ];
      aiTerm.add('info', randFrom(msgs));
    }
  }

  weightedRand(arr, weights) {
    const total = weights.reduce((a,b)=>a+b,0);
    let r = Math.random()*total;
    for (let i=0;i<arr.length;i++) { r-=weights[i]; if(r<=0) return arr[i]; }
    return arr[arr.length-1];
  }

  bgLoop() {
    // Background packet stream (benign traffic)
    setInterval(() => {
      if (!this.running) return;
      const ip    = REALISTIC_IPS[Math.floor(Math.random()*REALISTIC_IPS.length)];
      const port  = [80,443,53,22][Math.floor(Math.random()*4)];
      const proto = ['HTTP','HTTPS','DNS','SSH'][Math.floor(Math.random()*4)];
      const bytes = fmtBytes(Math.floor(Math.random()*200+10)*1024);
      packetStream.add(ip, 'normal', 'none', bytes, proto, port);
    }, 800);
  }

  toggle() {
    this.running = !this.running;
    const btn = document.getElementById('simToggle');
    btn.textContent = this.running ? '⏸ PAUSE SIM' : '▶ RESUME SIM';
    btn.style.borderColor = this.running ? '' : '#ff1744';
    btn.style.color       = this.running ? '' : '#ff1744';
    showToast(this.running ? '▶ Simulation resumed' : '⏸ Simulation paused', this.running ? 'success' : 'warning');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// MAIN APP
// ─────────────────────────────────────────────────────────────────────────────
let sim, sound;

window.SOC = {
  toggleSim:    () => sim?.toggle(),
  manualBlock:  () => {
    const ip = document.getElementById('manualIp').value.trim();
    if (!ip) { showToast('Enter an IP to block', 'warning'); return; }
    document.getElementById('manualIp').value = '';
    showFirewall(ip);
    showToast(`🔒 ${ip} manually blocked`, 'danger');
    sound.alarm();
    aiTerm.add('error', `MANUAL BLOCK: IP ${ip} → quarantined by operator`, true);
    document.getElementById('hdrBlocked').textContent = ++blockedCount;
    document.getElementById('blockedCount').textContent = blockedCount;
    const list = document.getElementById('blockedList');
    const item = document.createElement('div');
    item.className = 'blocked-item';
    item.innerHTML = `<span class="bi-icon">🔒</span><span class="bi-ip">${ip}</span><span class="bi-time">MANUAL</span>`;
    list.prepend(item);
    if (list.children.length > 6) list.removeChild(list.lastChild);
  }
};

document.addEventListener('DOMContentLoaded', () => {
  // Init globe
  globe = new GlobeEngine(document.getElementById('globeCanvas'));

  // Init network graph
  const nc = document.getElementById('networkCanvas');
  nc.width  = nc.offsetWidth;
  nc.height = nc.offsetHeight;
  netGraph = new NetworkGraph(nc);

  // Init AI terminal
  aiTerm = new AITerminal(document.getElementById('terminalBody'));

  // Init packet stream
  packetStream = new PacketStream(document.getElementById('packetBody'));

  // Sound
  sound = new SoundEngine();

  // Charts
  initCharts();

  // Simulation engine
  intensity = parseInt(document.getElementById('intensitySlider').value);
  document.getElementById('intensitySlider').addEventListener('input', e => {
    intensity = parseInt(e.target.value);
  });
  sim = new SimEngine();

  // Sound toggle
  document.getElementById('soundBtn').addEventListener('click', () => {
    soundEnabled = !soundEnabled;
    document.getElementById('soundBtn').textContent = soundEnabled ? '🔊' : '🔇';
  });

  // Load user info
  fetch(BASE_URL + '/api/me').then(r => r.json()).then(u => {
    document.getElementById('userNameDisplay').textContent = u.name || 'Analyst';
    const role = u.site_id ? u.site_id.toUpperCase() : (u.role||'analyst').toUpperCase();
    document.getElementById('userRoleDisplay').textContent = role;
    if (u.site_id) document.getElementById('userRoleDisplay').style.color = '#00e5ff';
    aiTerm.add('ok', `Authenticated: ${u.name} (${role}) — session active`);
  }).catch(() => {});

  // Poll real DB data
  const pollData = () => {
    fetch(API)
      .then(r => r.ok ? r.json() : null)
      .then(data => { if (data) updateDashboard(data); })
      .catch(() => {});
  };
  pollData();
  setInterval(pollData, POLL_MS);

  // Resize network canvas with container
  window.addEventListener('resize', () => {
    const nc = document.getElementById('networkCanvas');
    nc.width  = nc.offsetWidth;
    nc.height = nc.offsetHeight;
  });

  aiTerm.add('ok', 'Globe engine online — tracking global threat vectors');
});
