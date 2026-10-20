"use strict";

// tlsproxy console.
//
// The Listeners page works like pf-simple's console, one level deeper: listener
// cards (one per open port) hold rule cards, which hold connection rows.
// The server pushes the whole
// state over a WebSocket (api/ws) when something changed, at most once per
// 400ms; api/state is the same frame for the first paint. Local timers only
// repaint (ages, decaying rates, the charts); they never talk to the server.
// Rates per rule and per connection are computed here from byte counters.
//
// Memory stays bounded for a page left open indefinitely: chart history lives
// in fixed-size rings, rate samples are capped by count and age, everything
// kept per connection is deleted when it leaves the pushed state, and at most
// MAX_ROWS rows are in the DOM per rule.
//
// The Certificates, Log and Config file pages fetch their own endpoints while
// they are showing. Strings from the server (names clients sent, log lines,
// patterns from the file) only ever reach the page through textContent.

const $ = (id) => document.getElementById(id);
const RATE_WINDOW_MS = 1500;
const RATE_MAX_SAMPLES = 64;
const HISTORY_POINTS = 120; // two minutes at one sample per second
const MAX_ROWS = 200;
const ARM_MS = 3000;
const TABS = ["rules", "flows", "certs", "ca", "log", "config"];

const ui = {
  state: null,
  csrf: "",
  skew: 0, // local clock minus server clock
  filter: "",
  firstFrame: true,
  tab: "rules",
  expandedL: new Set(), // listener names
  expanded: new Set(), // rule keys
  openConns: new Set(),
  armed: new Map(), // connection id -> disarm timer
  resetting: new Set(),
  L: new Map(), // listener name -> refs
  R: new Map(), // rule key -> refs
  C: new Map(), // connection id -> refs
  meters: new Map(),
  history: new Map(), // "L"+listener name or "R"+rule key -> Ring
  total: null,
  ws: null,
  reconnectTimer: 0,
  retry: 0,
  pageTimer: 0,
};

// ---------- formatting ----------

function fmtBytes(n) {
  const u = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n.toFixed(0) : n.toFixed(n < 10 ? 2 : n < 100 ? 1 : 0)) + " " + u[i];
}

function fmtRate(bytesPerSec) {
  let v = bytesPerSec * 8;
  const u = ["b/s", "Kb/s", "Mb/s", "Gb/s", "Tb/s"];
  let i = 0;
  while (v >= 1000 && i < u.length - 1) { v /= 1000; i++; }
  if (v < 0.5 && i === 0) return "0 b/s";
  return (i === 0 ? v.toFixed(0) : v.toFixed(v < 10 ? 2 : v < 100 ? 1 : 0)) + " " + u[i];
}

// fmtLimit shows a configured speed limit in the units it was written in:
// bits for "1Gbit", decimal bytes for "50MB/s", binary bytes otherwise.
function fmtLimit(bytesPerSec, raw) {
  const unit = String(raw || "").trim().replace(/\/s$/, "").replace(/^[\d.\s]+/, "");
  const short = (v) => String(Number(v.toFixed(2)));
  const scale = (v, base, units) => {
    let i = 0;
    while (v >= base && i < units.length - 1) { v /= base; i++; }
    return `${short(v)} ${units[i]}`;
  };
  if (/bit|bps/i.test(unit) || ["b", "Kb", "Mb", "Gb"].includes(unit)) {
    return scale(bytesPerSec * 8, 1000, ["bit/s", "Kbit/s", "Mbit/s", "Gbit/s", "Tbit/s"]);
  }
  if (/^[kmg]?b$/i.test(unit)) return scale(bytesPerSec, 1000, ["B/s", "KB/s", "MB/s", "GB/s", "TB/s"]);
  return scale(bytesPerSec, 1024, ["B/s", "KiB/s", "MiB/s", "GiB/s", "TiB/s"]);
}

function fmtAge(ms) {
  let s = Math.max(0, Math.floor(ms / 1000));
  const d = Math.floor(s / 86400); s -= d * 86400;
  const h = Math.floor(s / 3600); s -= h * 3600;
  const m = Math.floor(s / 60); s -= m * 60;
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m ${s}s`;
  return `${s}s`;
}

function fmtClock(ms) {
  const d = new Date(ms);
  const time = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  return d.toDateString() === new Date().toDateString() ? time : `${d.toLocaleDateString()} ${time}`;
}

const serverNow = () => Date.now() - ui.skew;

// ---------- bounded data structures ----------

class RateMeter {
  constructor() { this.s = []; }
  add(t, v) {
    const s = this.s;
    if (s.length && v < s[s.length - 1][1]) s.length = 0; // counter restarted
    s.push([t, v]);
    while (s.length > RATE_MAX_SAMPLES || (s.length > 2 && t - s[0][0] > RATE_WINDOW_MS)) s.shift();
  }
  rate(now) {
    const s = this.s;
    while (s.length > 1 && now - s[0][0] > RATE_WINDOW_MS) s.shift();
    if (s.length < 2) return 0;
    const [t0, v0] = s[0];
    const [t1, v1] = s[s.length - 1];
    const dt = Math.max(now, t1) - t0; // keeps growing once pushes stop
    return dt > 0 ? ((v1 - v0) * 1000) / dt : 0;
  }
}

class Ring {
  constructor(n) { this.n = n; this.tx = new Float64Array(n); this.rx = new Float64Array(n); this.len = 0; this.head = 0; }
  push(tx, rx) {
    this.tx[this.head] = tx; this.rx[this.head] = rx;
    this.head = (this.head + 1) % this.n;
    if (this.len < this.n) this.len++;
  }
  at(i) { // 0 = oldest
    const k = (this.head - this.len + i + this.n) % this.n;
    return [this.tx[k], this.rx[k]];
  }
  max() {
    let m = 0;
    for (let i = 0; i < this.len; i++) { const [a, b] = this.at(i); if (a > m) m = a; if (b > m) m = b; }
    return m;
  }
}

function meter(key) {
  let m = ui.meters.get(key);
  if (!m) { m = new RateMeter(); ui.meters.set(key, m); }
  return m;
}

// ---------- DOM helpers ----------

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

function setText(node, text) {
  if (node.textContent !== text) node.textContent = text;
}

const SVG = "http://www.w3.org/2000/svg";
function chevron() {
  const svg = document.createElementNS(SVG, "svg");
  svg.setAttribute("viewBox", "0 0 16 16");
  svg.setAttribute("class", "chev");
  svg.setAttribute("aria-hidden", "true");
  const p = document.createElementNS(SVG, "path");
  p.setAttribute("d", "M6 3.5 10.5 8 6 12.5");
  p.setAttribute("fill", "none");
  p.setAttribute("stroke", "currentColor");
  p.setAttribute("stroke-width", "1.8");
  p.setAttribute("stroke-linecap", "round");
  p.setAttribute("stroke-linejoin", "round");
  svg.appendChild(p);
  return svg;
}

function arrowIcon(dir) {
  const svg = document.createElementNS(SVG, "svg");
  svg.setAttribute("viewBox", "0 0 16 16");
  svg.setAttribute("class", "arrow-icon");
  svg.setAttribute("aria-hidden", "true");
  const p = document.createElementNS(SVG, "path");
  p.setAttribute("d", dir === "up" ? "M8 13V3M3.5 7.5 8 3l4.5 4.5" : "M8 3v10M3.5 8.5 8 13l4.5-4.5");
  p.setAttribute("fill", "none");
  p.setAttribute("stroke", "currentColor");
  p.setAttribute("stroke-width", "1.9");
  p.setAttribute("stroke-linecap", "round");
  p.setAttribute("stroke-linejoin", "round");
  svg.appendChild(p);
  return svg;
}

// metric builds a label/value pair; dir adds an up or down arrow icon.
function metric(label, cls, dir) {
  const box = el("div", "metric " + cls);
  const k = el("span", "k");
  if (dir) k.appendChild(arrowIcon(dir));
  k.appendChild(document.createTextNode(label));
  box.appendChild(k);
  const v = el("span", "v " + cls, "—");
  box.appendChild(v);
  return [box, v];
}

// updown builds the stacked "↑ bytes / ↓ bytes" cell.
function updown(cls) {
  const box = el("span", cls);
  const up = el("span", "up");
  const down = el("span", "down");
  const upV = el("span");
  const downV = el("span");
  up.append(arrowIcon("up"), upV);
  down.append(arrowIcon("down"), downV);
  box.append(up, down);
  return [box, upV, downV];
}

function actionButton(label, cls, icon) {
  const b = el("button", "act " + cls);
  b.type = "button";
  if (icon) b.appendChild(el("span", "ico"));
  const t = el("span", "", label);
  b.appendChild(t);
  return [b, t];
}

// ---------- charts ----------

function tokens() {
  const cs = getComputedStyle(document.documentElement);
  const get = (n) => cs.getPropertyValue(n).trim();
  return { tx: get("--tx"), rx: get("--rx"), line: get("--line"), fg3: get("--fg-3"), font: get("--font-ui") };
}

function fitCanvas(c) {
  const dpr = window.devicePixelRatio || 1;
  const w = Math.max(1, Math.round(c.clientWidth * dpr));
  const h = Math.max(1, Math.round(c.clientHeight * dpr));
  if (c.width !== w || c.height !== h) { c.width = w; c.height = h; }
  const ctx = c.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  return [ctx, c.clientWidth, c.clientHeight];
}

function niceCeil(v) {
  if (v <= 0) return 1;
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}

function plot(ctx, ring, key, color, x0, y0, w, h, max, fill) {
  if (ring.len < 2) return;
  const step = w / (ring.n - 1);
  const start = ring.n - ring.len; // right-align: newest point at the right edge
  ctx.beginPath();
  for (let i = 0; i < ring.len; i++) {
    const v = ring.at(i)[key === "tx" ? 0 : 1];
    const x = x0 + (start + i) * step;
    const y = y0 + h - (v / max) * h;
    if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  }
  ctx.strokeStyle = color;
  ctx.lineWidth = 1.6;
  ctx.lineJoin = "round";
  ctx.stroke();
  if (fill) {
    ctx.lineTo(x0 + w, y0 + h);
    ctx.lineTo(x0 + start * step, y0 + h);
    ctx.closePath();
    ctx.globalAlpha = 0.12;
    ctx.fillStyle = color;
    ctx.fill();
    ctx.globalAlpha = 1;
  }
  const [lt, lr] = ring.at(ring.len - 1);
  const last = key === "tx" ? lt : lr;
  ctx.beginPath();
  ctx.arc(x0 + w, y0 + h - (last / max) * h, 2.6, 0, Math.PI * 2);
  ctx.fillStyle = color;
  ctx.fill();
}

function drawTrace() {
  const c = $("trace");
  if (!c || !ui.total || c.clientWidth === 0) return;
  const [ctx, W, H] = fitCanvas(c);
  const t = tokens();
  ctx.clearRect(0, 0, W, H);
  const max = niceCeil(ui.total.max() * 1.1);
  const left = 64, right = 8, top = 6, bottom = 18;
  const w = W - left - right, h = H - top - bottom;
  ctx.font = `11px ${t.font}`;
  ctx.textBaseline = "middle";
  ctx.textAlign = "right";
  for (let i = 0; i <= 2; i++) {
    const y = top + (h * i) / 2;
    ctx.strokeStyle = t.line;
    ctx.lineWidth = 1;
    ctx.beginPath(); ctx.moveTo(left, Math.round(y) + 0.5); ctx.lineTo(left + w, Math.round(y) + 0.5); ctx.stroke();
    ctx.fillStyle = t.fg3;
    ctx.fillText(fmtRate((max * (2 - i)) / 2), left - 8, y);
  }
  ctx.textAlign = "left";
  ctx.textBaseline = "alphabetic";
  ctx.fillText("2 min ago", left, H - 3);
  ctx.textAlign = "right";
  ctx.fillText("now", left + w, H - 3);
  plot(ctx, ui.total, "rx", t.rx, left, top, w, h, max, true);
  plot(ctx, ui.total, "tx", t.tx, left, top, w, h, max, true);
}

function drawSpark(c, ring) {
  if (!c || c.clientWidth === 0) return;
  const [ctx, W, H] = fitCanvas(c);
  const t = tokens();
  ctx.clearRect(0, 0, W, H);
  ctx.strokeStyle = t.line;
  ctx.lineWidth = 1;
  ctx.beginPath(); ctx.moveTo(0, H - 0.5); ctx.lineTo(W, H - 0.5); ctx.stroke();
  const max = Math.max(ring.max() * 1.15, 1);
  plot(ctx, ring, "rx", t.rx, 2, 3, W - 5, H - 5, max, false);
  plot(ctx, ring, "tx", t.tx, 2, 3, W - 5, H - 5, max, false);
}

// ---------- listener cards ----------

function buildListener(l) {
  const card = el("article", "listener");
  const head = el("div", "l-head");
  head.tabIndex = 0;
  head.setAttribute("role", "button");
  head.setAttribute("aria-expanded", "false");
  head.appendChild(chevron());

  const route = el("div", "route");
  const lname = el("span", "lname");
  const listen = el("span", "listen bracketed");
  const target = el("span", "target");
  const chips = el("span", "chips");
  const status = el("span", "chip warn");
  const redirectChip = el("span", "chip");
  const ppf = el("span", "chip");
  const maxConns = el("span", "chip limit");
  const refused = el("span", "chip bad");
  const hs = el("span", "chip");
  const idle = el("span", "chip");
  const half = el("span", "chip");
  const limTotal = el("span", "chip limit");
  const limConn = el("span", "chip limit");
  chips.append(status, redirectChip, ppf, maxConns, refused, hs, idle, half, limTotal, limConn);
  const line = el("div", "route-line");
  line.append(lname, listen, el("span", "arrow", "→"), target);
  route.append(line, chips);
  head.appendChild(route);

  const spark = el("canvas", "spark");
  spark.setAttribute("aria-hidden", "true");
  head.appendChild(spark);
  const [activeBox, active] = metric("Active", "");
  const [acceptedBox, accepted] = metric("Accepted", "");
  const [txBox, tx] = metric("Rate", "tx", "up");
  const [rxBox, rx] = metric("Rate", "rx", "down");
  head.append(activeBox, acceptedBox, txBox, rxBox);

  const actions = el("div", "l-actions");
  const [toggleBtn, toggleLabel] = actionButton("Stop", "", true);
  const [addBtn] = actionButton("+ Add rule", "add");
  const [editBtn] = actionButton("Edit", "");
  const [delBtn, delLabel] = actionButton("Delete", "danger");
  actions.append(toggleBtn, addBtn, editBtn, delBtn);
  head.appendChild(actions);

  const body = el("div", "lst-body");
  body.hidden = true;
  const err = el("p", "banner bad");
  err.setAttribute("role", "alert");
  err.hidden = true;
  const rules = el("div", "rules");
  const empty = el("div", "empty");
  const sleepy = el("img");
  sleepy.src = "logo-sleep.svg";
  sleepy.alt = "";
  const emptyText = el("span");
  empty.append(sleepy, emptyText);
  body.append(err, rules, empty);

  const toggle = () => {
    if (ui.expandedL.has(l.name)) ui.expandedL.delete(l.name); else ui.expandedL.add(l.name);
    renderAll();
    paint();
  };
  head.addEventListener("click", (ev) => { if (!actions.contains(ev.target)) toggle(); });
  head.addEventListener("keydown", (ev) => {
    if (ev.target !== head) return;
    if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); toggle(); }
  });
  toggleBtn.addEventListener("click", () => onListenerStartStop(l.name));
  addBtn.addEventListener("click", () => openEditor(null, l.name));
  editBtn.addEventListener("click", () => openListenerEditor(ui.L.get(l.name).data));
  delBtn.addEventListener("click", () => onDeleteListener(l.name));

  card.append(head, body);
  return {
    name: l.name, data: l, card, head, lname, listen, target, status, redirectChip, ppf, maxConns, refused, hs, idle, half,
    limTotal, limConn, spark, active, accepted, tx, rx, toggleBtn, toggleLabel, addBtn, editBtn, delBtn, delLabel,
    body, err, rules, empty, sleepy, emptyText,
  };
}

// listenAddrs shows where a listener listens: the open addresses when it
// runs, otherwise bind and port as configured.
function listenAddrs(l) {
  if (l.addrs && l.addrs.length) return l.addrs.join(", ");
  return String(l.bind || "0.0.0.0").split(/[;,]/).map((b) => b.trim()).filter(Boolean)
    .map((b) => (b.includes(":") ? `[${b.replace(/^\[|\]$/g, "")}]:${l.port}` : `${b}:${l.port}`)).join(", ");
}

// ---------- rule cards ----------

function buildRule(r) {
  const card = el("article", "rule");
  const head = el("div", "l-head");
  head.tabIndex = 0;
  head.setAttribute("role", "button");
  head.setAttribute("aria-expanded", "false");
  head.appendChild(chevron());

  const route = el("div", "route");
  const pattern = el("span", "listen");
  const target = el("span", "target");
  const chips = el("span", "chips");
  const status = el("span", "chip warn");
  const active = el("span", "chip");
  const total = el("span", "chip");
  const kind = el("span", "chip");
  const tls = el("span", "chip");
  const proxy = el("span", "chip");
  const limTotal = el("span", "chip limit");
  const limConn = el("span", "chip limit");
  chips.append(status, active, total, kind, tls, proxy, limTotal, limConn);
  const line = el("div", "route-line");
  line.append(pattern, el("span", "arrow", "→"), target);
  route.append(line, chips);
  head.appendChild(route);

  const spark = el("canvas", "spark");
  spark.setAttribute("aria-hidden", "true");
  head.appendChild(spark);
  const [txBox, tx] = metric("Rate", "tx", "up");
  const [rxBox, rx] = metric("Rate", "rx", "down");
  const [upBox, totalUp] = metric("Sent", "tx", "up");
  const [downBox, totalDown] = metric("Sent", "rx", "down");
  head.append(txBox, rxBox, upBox, downBox);

  const actions = el("div", "l-actions");
  const [toggleBtn, toggleLabel] = actionButton("Stop", "", true);
  const [editBtn] = actionButton("Edit", "");
  const [delBtn, delLabel] = actionButton("Delete", "danger");
  actions.append(toggleBtn, editBtn, delBtn);
  head.appendChild(actions);

  const body = el("div", "l-body");
  body.hidden = true;
  const thead = el("div", "t-head cols");
  ["", "ID", "Client", "Host (SNI)", "Age", "State", "To upstream", "To clients", "Transferred", ""].forEach((label, i) => {
    thead.appendChild(el("span", i >= 6 && i <= 8 ? "r" : "", label));
  });
  const empty = el("div", "empty");
  const sleepy = el("img");
  sleepy.src = "logo-sleep.svg";
  sleepy.alt = "";
  const emptyText = el("span");
  empty.append(sleepy, emptyText);
  const more = el("div", "more");
  body.append(thead, empty, more);

  const toggle = () => {
    if (ui.expanded.has(r.key)) ui.expanded.delete(r.key); else ui.expanded.add(r.key);
    renderAll();
    paint();
  };
  head.addEventListener("click", (ev) => { if (!actions.contains(ev.target)) toggle(); });
  head.addEventListener("keydown", (ev) => {
    if (ev.target !== head) return;
    if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); toggle(); }
  });
  toggleBtn.addEventListener("click", () => onStartStop(r.key));
  editBtn.addEventListener("click", () => { const rr = ui.R.get(r.key); openEditor(rr.data, rr.listener.name); });
  delBtn.addEventListener("click", () => onDeleteRule(r.key));

  card.append(head, body);
  return {
    key: r.key, data: r, card, head, pattern, target, status, active, total, kind, tls, proxy, limTotal, limConn,
    spark, tx, rx, totalUp, totalDown, toggleBtn, toggleLabel, editBtn, delBtn, delLabel,
    body, thead, empty, sleepy, emptyText, more, shown: [],
  };
}

// ---------- connection rows ----------

function endpoint(role, cls, sides) {
  const n = el("div", "node " + cls);
  n.appendChild(el("div", "role", role));
  const values = sides.map((side) => {
    const ep = el("div", "ep");
    if (side) ep.appendChild(el("span", "side", side));
    const v = el("span");
    ep.appendChild(v);
    n.appendChild(ep);
    return v;
  });
  return [n, values];
}

function lane(cls, label) {
  const d = el("div", "lane " + cls);
  const bytes = el("span", "bytes", "0 B");
  const wire = el("span", "wire");
  const fin = el("span", "fin-tag");
  if (cls === "tx") d.append(wire, bytes, fin); else d.append(fin, bytes, wire);
  d.title = label;
  return { d, bytes, fin };
}

function fact(dl, label) {
  const row = el("div");
  row.appendChild(el("dt", "", label));
  const dd = el("dd");
  row.appendChild(dd);
  dl.appendChild(row);
  return dd;
}

function buildConn(c) {
  const wrap = el("div", "conn");
  const row = el("div", "p-row cols");
  row.tabIndex = 0;
  row.setAttribute("role", "button");
  row.setAttribute("aria-expanded", "false");
  row.appendChild(chevron());
  const id = el("span", "p-id", "#" + c.id);
  const client = el("span", "p-client");
  const sni = el("span", "p-sni");
  const age = el("span", "p-age");
  const stateCell = el("span", "p-statecell");
  const state = el("span", "state");
  stateCell.appendChild(state);
  const tx = el("span", "p-rate tx r");
  const rx = el("span", "p-rate rx r");
  const [total, totalUp, totalDown] = updown("p-total r");
  const action = el("span", "p-action");
  const stop = el("button", "stop");
  stop.type = "button";
  stop.appendChild(el("span", "sq"));
  const stopLabel = el("span", "", "Stop");
  stop.appendChild(stopLabel);
  stop.title = "Close both legs of this connection";
  action.appendChild(stop);
  row.append(id, client, sni, age, stateCell, tx, rx, total, action);

  const detail = el("div", "detail");
  detail.hidden = true;
  const legs = el("div", "legs");
  const [cNode, [cRemote]] = endpoint("Client", "client", [""]);
  const [hubNode, [hubIn, hubOut]] = endpoint("tlsproxy", "hub", ["in", "out"]);
  const [uNode, [uRemote]] = endpoint("Upstream", "upstream", [""]);
  const legA = el("div", "link");
  const c2p = lane("tx", "Client to tlsproxy");
  const p2c = lane("rx", "tlsproxy to client");
  legA.append(c2p.d, p2c.d);
  const legB = el("div", "link");
  const p2u = lane("tx", "tlsproxy to upstream");
  const u2p = lane("rx", "Upstream to tlsproxy");
  legB.append(p2u.d, u2p.d);
  legs.append(cNode, legA, hubNode, legB, uNode);
  const facts = el("dl", "facts");
  const fSni = fact(facts, "SNI");
  const fDst = fact(facts, "Destination");
  const fMode = fact(facts, "Mode");
  const opened = fact(facts, "Opened");
  const duration = fact(facts, "Duration");
  const idle = fact(facts, "Idle");
  detail.append(legs, facts);
  wrap.append(row, detail);

  const toggle = () => {
    if (ui.resetting.has(c.id)) return;
    if (ui.openConns.has(c.id)) ui.openConns.delete(c.id); else ui.openConns.add(c.id);
    syncConnOpen(ui.C.get(c.id));
    paint();
  };
  row.addEventListener("click", toggle);
  row.addEventListener("keydown", (ev) => {
    if (ev.target !== row) return;
    if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); toggle(); }
  });
  stop.addEventListener("click", (ev) => { ev.stopPropagation(); onStop(c.id); });

  return {
    id: c.id, data: c, wrap, row, client, sni, age, state, tx, rx, totalUp, totalDown, stop, stopLabel, detail,
    cRemote, hubIn, hubOut, uRemote, c2p, p2c, p2u, u2p, fSni, fDst, fMode, opened, duration, idle,
  };
}

function syncConnOpen(cr) {
  const open = ui.openConns.has(cr.id);
  cr.row.setAttribute("aria-expanded", String(open));
  cr.wrap.classList.toggle("open", open);
  cr.detail.hidden = !open;
}

function connState(c) {
  const upDone = c.cToS !== "open", downDone = c.sToC !== "open";
  if (c.stopping || ui.resetting.has(c.id)) return ["CLOSING", "state reset", "Stop requested: both legs are being closed"];
  if (upDone && downDone) return ["CLOSING", "state half", "Both directions finished"];
  if (upDone) return ["CLIENT FIN", "state half", "Client half-closed; upstream may still send"];
  if (downDone) return ["UPSTREAM FIN", "state half", "Upstream half-closed; client may still send"];
  return ["ESTABLISHED", "state", "Both directions open"];
}

// The filter matches at every level: a listener (name, bind, port, open
// addresses), a rule (pattern, target) and a connection (#id, addresses,
// SNI). Whatever an upper level matches, everything below it matches too.
const listenerHay = (l) => `${l.name} ${l.bind} ${l.port} ${(l.addrs || []).join(" ")}`.toLowerCase();
const ruleHay = (r) => `${r.pattern} ${r.target} ${(r.routes || []).join(" ")}`.toLowerCase();

function matches(c, r, l) {
  const f = ui.filter;
  if (!f) return true;
  const hay = `#${c.id} ${c.src} ${c.local} ${c.upstreamLocal} ${c.peer} ${c.sni} ${c.dst}`.toLowerCase();
  return hay.includes(f) || ruleHay(r).includes(f) || listenerHay(l).includes(f);
}

// ---------- stop a connection ----------

function onStop(id) {
  const cr = ui.C.get(id);
  if (!cr || ui.resetting.has(id)) return;
  if (!ui.armed.has(id)) {
    cr.stop.classList.add("armed");
    setText(cr.stopLabel, "Confirm");
    ui.armed.set(id, setTimeout(() => disarm(id), ARM_MS));
    return;
  }
  disarm(id);
  ui.resetting.add(id);
  cr.wrap.classList.add("resetting");
  cr.stop.disabled = true;
  setText(cr.stopLabel, "Closing");
  paint();
  api("api/connections/stop", { id })
    .catch((e) => {
      if (e.status === 404) return; // already gone: the next frame drops the row
      ui.resetting.delete(id);
      const again = ui.C.get(id);
      if (!again) return;
      again.wrap.classList.remove("resetting");
      again.stop.disabled = false;
      setText(again.stopLabel, "Stop");
      toast(`Could not stop #${id}: ${e.message}`, true);
      paint();
    });
}

function disarm(id) {
  clearTimeout(ui.armed.get(id));
  ui.armed.delete(id);
  const cr = ui.C.get(id);
  if (cr && !ui.resetting.has(id)) {
    cr.stop.classList.remove("armed");
    setText(cr.stopLabel, "Stop");
  }
}

document.addEventListener("keydown", (ev) => {
  if (ev.key === "Escape") {
    for (const id of [...ui.armed.keys()]) disarm(id);
    for (const key of [...armedDeletes.keys()]) disarmDelete(key);
    for (const name of [...armedLDeletes.keys()]) disarmListenerDelete(name);
  }
});

// ---------- applying pushed state ----------

function forgetConn(id) {
  const cr = ui.C.get(id);
  if (cr) cr.wrap.remove();
  ui.C.delete(id);
  ui.openConns.delete(id);
  ui.resetting.delete(id);
  clearTimeout(ui.armed.get(id));
  ui.armed.delete(id);
  ui.meters.delete("ct" + id);
  ui.meters.delete("cr" + id);
}

function applyState(s) {
  ui.skew = Date.now() - s.now;
  ui.state = s;
  if (s.host) { $("host").hidden = false; setText($("host"), s.host); document.title = `${s.host} · tlsproxy`; }
  if (!ui.total) ui.total = new Ring(HISTORY_POINTS);
  meter("st").add(s.now, s.status.bytesUp);
  meter("sr").add(s.now, s.status.bytesDown);

  const container = $("listeners");
  const seenL = new Set();
  const seenR = new Set();
  const seenC = new Set();
  const ruleCount = s.listeners.reduce((n, l) => n + l.rules.length, 0);
  s.listeners.forEach((l, li) => {
    seenL.add(l.name);
    let lr = ui.L.get(l.name);
    if (!lr) {
      lr = buildListener(l);
      ui.L.set(l.name, lr);
      ui.history.set("L" + l.name, new Ring(HISTORY_POINTS));
      if (s.listeners.length <= 3) ui.expandedL.add(l.name);
    }
    if (container.children[li] !== lr.card) container.insertBefore(lr.card, container.children[li] || null);
    lr.data = l;
    meter("lt" + l.name).add(s.now, l.bytesUp);
    meter("lr" + l.name).add(s.now, l.bytesDown);

    l.rules.forEach((r, index) => {
      seenR.add(r.key);
      let rr = ui.R.get(r.key);
      if (!rr) {
        rr = buildRule(r);
        ui.R.set(r.key, rr);
        ui.history.set("R" + r.key, new Ring(HISTORY_POINTS));
        if (ruleCount <= 3) ui.expanded.add(r.key);
      }
      // A rule moved to another listener moves its card along.
      if (lr.rules.children[index] !== rr.card) lr.rules.insertBefore(rr.card, lr.rules.children[index] || null);
      rr.data = r;
      rr.listener = l;
      meter("rt" + r.key).add(s.now, r.bytesUp);
      meter("rr" + r.key).add(s.now, r.bytesDown);
      for (const c of r.connections) {
        seenC.add(c.id);
        let cr = ui.C.get(c.id);
        if (!cr) {
          cr = buildConn(c);
          ui.C.set(c.id, cr);
          if (!ui.firstFrame) {
            cr.wrap.classList.add("fresh");
            setTimeout(() => cr.wrap.classList.remove("fresh"), 1700);
          }
        }
        cr.data = c;
        cr.rule = r;
        meter("ct" + c.id).add(s.now, c.bytesUp);
        meter("cr" + c.id).add(s.now, c.bytesDown);
      }
    });
  });

  for (const id of [...ui.C.keys()]) if (!seenC.has(id)) forgetConn(id);
  for (const [key, rr] of [...ui.R]) {
    if (seenR.has(key)) continue;
    rr.card.remove();
    ui.R.delete(key);
    clearTimeout(armedDeletes.get(key));
    armedDeletes.delete(key);
    pendingRules.delete(key);
    ui.history.delete("R" + key);
    ui.expanded.delete(key);
    ui.meters.delete("rt" + key);
    ui.meters.delete("rr" + key);
  }
  for (const [name, lr] of [...ui.L]) {
    if (seenL.has(name)) continue;
    lr.card.remove();
    ui.L.delete(name);
    clearTimeout(armedLDeletes.get(name));
    armedLDeletes.delete(name);
    pendingListeners.delete(name);
    ui.history.delete("L" + name);
    ui.expandedL.delete(name);
    ui.meters.delete("lt" + name);
    ui.meters.delete("lr" + name);
  }

  paintFile(s.file);
  confirmPending();
  renderAll();
  if (ui.firstFrame) { ui.firstFrame = false; sample(); }
  paint();
}

// allRules lists every rule of the last frame, listener by listener.
function allRules(s) {
  return (s ? s.listeners : []).flatMap((l) => l.rules);
}

// renderAll applies expand state and the filter to both levels.
function renderAll() {
  for (const lr of ui.L.values()) renderListener(lr);
}

// renderListener opens or closes one listener card and shows the rule cards
// the filter lets through.
function renderListener(lr) {
  const l = lr.data;
  const f = ui.filter;
  const lMatch = !!f && listenerHay(l).includes(f);
  let shown = 0;
  for (const r of l.rules) {
    const rr = ui.R.get(r.key);
    if (!rr) continue;
    const visible = renderRows(rr);
    const show = !f || lMatch || ruleHay(r).includes(f) || visible > 0;
    rr.card.hidden = !show;
    if (show) shown++;
  }
  const open = ui.expandedL.has(l.name) || (f !== "" && shown > 0);
  lr.head.setAttribute("aria-expanded", String(open));
  lr.body.hidden = !open;
  lr.empty.hidden = shown > 0;
  if (shown === 0) {
    const none = l.rules.length === 0;
    lr.sleepy.hidden = !none;
    setText(lr.emptyText, none
      ? `No rules on ${l.name} yet. Connections to ${listenAddrs(l)} are refused until one matches; use Add rule.`
      : `No rules match “${ui.filter}”.`);
  }
}

// renderRows puts the visible, filtered rows of one rule into the DOM,
// newest first, capped at MAX_ROWS.
function renderRows(rr) {
  const r = rr.data;
  const visible = r.connections.filter((c) => matches(c, r, rr.listener));
  const open = ui.expanded.has(r.key) || (ui.filter !== "" && visible.length > 0);
  rr.head.setAttribute("aria-expanded", String(open));
  rr.body.hidden = !open;

  const want = open ? visible.slice(-MAX_ROWS).reverse() : [];
  const wantIds = new Set(want.map((c) => c.id));
  for (const id of rr.shown) {
    if (!wantIds.has(id)) { const cr = ui.C.get(id); if (cr) cr.wrap.remove(); }
  }
  let anchor = rr.thead;
  for (const c of want) {
    const cr = ui.C.get(c.id);
    if (anchor.nextSibling !== cr.wrap) rr.body.insertBefore(cr.wrap, anchor.nextSibling);
    syncConnOpen(cr);
    anchor = cr.wrap;
  }
  rr.shown = want.map((c) => c.id);

  rr.thead.hidden = want.length === 0;
  rr.empty.hidden = want.length > 0;
  if (want.length === 0) {
    const none = r.connCount === 0;
    rr.sleepy.hidden = !none;
    let idle;
    if (r.kind === "removed") idle = `${r.pattern} is no longer in the config file.`;
    else if (r.stopped) idle = `${r.pattern} is stopped: matching names fall through to the next rule. Start it to route them here again.`;
    else if (!r.allow) idle = `Deny rule: clients asking for ${r.pattern} are refused, so no connection stays open.`;
    else if (r.kind === "redirect") idle = "No open connections. Plain HTTP clients show up here while they are being redirected.";
    else if (r.kind === "no SNI") idle = "No open connections. Clients that send no name show up here.";
    else idle = `No open connections. Clients asking for ${r.pattern} show up here.`;
    setText(rr.emptyText, none ? idle : `No connections match “${ui.filter}”.`);
  }
  const hidden = visible.length - want.length;
  const capped = r.connCount - r.connections.length;
  const notes = [];
  if (open && hidden > 0) notes.push(`Showing the newest ${want.length} of ${visible.length} connections. Filter to find the rest.`);
  if (open && capped > 0) notes.push(`${capped} older connections are not sent to the console.`);
  rr.more.hidden = notes.length === 0;
  setText(rr.more, notes.join(" "));
  return visible.length;
}

// ---------- paint (local clock only) ----------

function paint() {
  const s = ui.state;
  if (!s) return;
  const now = serverNow();
  let matched = 0, all = 0, running = 0;

  for (const lr of ui.L.values()) {
    const l = lr.data;
    if (l.running && !l.stopped) running++;
    paintListener(lr, l, now, s.file);
  }

  for (const rr of ui.R.values()) {
    const r = rr.data;
    const tx = meter("rt" + r.key).rate(now);
    const rx = meter("rr" + r.key).rate(now);
    const removed = r.kind === "removed";
    const out = removed || r.stopped || !r.running;
    all += r.connections.length;
    if (ui.filter) matched += r.connections.filter((c) => matches(c, r, rr.listener)).length;

    setText(rr.pattern, r.pattern);
    rr.pattern.title = r.line ? `[[host]] at line ${r.line} of the config file` : "";
    setText(rr.target, removed ? "removed" : r.allow ? r.target : "deny");
    rr.target.classList.toggle("deny", !removed && !r.allow);
    rr.target.title = r.routes ? r.routes.join("\n") : "";
    rr.card.classList.toggle("stopped", out);

    rr.status.hidden = !out;
    if (removed) {
      setText(rr.status, "removed from the file");
      rr.status.className = "chip bad";
      rr.status.title = "This rule was deleted or changed; its open connections are still listed";
    } else if (r.stopped) {
      setText(rr.status, "stopped");
      rr.status.className = "chip warn";
      rr.status.title = "Stopped from the console: matching names fall through to the next rule. Not saved: a restart or Start brings it back.";
    } else {
      setText(rr.status, "not running");
      rr.status.className = "chip bad";
      rr.status.title = "In the config file but not in the configuration the proxy is running";
    }
    rr.active.hidden = out && r.active === 0;
    setText(rr.active, `${r.active} active`);
    rr.active.className = r.active > 0 ? "chip live" : "chip";
    setText(rr.total, `${r.total} total`);
    rr.total.title = "Connections this rule has handled since the proxy started";
    rr.total.hidden = removed;

    rr.kind.hidden = removed;
    setText(rr.kind, r.kind);
    rr.kind.title = {
      literal: "Exact name: checked first, always wins over wildcards",
      wildcard: "Wildcard: among wildcards the one with more fixed characters wins",
      "no SNI": "Only clients that send no server name",
      "catch-all": "Everything else: used only when no other rule matches",
      redirect: "Every name: the redirect does not look at the rules; HTTPS refuses the names it does not serve",
    }[r.kind] || "";
    const redirect = r.kind === "redirect";
    rr.tls.hidden = removed || !r.allow;
    setText(rr.tls, redirect ? "plain HTTP · 301 / 308" : r.terminates ? `terminates TLS · ${r.cert}` : "passthrough");
    rr.tls.className = r.terminates ? "chip tls" : "chip";
    rr.tls.title = redirect ? "Answers each request with a redirect to the same host and path on https://: 301 for GET and HEAD, 308 (keeps the method) for the others. Keep-alive is supported."
      : r.terminates ? `TLS is terminated here (cert = ${r.cert})` : "TLS passes through untouched; the upstream presents its own certificate";
    rr.proxy.hidden = removed || !r.allow || !r.proxy;
    setText(rr.proxy, `PROXY v${r.proxyVersion || 2}`);
    rr.proxy.title = "Sends a PROXY protocol header with the client's address to the target";
    rr.limTotal.hidden = !r.aggSpeed;
    if (r.aggSpeed) setText(rr.limTotal, `≤ ${fmtLimit(r.aggSpeed, r.values.max_aggregated_speed)} total`);
    rr.limTotal.title = "max_aggregated_speed: shared by every connection of this rule, in each direction";
    rr.limConn.hidden = !r.connSpeed;
    if (r.connSpeed) setText(rr.limConn, `≤ ${fmtLimit(r.connSpeed, r.values.max_single_connection_speed)} per conn`);
    rr.limConn.title = "max_single_connection_speed: the cap for each connection, in each direction";

    setText(rr.tx, fmtRate(tx));
    setText(rr.rx, fmtRate(rx));
    setText(rr.totalUp, fmtBytes(r.bytesUp));
    setText(rr.totalDown, fmtBytes(r.bytesDown));
    paintRuleActions(rr, r, s.file);

    for (const id of rr.shown) {
      const cr = ui.C.get(id);
      if (cr) paintConn(cr, now);
    }
  }

  const st = s.status;
  const n = s.listeners.length;
  setText($("k-listeners"), running === n ? String(n) : `${running} / ${n} running`);
  setText($("k-active"), String(st.active));
  setText($("k-accepted"), String(st.accepted));
  setText($("k-tx"), fmtRate(meter("st").rate(now)));
  setText($("k-rx"), fmtRate(meter("sr").rate(now)));
  setText($("k-total-up"), fmtBytes(st.bytesUp));
  setText($("k-total-down"), fmtBytes(st.bytesDown));
  setText($("k-uptime"), fmtAge(now - s.started));
  $("add-listener").hidden = !s.file.editable;
  setText($("filter-note"), ui.filter ? `${matched} of ${all} connections match` : "");
}

function paintListener(lr, l, now, file) {
  setText(lr.lname, l.name);
  setText(lr.listen, `[${listenAddrs(l)}]`);
  lr.listen.title = l.redirect ? "http_to_https_redirect = true in [global]: port 80 on every address the other listeners use"
    : `[[listener]] at line ${l.line} of the config file`;
  const n = l.rules.length;
  setText(lr.target, l.redirect ? "https://" : `${n} rule${n === 1 ? "" : "s"}`);
  const out = l.stopped || !l.running;
  lr.card.classList.toggle("stopped", out);

  lr.status.hidden = !out;
  if (l.stopped) {
    setText(lr.status, "stopped");
    lr.status.className = "chip warn";
    lr.status.title = "Stopped from the console: the port is closed. Not saved: a restart or Start opens it again.";
  } else if (l.error) {
    setText(lr.status, "port not open");
    lr.status.className = "chip bad";
    lr.status.title = l.error;
  } else {
    setText(lr.status, "not running");
    lr.status.className = "chip bad";
    lr.status.title = "The port is not open";
  }
  lr.err.hidden = !l.error;
  setText(lr.err, l.error ? `Could not open the port: ${l.error}` : "");
  lr.redirectChip.hidden = !l.redirect;
  setText(lr.redirectChip, "HTTP → HTTPS redirect");
  lr.redirectChip.title = "http_to_https_redirect: every plain HTTP request is redirected to the same URL on https://, whatever the name; the HTTPS rules decide from there. Set in [global]; it has no rules and cannot be edited here.";
  lr.ppf.hidden = !l.proxyTrustSource;
  setText(lr.ppf, `PROXY from ${l.proxyTrustSource || ""}`);
  lr.ppf.title = "Accepts a PROXY protocol header from these addresses (proxy_trust_source)";
  lr.maxConns.hidden = !l.maxConnections;
  setText(lr.maxConns, `≤ ${l.maxConnections} conns`);
  lr.maxConns.className = l.maxConnections && l.active >= l.maxConnections ? "chip bad" : "chip limit";
  lr.maxConns.title = `max_connections for this listener (${l.active} open now)`;
  lr.refused.hidden = !l.rejected;
  setText(lr.refused, `${l.rejected} refused`);
  lr.refused.title = "Connections refused because a limit was reached";
  for (const [chip, v, label, key] of [[lr.hs, l.handshakeTimeout, "handshake", "handshake_timeout"],
    [lr.idle, l.idleTimeout, "idle", "idle_timeout"], [lr.half, l.halfCloseTimeout, "half-close", "half_close_timeout"]]) {
    chip.hidden = v === null || v === undefined;
    setText(chip, `${label} ${v}s`);
    chip.title = `${key} for this listener (overrides [global])`;
  }
  const vals = l.values || {};
  lr.limTotal.hidden = !l.aggSpeed;
  if (l.aggSpeed) setText(lr.limTotal, `≤ ${fmtLimit(l.aggSpeed, vals.max_aggregated_speed)} total`);
  lr.limTotal.title = "max_aggregated_speed: shared by every connection on this listener, in each direction, on top of each rule's limits";
  lr.limConn.hidden = !l.connSpeed;
  if (l.connSpeed) setText(lr.limConn, `≤ ${fmtLimit(l.connSpeed, vals.max_single_connection_speed)} per conn`);
  lr.limConn.title = "max_single_connection_speed: the cap for each connection on this listener, in each direction";

  setText(lr.active, String(l.active));
  setText(lr.accepted, String(l.accepted));
  setText(lr.tx, fmtRate(meter("lt" + l.name).rate(now)));
  setText(lr.rx, fmtRate(meter("lr" + l.name).rate(now)));

  const editable = !!(file && file.editable);
  const busy = pendingListeners.has(l.name);
  const closed = l.stopped || !l.running;
  lr.toggleBtn.disabled = busy;
  if (!busy) setText(lr.toggleLabel, closed ? "Start" : "Stop");
  lr.toggleBtn.className = closed ? "act start" : "act";
  lr.toggleBtn.title = l.stopped ? "Start: open the port again."
    : closed ? "Start: try to open the port again."
    : "Stop: closes the port and its connections. Not saved: a restart or Start opens it again.";
  lr.addBtn.disabled = !editable;
  lr.addBtn.title = editable ? `Add a rule to ${l.name}` : "Editing is off: see the note above";
  lr.editBtn.disabled = busy || !editable;
  lr.editBtn.title = !editable ? "Editing is off: see the note above"
    : "Edit this listener in the config file";
  lr.delBtn.hidden = !!l.redirect;
  lr.addBtn.hidden = lr.editBtn.hidden = !!l.redirect;
  lr.delBtn.disabled = busy || !editable;
  lr.delBtn.title = editable ? "Delete this listener from the config file (only once no rule uses it)" : "Editing is off: see the note above";
  if (!editable && armedLDeletes.has(l.name)) disarmListenerDelete(l.name);
}

function paintConn(cr, now) {
  const c = cr.data;
  setText(cr.client, c.src);
  cr.client.title = c.src;
  setText(cr.sni, c.sni || "no SNI");
  cr.sni.classList.toggle("none", !c.sni);
  cr.sni.title = c.sni || "The client sent no server name";
  setText(cr.age, fmtAge(now - c.started));
  const [label, cls, title] = connState(c);
  setText(cr.state, label);
  if (cr.state.className !== cls) cr.state.className = cls;
  cr.state.title = title;
  if (c.stopping && !cr.wrap.classList.contains("resetting")) {
    cr.wrap.classList.add("resetting"); // stopped elsewhere: fade until it leaves
    cr.stop.disabled = true;
    setText(cr.stopLabel, "Closing");
  }
  setText(cr.tx, fmtRate(meter("ct" + c.id).rate(now)));
  setText(cr.rx, fmtRate(meter("cr" + c.id).rate(now)));
  setText(cr.totalUp, fmtBytes(c.bytesUp));
  setText(cr.totalDown, fmtBytes(c.bytesDown));
  if (cr.detail.hidden) return;
  const upDone = c.cToS !== "open", downDone = c.sToC !== "open";
  setText(cr.cRemote, c.src);
  setText(cr.hubIn, c.local || "—");
  setText(cr.hubOut, c.upstreamLocal || "—");
  setText(cr.uRemote, c.peer || c.dst || "—");
  setLane(cr.c2p, c.bytesUp, upDone);
  setLane(cr.p2u, c.bytesUp, upDone);
  setLane(cr.u2p, c.bytesDown, downDone);
  setLane(cr.p2c, c.bytesDown, downDone);
  setText(cr.fSni, c.sni || "none sent");
  setText(cr.fDst, c.dst || "—");
  setText(cr.fMode, c.terminated ? c.mode : cr.rule && cr.rule.kind === "redirect" ? "plain HTTP, redirected to https://" : "passthrough (TLS untouched)");
  setText(cr.opened, fmtClock(c.started));
  setText(cr.duration, fmtAge(now - c.started));
  setText(cr.idle, c.lastActivity ? fmtAge(now - c.lastActivity) : "—");
}

function setLane(ln, bytes, fin) {
  setText(ln.bytes, fmtBytes(bytes));
  setText(ln.fin, fin ? "FIN" : "");
  ln.d.classList.toggle("fin", fin);
}

// sample appends one point per second to every chart ring and redraws.
function sample() {
  if (!ui.state || !ui.total) return;
  const now = serverNow();
  for (const lr of ui.L.values()) {
    const ring = ui.history.get("L" + lr.name);
    ring.push(meter("lt" + lr.name).rate(now), meter("lr" + lr.name).rate(now));
    drawSpark(lr.spark, ring);
  }
  for (const rr of ui.R.values()) {
    const ring = ui.history.get("R" + rr.key);
    ring.push(meter("rt" + rr.key).rate(now), meter("rr" + rr.key).rate(now));
    drawSpark(rr.spark, ring);
  }
  ui.total.push(meter("st").rate(now), meter("sr").rate(now));
  drawTrace();
}

function redrawCharts() {
  for (const lr of ui.L.values()) drawSpark(lr.spark, ui.history.get("L" + lr.name));
  for (const rr of ui.R.values()) drawSpark(rr.spark, ui.history.get("R" + rr.key));
  drawTrace();
}

// paintFile shows why rules cannot be edited, when they cannot.
function paintFile(f) {
  const b = $("file-banner");
  if (f.error) {
    b.hidden = false;
    setText(b, `The config file cannot be used: ${f.error}. The rules shown are the ones running; editing is off until the file is fixed (see Config file).`);
  } else if (!f.editable) {
    b.hidden = false;
    setText(b, "Rules cannot be edited here: this proxy was not started from a config file.");
  } else {
    b.hidden = true;
  }
}

// ---------- rule actions ----------

// An action in flight keeps its card's buttons disabled until the pushed
// state shows its effect (or CONFIRM_MS passes), so a card changes once, when
// the server says so, instead of flipping back and forth. A refused action
// re-enables the buttons with nothing changed.
const CONFIRM_MS = 3000;
const pendingRules = new Map(); // rule key -> {done, timer} for a start/stop/delete in flight

// track runs request with key marked busy in pending. done(item) says
// whether the pushed state (the rule or listener, undefined once gone) shows
// the action took effect.
function track(pending, key, request, done, ok, failed) {
  const entry = { done: null, timer: 0 };
  pending.set(key, entry);
  paint();
  request()
    .then((d) => {
      ok(d);
      if (pending.get(key) !== entry) return; // already gone from the state
      entry.done = done;
      entry.timer = setTimeout(() => { if (pending.get(key) === entry) { pending.delete(key); paint(); } }, CONFIRM_MS);
      confirmPending();
    })
    .catch((e) => {
      if (pending.get(key) === entry) pending.delete(key);
      failed(e);
      paint();
    });
}

// confirmPending ends the actions whose effect the last frame shows.
function confirmPending() {
  const s = ui.state;
  if (!s) return;
  const rules = new Map(allRules(s).map((r) => [r.key, r]));
  const listeners = new Map(s.listeners.map((l) => [l.name, l]));
  let changed = false;
  for (const [pending, items] of [[pendingRules, rules], [pendingListeners, listeners]]) {
    for (const [key, e] of [...pending]) {
      if (e.done && e.done(items.get(key))) { clearTimeout(e.timer); pending.delete(key); changed = true; }
    }
  }
  if (changed) paint();
}
const armedDeletes = new Map(); // rule key -> disarm timer

function paintRuleActions(rr, r, file) {
  const removed = r.kind === "removed" || r.kind === "redirect"; // nothing to stop, edit or delete
  const editable = !!(file && file.editable && r.line > 0);
  const busy = pendingRules.has(r.key);
  rr.toggleBtn.hidden = removed;
  rr.editBtn.hidden = removed;
  rr.delBtn.hidden = removed;
  rr.toggleBtn.disabled = busy || (!r.running && !r.stopped);
  if (!busy) setText(rr.toggleLabel, r.stopped ? "Start" : "Stop");
  rr.toggleBtn.className = r.stopped ? "act start" : "act";
  rr.toggleBtn.title = r.stopped
    ? "Start: route matching names with this rule again."
    : !r.running ? "Not in the running configuration yet"
    : "Stop: matching names fall through to the next rule as if this one were not configured; open connections are closed. Not saved: a restart or Start brings it back.";
  rr.editBtn.disabled = busy || !editable;
  rr.delBtn.disabled = busy || !editable;
  rr.editBtn.title = editable ? "Edit this rule in the config file" : "Editing is off: see the note above the rules";
  rr.delBtn.title = editable ? "Delete this rule from the config file" : "Editing is off: see the note above the rules";
  if (!editable && armedDeletes.has(r.key)) disarmDelete(r.key);
}

// api posts JSON with the session's CSRF token. It resolves with the reply
// when the server says ok, and rejects with an Error carrying .status and
// the server's message otherwise.
function api(path, body) {
  return fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": ui.csrf },
    credentials: "same-origin",
    body: JSON.stringify(body || {}),
  }).then(async (r) => {
    if (r.status === 401) { showLogin(); throw Object.assign(new Error("Your session ended. Sign in again."), { status: 401 }); }
    let data = {};
    try { data = await r.json(); } catch (_) { /* not JSON */ }
    if (!r.ok || data.ok === false) throw Object.assign(new Error(data.error || r.statusText || `HTTP ${r.status}`), { status: r.status, data });
    return data;
  });
}

// getJSON fetches a read-only endpoint.
function getJSON(path) {
  return fetch(path, { credentials: "same-origin" }).then(async (r) => {
    if (r.status === 401) { showLogin(); throw Object.assign(new Error("Your session ended. Sign in again."), { status: 401 }); }
    let data = {};
    try { data = await r.json(); } catch (_) { /* not JSON */ }
    if (!r.ok) throw Object.assign(new Error(data.error || r.statusText || `HTTP ${r.status}`), { status: r.status, data });
    return data;
  });
}

function onStartStop(key) {
  const rr = ui.R.get(key);
  if (!rr || pendingRules.has(key)) return;
  const r = rr.data;
  const stop = !r.stopped;
  const action = stop ? "stop" : "start";
  setText(rr.toggleLabel, stop ? "Stopping" : "Starting");
  track(pendingRules, key, () => api(`api/rules/${action}`, { key }),
    (now) => !now || now.stopped === stop,
    () => toast(`${stop ? "Stopped" : "Started"} ${r.pattern}`),
    (e) => toast(`Could not ${action} ${r.pattern}: ${e.message}`, true));
}

function onDeleteRule(key) {
  const rr = ui.R.get(key);
  if (!rr || pendingRules.has(key)) return;
  if (!armedDeletes.has(key)) {
    rr.delBtn.classList.add("armed");
    setText(rr.delLabel, "Confirm delete");
    armedDeletes.set(key, setTimeout(() => disarmDelete(key), ARM_MS));
    return;
  }
  disarmDelete(key);
  const r = rr.data;
  const f = ui.state.file;
  track(pendingRules, key, () => api("api/rules/delete", { line: r.line, baseHash: f.hash, baseMtime: f.mtime }),
    (now) => !now || now.line === 0,
    (d) => { toast(`Deleted ${r.pattern}${d.backup ? ` (previous file kept as ${d.backup})` : ""}`); saveProblems(d); },
    (e) => toast(`Could not delete ${r.pattern}: ${e.message}`, true));
}

function disarmDelete(key) {
  clearTimeout(armedDeletes.get(key));
  armedDeletes.delete(key);
  const rr = ui.R.get(key);
  if (rr) { rr.delBtn.classList.remove("armed"); setText(rr.delLabel, "Delete"); }
}

// ---------- listener actions ----------

const pendingListeners = new Map(); // listener name -> {done, timer}, as pendingRules
const armedLDeletes = new Map(); // listener name -> disarm timer

function onListenerStartStop(name) {
  const lr = ui.L.get(name);
  if (!lr || pendingListeners.has(name)) return;
  const l = lr.data;
  // A port that is not open (stopped, or it failed to open) offers Start.
  const stop = !l.stopped && l.running;
  const action = stop ? "stop" : "start";
  setText(lr.toggleLabel, stop ? "Stopping" : "Starting");
  track(pendingListeners, name, () => api(`api/listeners/${action}`, { name }),
    (now) => !now || (stop ? now.stopped : now.running && !now.stopped),
    () => toast(`${stop ? "Stopped" : "Started"} ${name} [${listenAddrs(l)}]`),
    (e) => toast(`Could not ${action} ${name}: ${e.message}`, true));
}

function onDeleteListener(name) {
  const lr = ui.L.get(name);
  if (!lr || pendingListeners.has(name) || lr.data.redirect) return;
  if (!armedLDeletes.has(name)) {
    lr.delBtn.classList.add("armed");
    setText(lr.delLabel, "Confirm delete");
    armedLDeletes.set(name, setTimeout(() => disarmListenerDelete(name), ARM_MS));
    return;
  }
  disarmListenerDelete(name);
  const f = ui.state.file;
  track(pendingListeners, name, () => api("api/listeners/delete", { line: lr.data.line, baseHash: f.hash, baseMtime: f.mtime }),
    (now) => !now || now.removed,
    (d) => { toast(`Deleted listener ${name}${d.backup ? ` (previous file kept as ${d.backup})` : ""}`); saveProblems(d); },
    (e) => toast(`Could not delete ${name}: ${e.message}`, true));
}

function disarmListenerDelete(name) {
  clearTimeout(armedLDeletes.get(name));
  armedLDeletes.delete(name);
  const lr = ui.L.get(name);
  if (lr) { lr.delBtn.classList.remove("armed"); setText(lr.delLabel, "Delete"); }
}

// dryRun posts to a validate endpoint and always resolves with an answer:
// {ok:false, error} stands in for network and HTTP failures.
function dryRun(path, body) {
  return fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": ui.csrf },
    credentials: "same-origin",
    body: JSON.stringify(body),
  })
    .then(async (r) => {
      if (r.status === 401) { showLogin(); throw new Error("Your session ended. Sign in again."); }
      let data = {};
      try { data = await r.json(); } catch (_) { /* not JSON */ }
      if (!r.ok && !data.error) data = { ok: false, error: `${r.statusText || r.status}` };
      return data;
    })
    .catch((e) => ({ ok: false, error: `Could not check it: ${e.message}` }));
}

// ---------- rule wizard (add / edit dialog) ----------
//
// Three steps over one form: what to match, where to send it, options. Only
// the fields that apply are shown. Every change runs quick checks here and,
// 300 ms later, a dry run on the server (api/rules/validate) that returns the
// exact [[host]] block that would be written and where sample names route.
// Values go to the server as raw strings; "" removes the key from the file.

const ed = {
  conflict: false, // the last save was refused because the file changed
  saving: false,
  rule: null, // the rule being edited, or null when adding
  base: null, // file version the editor started from: {hash, mtime}
  step: 0,
  seq: 0, // validation requests sent; older answers are ignored
  timer: 0,
  result: null, // last validation answer
  pending: false,
  tryTouched: false,
};

const BOOL_KEYS = new Set(["proxy", "upstream_tls", "upstream_tls_verify"]);
const DEFAULTS = { action: "allow", proxy: "false", proxy_version: "2", upstream_tls: "true", upstream_tls_verify: "true" };
const LISTENER_NAME_RE = /^[A-Za-z0-9_@#~()[\]<>"'-](?:[A-Za-z0-9 _@#~()[\]<>"'-]{0,62}[A-Za-z0-9_@#~()[\]<>"'-])?$/; // as config.go
const RATE_RE = /^\s*\d+(\.\d+)?\s*(bit|bps|[kmg](bit|bps)|[kmg]?b|[kmg]ib)\s*(\/s)?\s*$/i;

// normal is a value's meaning, so a file's own spelling ("yes", "Allow") is
// kept when the user did not change what it means.
function normal(key, v) {
  let s = String(v ?? "").trim();
  if (BOOL_KEYS.has(key)) {
    const l = s.toLowerCase();
    s = ["true", "yes", "on"].includes(l) ? "true" : ["false", "no", "off"].includes(l) ? "false" : l;
  }
  if (key === "action") s = s.toLowerCase();
  if (key === "listener") return s;
  return s === "" ? DEFAULTS[key] ?? "" : s;
}

function onlyListener() {
  const ls = ui.state ? ui.state.listeners.filter((x) => !x.redirect) : [];
  return ls.length === 1 ? ls[0].name : "";
}

const val = (id) => $(id).value.trim();
const radio = (name) => (document.querySelector(`input[name="${name}"]:checked`) || {}).value;
function setRadio(name, v) {
  for (const r of document.querySelectorAll(`input[name="${name}"]`)) r.checked = r.value === v;
}

// formValues reads the form into config keys. Options that do not apply
// (target of a deny rule, TLS settings when passing through, ...) are sent as
// "" so they leave the file.
function formValues() {
  const allow = radio("f-action") !== "deny";
  const serve = radio("f-action") === "serve"; // service rules: no target, nothing upstream
  const term = serve || (allow && radio("f-tls") === "terminate");
  const src = radio("f-certsrc");
  const auto = term && src === "auto";
  const local = term && src === "local";
  const upTLS = term && !serve && $("f-upstream-tls").value !== "false";
  const proxy = allow && !serve && $("f-proxy").checked;
  const v = {
    listener: $("f-listener").value,
    pattern: val("f-pattern"),
    action: allow ? "allow" : "deny",
    target_host: allow && !serve ? val("f-target-host") : null,
    target_port: allow && !serve ? val("f-target-port") : null,
    service_rules: serve ? $("f-routes").value : null,
    max_aggregated_speed: allow ? val("f-agg") : null,
    max_single_connection_speed: allow ? val("f-conn") : null,
    proxy: allow ? (proxy ? "true" : "") : null,
    proxy_version: proxy ? $("f-proxy-version").value : null,
    cert: term ? (local ? localCAValue($("f-cert-ca").value) : "auto") : null,
    cert_domains: auto || local ? val("f-cert-domains") : null,
    cert_validate_script: auto ? val("f-cert-script") : null,
    cert_validate_args: auto && val("f-cert-script") ? val("f-cert-args") : null,
    upstream_tls: term && !serve ? $("f-upstream-tls").value : null,
    upstream_tls_verify: upTLS ? $("f-upstream-verify").value : null,
    upstream_sni: upTLS ? val("f-upstream-sni") : null,
  };
  const orig = ed.rule ? ed.rule.values : {};
  for (const k of Object.keys(v)) {
    if (v[k] === null) { v[k] = ""; continue; }
    const o = orig[k] ?? "";
    if (normal(k, o) === normal(k, v[k])) v[k] = o;
  }
  // Unchanged service rules are not sent, so their keys stay as written
  // (a change rewrites them as service_rule1, 2, ...).
  if (routeLines(v.service_rules) === routeLines(orig.service_rules)) delete v.service_rules;
  return v;
}

// routeLines is the service rules that count: blank lines and # comments out.
function routeLines(text) {
  return String(text ?? "").split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#")).join("\n");
}

// localCAOf is the CA a cert value names ("local-ca" is ca001), "" if none.
function localCAOf(cert) {
  const m = /^local-ca(?::(ca\d{3}))?$/i.exec((cert || "").trim());
  return m ? (m[1] || "ca001").toLowerCase() : "";
}

function localCAValue(id) { return id === "ca001" ? "local-ca" : `local-ca:${id}`; }

// fillCASelect lists the CAs that exist for the rule editor. A new one is
// made on the CAs page, never from here.
function fillCASelect(selected) {
  const sel = $("f-cert-ca");
  return getJSON("api/cas").then((d) => {
    sel.replaceChildren();
    if (!d.cas.length) {
      const o = el("option", "", "no CA yet: make one on the CAs page");
      o.value = "";
      sel.appendChild(o);
    }
    for (const ca of d.cas) {
      const o = el("option", "", `${ca.id} · ${ca.name || ca.error || ""}`);
      o.value = ca.id;
      o.disabled = !!ca.error;
      sel.appendChild(o);
    }
    if (selected && !d.cas.some((ca) => ca.id === selected)) {
      const o = el("option", "", `${selected} · missing: this rule can't be saved until it exists`);
      o.value = selected;
      sel.appendChild(o);
    }
    sel.value = selected || (d.cas[0] ? d.cas[0].id : "");
    onFormChange();
  }).catch(() => {});
}

function boolSelect(raw) {
  const n = normal("proxy", raw); // any bool key: same spelling rules
  return String(raw ?? "").trim() === "" ? "" : n;
}

function prefill(values) {
  const v = values || {};
  $("f-pattern").value = v.pattern || "";
  setRadio("f-action", normal("action", v.action) === "deny" ? "deny" : v.service_rules ? "serve" : "allow");
  $("f-routes").value = v.service_rules || "";
  $("f-target-host").value = v.target_host || "";
  $("f-target-port").value = v.target_port || "";
  const cert = (v.cert || "").trim();
  setRadio("f-tls", cert ? "terminate" : "pass");
  const ca = localCAOf(cert);
  setRadio("f-certsrc", ca ? "local" : "auto");
  ed.ca = ca || "";
  $("f-cert-domains").value = v.cert_domains || "";
  $("f-cert-script").value = v.cert_validate_script || "";
  $("f-cert-args").value = v.cert_validate_args || "";
  $("f-upstream-tls").value = boolSelect(v.upstream_tls);
  $("f-upstream-verify").value = boolSelect(v.upstream_tls_verify);
  $("f-upstream-sni").value = v.upstream_sni || "";
  $("f-proxy").checked = normal("proxy", v.proxy) === "true";
  $("f-proxy-version").value = normal("proxy_version", v.proxy_version) === "1" ? "1" : "2";
  $("f-agg").value = v.max_aggregated_speed || "";
  $("f-conn").value = v.max_single_connection_speed || "";
}

// patternInfo explains a pattern the way the proxy reads it.
function patternInfo(p) {
  const t = p.trim();
  if (!t) return { kind: "", text: "Type the host name clients ask for, or pick an example." };
  if (/^none$/i.test(t)) return { kind: "no SNI", text: "Only clients that send no server name (old clients, connections to an IP address). Exact names are checked before it, wildcards after." };
  if (/^any$/i.test(t) || /^\^?\.\*\$?$/.test(t)) return { kind: "catch-all", text: "Everything, with or without a name: used only when no other rule matches." };
  const name = t.replace(/^\^/, "").replace(/\$$/, "").replace(/\\\./g, ".").toLowerCase();
  if (!/^[a-z0-9_*.-]+$/.test(name) || name.startsWith(".") || name.endsWith(".") || name.includes("..")) {
    return { kind: "", bad: true, text: "Not a host name: use letters, digits, hyphens and dots, with * for one label or part of one. Regular expressions are not supported." };
  }
  if (!name.includes("*")) return { kind: "literal", text: "Exact name: the most specific kind. It is checked first and always wins over wildcards." };
  if (name.includes("**")) return { kind: "", bad: true, text: "** is not supported: a * never crosses a dot. Write one rule per depth (*.example.com, *.*.example.com)." };
  const stars = (name.match(/\*/g) || []).length;
  const fixed = name.replace(/\*/g, "").length;
  return {
    kind: "wildcard",
    text: `Wildcard with ${stars} capture${stars > 1 ? "s" : ""} and ${fixed} fixed characters. A whole-label * is exactly one label (*.example.com does not match a.b.example.com nor example.com); a * inside a label is any run of characters. Among wildcards, the one with more fixed characters wins; ties go to the rule higher in the file.`,
  };
}

// patternRegex mirrors the proxy's wildcard matching, for the capture hint.
function patternRegex(p) {
  const name = p.trim().replace(/^\^/, "").replace(/\$$/, "").replace(/\\\./g, ".").toLowerCase();
  const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const parts = name.split(".").map((label) => label === "*" ? "([^.]+)" : label.split("*").map(esc).join("([^.]*)"));
  try { return new RegExp("^" + parts.join("\\.") + "$", "i"); } catch (_) { return null; }
}

function sampleNames(p) {
  const t = p.trim();
  if (!t) return "";
  if (/^none$/i.test(t)) return "<none>";
  if (/^any$/i.test(t) || /^\^?\.\*\$?$/.test(t)) return "example.org <none>";
  return t.replace(/^\^/, "").replace(/\$$/, "").replace(/\\\./g, ".").replace(/\*/g, "www").toLowerCase();
}

function tryNames() {
  return val("f-try").split(/[\s,]+/).filter(Boolean).slice(0, 10).map((n) => (/^<?none>?$/i.test(n) ? "" : n));
}

// quickChecks returns [step, message] pairs; the server checks the rest.
function quickChecks(v) {
  const out = [];
  const info = patternInfo($("f-pattern").value);
  if (!$("f-listener").value) out.push([0, "Choose the listener this rule belongs to."]);
  if (!v.pattern) out.push([0, "The pattern is required."]);
  else if (info.bad) out.push([0, info.text]);
  if (radio("f-action") === "serve") {
    if (!routeLines($("f-routes").value)) out.push([1, "Write at least one service rule, e.g. type=static_content; prefix=/; base_dir=/opt/www/site"]);
    if (radio("f-certsrc") === "local" && !$("f-cert-ca").value) out.push([2, "Choose a certificate authority, or make one on the CAs page first."]);
  } else if (v.action !== "deny") {
    const host = val("f-target-host");
    if (!host) out.push([1, "A target host is required for an allow rule."]);
    const bare = /\$(?!\{)(\d*)/.exec(host);
    if (bare) out.push([1, bare[1] ? `Write \${${bare[1]}}, not $${bare[1]}: captures are always in braces.` : "A $ must start ${1}, ${2}, … or ${host}."]);
    for (const [, ref] of host.matchAll(/\$\{([^}]*)\}/g)) {
      if (ref !== "host" && !/^(0|[1-9]\d*)$/.test(ref)) out.push([1, `Unknown reference \${${ref}}: use \${1}, \${2}, … for the *s, or \${host} for the whole name.`]);
    }
    const port = val("f-target-port");
    if (!port) out.push([1, "A target port is required for an allow rule."]);
    else if ((!/^\d+$/.test(port) || +port < 1 || +port > 65535)) out.push([1, "The target port must be a number from 1 to 65535."]);
    if (radio("f-tls") === "terminate" && radio("f-certsrc") === "local" && !$("f-cert-ca").value) out.push([2, "Choose a certificate authority, or make one on the CAs page first."]);
    for (const [id, label] of [["f-agg", "aggregated speed"], ["f-conn", "per-connection speed"]]) {
      const s = val(id);
      if (s && !RATE_RE.test(s)) out.push([2, `The ${label} needs a number and a unit, like 1Gbit or 15MiB/s.`]);
    }
  }
  return out;
}

// syncWizard shows the fields that apply and the hints for what is typed.
function syncWizard() {
  const pattern = $("f-pattern").value;
  if (!ed.tryTouched) $("f-try").value = sampleNames(pattern);
  const info = patternInfo(pattern);
  $("pattern-kind").hidden = !info.kind;
  setText($("pattern-kind"), info.kind);
  setText($("pattern-text"), info.text);
  $("pattern-help").classList.toggle("bad", !!info.bad);

  const allow = radio("f-action") !== "deny";
  const serve = radio("f-action") === "serve";
  $("target-fields").hidden = !allow || serve;
  $("routes-fields").hidden = !serve;
  $("deny-help").hidden = allow;
  $("options-allow").hidden = !allow;
  $("options-deny").hidden = allow;

  // ${1}, ${2}, ... in the target: explain them with a sample name.
  const cap = $("capture-help");
  cap.hidden = !allow || serve || info.kind !== "wildcard";
  if (!cap.hidden) {
    const sample = tryNames().find((n) => n) || sampleNames(pattern);
    const re = patternRegex(pattern);
    const m = re && sample ? re.exec(sample) : null;
    cap.replaceChildren();
    cap.append("Each * is a capture you can use in the target host: ${1}, ${2}, … from the left; ${host} is the whole name. Always in braces, so ${1}hello is exact.");
    if (m) {
      const parts = m.slice(1).map((g, i) => `\${${i + 1}} = ${g}`).join(", ");
      const host = val("f-target-host");
      const expanded = host.replace(/\$\{(\d+|host)\}/g, (_, a) => m[a === "host" ? 0 : +a] ?? "");
      const line = el("span");
      line.append("For ", el("code", "", sample), `: ${parts}`);
      if (host && host !== expanded) line.append(" → ", el("code", "", expanded));
      cap.append(" ", line);
    }
  }

  if (serve) setRadio("f-tls", "terminate"); // serving needs the requests decrypted
  for (const r of document.querySelectorAll('input[name="f-tls"]')) r.disabled = serve && r.value === "pass";
  const term = radio("f-tls") === "terminate";
  $("tls-fields").hidden = !term;
  setText($("tls-help"), serve
    ? "The proxy decrypts here with its own certificate and answers the requests itself, by the service rules."
    : term
    ? "The proxy decrypts here with its own certificate and opens a new connection to the target."
    : "The encrypted stream goes to the target untouched; the target presents its own certificate.");
  const src = radio("f-certsrc");
  $("cert-ca-field").hidden = src !== "local";
  for (const n of document.querySelectorAll(".auto-only")) n.hidden = src !== "auto";
  setText($("cert-names-hint"), src === "local" ? "optional: names or globs (*.dev.abc.com, *.abc.com); any other name is refused" : "optional");
  const upTLS = $("f-upstream-tls").value !== "false";
  for (const n of document.querySelectorAll(".upstream-tls-only")) n.hidden = !upTLS || serve;
  $("f-upstream-tls").closest(".field").hidden = serve;
  $("proxy-group").hidden = serve;
  $("proxy-version-field").hidden = !$("f-proxy").checked;
}

function showStep(n) {
  ed.step = Math.max(0, Math.min(2, n));
  for (const s of document.querySelectorAll("#editor .step")) s.hidden = +s.dataset.step !== ed.step;
  for (const b of document.querySelectorAll("#editor .step-btn")) b.setAttribute("aria-selected", String(+b.dataset.step === ed.step));
  $("editor-back").hidden = ed.step === 0;
  $("editor-next").hidden = ed.step === 2;
}

function paintVerdict() {
  const v = formValues();
  const quick = quickChecks(v);
  for (const b of document.querySelectorAll("#editor .step-btn")) b.classList.toggle("bad", quick.some(([s]) => s === +b.dataset.step));
  const res = ed.result;
  const state = $("preview-state");
  let error = "";
  if (quick.length) error = quick[0][1];
  else if (res && !res.ok) error = res.error || "Not valid.";
  setText($("editor-error"), error);

  const warns = $("editor-warnings");
  warns.replaceChildren();
  const list = [];
  if (res && res.stale) list.push("The config file changed since you opened this rule. Reload from file before saving.");
  if (res && res.ok) list.push(...(res.warnings || []));
  for (const w of list) warns.appendChild(el("li", "", w));
  warns.hidden = list.length === 0;
  $("editor-reload").hidden = !(res && res.stale) && !ed.conflict;

  if (quick.length) { setText(state, "fix the form first"); state.className = "preview-state bad"; }
  else if (ed.pending) { setText(state, "checking…"); state.className = "preview-state busy"; }
  else if (res && res.ok) { setText(state, "valid"); state.className = "preview-state ok"; }
  else if (res) { setText(state, "not valid"); state.className = "preview-state bad"; }
  setText($("editor-block"), res && res.block ? res.block : "");

  const routes = $("try-results");
  routes.replaceChildren();
  for (const r of (res && res.ok && !quick.length && res.routes) || []) {
    const li = el("li");
    li.appendChild(el("span", "sni", r.sni === "" ? "(no SNI)" : r.sni));
    let text, cls;
    if (r.error) { text = `→ error: ${r.error}`; cls = "bad"; }
    else if (r.allow && r.thisRule) { text = `→ ${r.target} via this rule`; cls = "ok"; }
    else if (r.allow) { text = `→ ${r.target}, handled by ${r.pattern} (line ${r.ruleLine})`; cls = "other"; }
    else if (r.thisRule) { text = "→ denied by this rule"; cls = "ok"; }
    else if (r.ruleLine) { text = `→ denied by ${r.pattern} (line ${r.ruleLine})`; cls = "other"; }
    else { text = "→ denied: no rule matches"; cls = "bad"; }
    li.appendChild(el("span", "to " + cls, text));
    routes.appendChild(li);
  }

  $("editor-save").disabled = !!quick.length || ed.pending || !(res && res.ok) || !!(res && res.stale) || ed.saving;
}

// onFormChange: hints now, server check after a pause in typing.
function onFormChange() {
  syncWizard();
  ed.conflict = false;
  clearTimeout(ed.timer);
  const quick = quickChecks(formValues());
  ed.pending = quick.length === 0;
  if (quick.length) ed.result = null;
  paintVerdict();
  if (!quick.length) ed.timer = setTimeout(validateNow, 300);
}

function validateNow() {
  const seq = ++ed.seq;
  ed.pending = true;
  paintVerdict();
  dryRun("api/rules/validate", { line: ed.rule ? ed.rule.line : 0, baseHash: ed.base.hash, baseMtime: ed.base.mtime, values: formValues(), snis: tryNames() })
    .then((data) => {
      if (seq !== ed.seq || !$("editor").open) return;
      ed.pending = false;
      ed.result = data;
      paintVerdict();
    });
}

function fillListenerSelect(selected) {
  const sel = $("f-listener");
  sel.replaceChildren();
  for (const l of ui.state.listeners) {
    if (l.redirect) continue; // has no rules
    const o = el("option", "", `${l.name} [${listenAddrs(l)}]`);
    o.value = l.name;
    sel.appendChild(o);
  }
  if (![...sel.options].some((o) => o.value === selected)) { // a name the file has but no listener
    const o = el("option", "", `${selected} (unknown listener)`);
    o.value = selected;
    if (selected) sel.appendChild(o);
  }
  sel.value = selected || (sel.options[0] && sel.options[0].value) || "";
  sel.closest(".field").title = sel.options.length > 1 ? "Which port this rule answers on" : "The only listener";
}

function openEditor(r, listenerName) {
  const s = ui.state;
  if (!s || !s.file.editable) return;
  fillListenerSelect((r && (r.listener || r.values.listener)) || listenerName || onlyListener());
  ed.rule = r || null;
  ed.base = { hash: s.file.hash, mtime: s.file.mtime };
  ed.result = null;
  ed.conflict = false;
  ed.saving = false;
  ed.tryTouched = false;
  setText($("editor-title"), r ? `Edit ${r.pattern}` : "Add rule");
  setText($("editor-save"), r ? "Save" : "Add rule");
  setText($("editor-hint"), `Saved to ${s.file.path} (previous version kept as a backup) and applied at once.` +
    (r ? ` This is the [[host]] at line ${r.line}.` : " A new rule goes after the last one."));
  setText($("preview-title"), `Will be written to ${s.file.path}`);
  prefill(r ? r.values : null);
  fillCASelect(ed.ca);
  showStep(0);
  $("editor").showModal();
  $("f-pattern").focus();
  onFormChange();
}

// reloadEditor starts the edit again from the file as it is now.
function reloadEditor() {
  const s = ui.state;
  if (!ed.rule) { ed.base = { hash: s.file.hash, mtime: s.file.mtime }; onFormChange(); return; }
  const fresh = allRules(s).find((r) => r.key === ed.rule.key && r.line > 0);
  if (!fresh) {
    $("editor").close();
    toast("That rule is no longer in the config file as it was; nothing was saved.", true);
    return;
  }
  openEditor(fresh, fresh.listener);
  toast("Reloaded the rule from the file. Make your change again.");
}

$("editor-cancel").addEventListener("click", () => $("editor").close());
$("editor-reload").addEventListener("click", reloadEditor);
$("editor-back").addEventListener("click", () => showStep(ed.step - 1));
$("editor-next").addEventListener("click", () => showStep(ed.step + 1));
for (const b of document.querySelectorAll("#editor .step-btn")) b.addEventListener("click", () => showStep(+b.dataset.step));
for (const b of document.querySelectorAll("#pattern-examples .pick")) {
  b.addEventListener("click", () => { $("f-pattern").value = b.dataset.example; onFormChange(); $("f-pattern").focus(); });
}
$("editor-form").addEventListener("input", (ev) => {
  if (ev.target.id === "f-try") ed.tryTouched = $("f-try").value.trim() !== "";
  onFormChange();
});
$("editor-form").addEventListener("change", onFormChange);
$("editor").addEventListener("close", () => { clearTimeout(ed.timer); ed.seq++; });
$("editor-form").addEventListener("submit", (ev) => {
  ev.preventDefault();
  const values = formValues();
  if (quickChecks(values).length || !(ed.result && ed.result.ok)) { paintVerdict(); return; }
  const btn = $("editor-save");
  ed.saving = true;
  btn.disabled = true;
  const was = ed.rule;
  api("api/rules/save", { line: was ? was.line : 0, baseHash: ed.base.hash, baseMtime: ed.base.mtime, values })
    .then((d) => {
      $("editor").close();
      if (d.unchanged) toast("Nothing to save: the rule is as it was.");
      else toast(was ? `Saved ${values.pattern}` : `Added ${values.pattern}${d.backup ? ` (previous file kept as ${d.backup})` : ""}`);
      for (const w of d.warnings || []) toast(`Warning: ${w}`);
      saveProblems(d);
      if (d.restartNeeded) toast("bind/port changed: that part needs a restart.");
    })
    .catch((e) => {
      ed.conflict = e.status === 409;
      ed.result = { ok: false, error: e.message, block: ed.result && ed.result.block };
      paintVerdict();
    })
    .finally(() => { ed.saving = false; paintVerdict(); });
});

// ---------- listener wizard ----------
//
// Two steps: name and address, then optional overrides of [global]. Same
// flow as the rule wizard: quick checks here, a dry run on the server 300 ms
// after typing stops, the [[listener]] block and the extra changes the save
// will make (notes) shown before Save is enabled.

const led = { l: null, base: null, step: 0, seq: 0, timer: 0, result: null, pending: false, conflict: false, saving: false };
const L_FIELDS = {
  name: "l-name", bind: "l-bind", port: "l-port", proxy_trust_source: "l-ppf", max_connections: "l-maxconn",
  handshake_timeout: "l-hs", idle_timeout: "l-idle", half_close_timeout: "l-half",
  max_aggregated_speed: "l-agg", max_single_connection_speed: "l-conn",
};

function lFormValues() {
  const orig = led.l ? led.l.values || {} : {};
  const v = {};
  for (const [k, id] of Object.entries(L_FIELDS)) {
    const now = val(id);
    const o = orig[k] ?? "";
    v[k] = now === String(o).trim() ? o : now; // keep the file's spelling when unchanged
  }
  return v;
}

function lQuickChecks(v) {
  const out = [];
  const others = ui.state.listeners.filter((l) => !led.l || l.name !== led.l.name).map((l) => l.name.toLowerCase());
  if (!v.name) out.push([0, "The name is required."]);
  else if (!LISTENER_NAME_RE.test(v.name)) out.push([0, "The name may use letters, digits, spaces and - _ @ # ~ ( ) [ ] < > \" ' (up to 64, no space at either end)."]);
  else if (others.includes(v.name.toLowerCase())) out.push([0, `There is already a listener called ${v.name}.`]);
  if (!v.port) out.push([0, "The port is required."]);
  else if (!/^\d+$/.test(v.port) || +v.port < 1 || +v.port > 65535) out.push([0, "The port must be a number from 1 to 65535."]);
  for (const [k, label] of [["max_connections", "Max connections"], ["handshake_timeout", "The handshake timeout"],
    ["idle_timeout", "The idle timeout"], ["half_close_timeout", "The half-close timeout"]]) {
    if (v[k] && !/^\d+$/.test(String(v[k]).trim())) out.push([1, `${label} must be a whole number${k === "max_connections" ? "" : " of seconds"}.`]);
  }
  for (const [k, label] of [["max_aggregated_speed", "aggregated speed"], ["max_single_connection_speed", "per-connection speed"]]) {
    if (v[k] && !RATE_RE.test(v[k])) out.push([1, `The ${label} needs a number and a unit, like 1Gbit or 15MiB/s.`]);
  }
  return out;
}

function lShowStep(n) {
  led.step = Math.max(0, Math.min(1, n));
  for (const st of document.querySelectorAll("#lst-editor .step")) st.hidden = +st.dataset.step !== led.step;
  for (const b of document.querySelectorAll("#lst-editor .step-btn")) b.setAttribute("aria-selected", String(+b.dataset.step === led.step));
  $("lst-back").hidden = led.step === 0;
  $("lst-next").hidden = led.step === 1;
}

function lPaintVerdict() {
  const quick = lQuickChecks(lFormValues());
  for (const b of document.querySelectorAll("#lst-editor .step-btn")) b.classList.toggle("bad", quick.some(([st]) => st === +b.dataset.step));
  const res = led.result;
  setText($("lst-error"), quick.length ? quick[0][1] : res && !res.ok ? res.error || "Not valid." : "");

  const warns = $("lst-warnings");
  warns.replaceChildren();
  const list = [];
  if (res && res.stale) list.push("The config file changed since you opened this listener. Reload from file before saving.");
  if (res && res.ok) list.push(...(res.warnings || []));
  for (const w of list) warns.appendChild(el("li", "", w));
  warns.hidden = list.length === 0;

  const notes = $("lst-notes");
  notes.replaceChildren();
  const nl = (res && res.ok && !quick.length && res.notes) || [];
  for (const n of nl) notes.appendChild(el("li", "", n));
  notes.hidden = nl.length === 0;
  $("lst-reload").hidden = !(res && res.stale) && !led.conflict;

  const state = $("lst-preview-state");
  if (quick.length) { setText(state, "fix the form first"); state.className = "preview-state bad"; }
  else if (led.pending) { setText(state, "checking…"); state.className = "preview-state busy"; }
  else if (res && res.ok) { setText(state, "valid"); state.className = "preview-state ok"; }
  else if (res) { setText(state, "not valid"); state.className = "preview-state bad"; }
  else { setText(state, ""); state.className = "preview-state"; }
  setText($("lst-block"), res && res.block ? res.block : "");
  $("lst-save").disabled = !!quick.length || led.pending || !(res && res.ok) || !!(res && res.stale) || led.saving;
}

function lOnFormChange() {
  led.conflict = false;
  clearTimeout(led.timer);
  const quick = lQuickChecks(lFormValues());
  led.pending = quick.length === 0;
  if (quick.length) led.result = null;
  lPaintVerdict();
  if (!quick.length) led.timer = setTimeout(lValidateNow, 300);
}

function lValidateNow() {
  const seq = ++led.seq;
  led.pending = true;
  lPaintVerdict();
  dryRun("api/listeners/validate", { line: led.l ? led.l.line : 0, baseHash: led.base.hash, baseMtime: led.base.mtime, values: lFormValues() })
    .then((data) => {
      if (seq !== led.seq || !$("lst-editor").open) return;
      led.pending = false;
      led.result = data;
      lPaintVerdict();
    });
}

function openListenerEditor(l) {
  const s = ui.state;
  if (!s || !s.file.editable) return;
  led.l = l || null;
  led.base = { hash: s.file.hash, mtime: s.file.mtime };
  led.result = null;
  led.conflict = false;
  led.saving = false;
  const v = (l && l.values) || {};
  const start = {
    name: v.name ?? (l ? l.name : ""), bind: v.bind ?? (l ? l.bind : ""), port: v.port ?? (l ? String(l.port) : ""),
  };
  for (const [k, id] of Object.entries(L_FIELDS)) $(id).value = start[k] ?? v[k] ?? "";
  setText($("lst-title"), l ? `Edit listener ${l.name}` : "Add listener");
  setText($("lst-save"), l ? "Save" : "Add listener");
  setText($("lst-hint"), `Saved to ${s.file.path} (previous version kept as a backup) and applied at once: the port opens or moves right away.`);
  setText($("lst-preview-title"), `Will be written to ${s.file.path}`);
  lShowStep(0);
  $("lst-editor").showModal();
  $("l-name").focus();
  lOnFormChange();
}

function lReloadEditor() {
  const s = ui.state;
  if (!led.l) { led.base = { hash: s.file.hash, mtime: s.file.mtime }; lOnFormChange(); return; }
  const fresh = s.listeners.find((l) => l.name === led.l.name);
  if (!fresh) {
    $("lst-editor").close();
    toast("That listener is no longer in the config file as it was; nothing was saved.", true);
    return;
  }
  openListenerEditor(fresh);
  toast("Reloaded the listener from the file. Make your change again.");
}

$("add-listener").addEventListener("click", () => openListenerEditor(null));
$("lst-cancel").addEventListener("click", () => $("lst-editor").close());
$("lst-reload").addEventListener("click", lReloadEditor);
$("lst-back").addEventListener("click", () => lShowStep(led.step - 1));
$("lst-next").addEventListener("click", () => lShowStep(led.step + 1));
for (const b of document.querySelectorAll("#lst-editor .step-btn")) b.addEventListener("click", () => lShowStep(+b.dataset.step));
$("lst-form").addEventListener("input", lOnFormChange);
$("lst-editor").addEventListener("close", () => { clearTimeout(led.timer); led.seq++; });
$("lst-form").addEventListener("submit", (ev) => {
  ev.preventDefault();
  const values = lFormValues();
  if (lQuickChecks(values).length || !(led.result && led.result.ok)) { lPaintVerdict(); return; }
  led.saving = true;
  $("lst-save").disabled = true;
  const was = led.l;
  api("api/listeners/save", { line: was ? was.line : 0, baseHash: led.base.hash, baseMtime: led.base.mtime, values })
    .then((d) => {
      $("lst-editor").close();
      if (d.unchanged) toast("Nothing to save: the listener is as it was.");
      else toast(was ? `Saved listener ${values.name}` : `Added listener ${values.name}${d.backup ? ` (previous file kept as ${d.backup})` : ""}`);
      for (const w of d.warnings || []) toast(`Warning: ${w}`);
      saveProblems(d);
      if (d.restartNeeded) toast("Part of this change needs a restart.");
    })
    .catch((e) => {
      led.conflict = e.status === 409;
      led.result = { ok: false, error: e.message, block: led.result && led.result.block };
      lPaintVerdict();
    })
    .finally(() => { led.saving = false; lPaintVerdict(); });
});

// ---------- toasts ----------

// saveProblems reports what a saved change could not do once applied, such
// as a listener whose port is taken.
function saveProblems(d) {
  for (const p of (d && d.problems) || []) toast(`Saved, but: ${p}`, true);
}

function toast(msg, bad) {
  const box = $("toasts");
  const t = el("div", bad ? "toast bad" : "toast", msg);
  t.setAttribute("role", bad ? "alert" : "status");
  box.appendChild(t);
  while (box.children.length > 3) box.firstChild.remove();
  setTimeout(() => t.remove(), bad ? 7000 : 3500);
}

// ---------- toolbar ----------

$("filter").addEventListener("input", (ev) => {
  ui.filter = ev.target.value.trim().toLowerCase();
  renderAll();
  paint();
});
$("expand-all").addEventListener("click", () => {
  for (const name of ui.L.keys()) ui.expandedL.add(name);
  for (const key of ui.R.keys()) ui.expanded.add(key);
  renderAll();
  paint();
});
$("collapse-all").addEventListener("click", () => {
  ui.expandedL.clear();
  ui.expanded.clear();
  ui.openConns.clear();
  renderAll();
  paint();
});

// ---------- tabs ----------

function selectTab(name, force) {
  if (!TABS.includes(name)) name = "rules";
  if (!force && ui.tab === "config" && name !== "config" && cfgDirty() &&
      !confirm("Leave the config editor? Your unsaved text stays in this page until you reload it.")) {
    history.replaceState(null, "", "#config");
    return;
  }
  ui.tab = name;
  for (const b of document.querySelectorAll(".tab")) b.setAttribute("aria-selected", String(b.dataset.tab === name));
  for (const t of TABS) $("tab-" + t).hidden = t !== name;
  const hash = name === "rules" ? "" : "#" + name;
  if (location.hash !== hash) history.replaceState(null, "", hash || location.pathname + location.search);
  clearInterval(ui.pageTimer);
  ui.pageTimer = 0;
  const every = { certs: 10000, log: 2000 }[name];
  const load = { certs: loadCerts, ca: loadCAs, log: loadLog, config: loadConfigOnce }[name];
  if (load) {
    const run = () => { if (!document.hidden) load().catch((e) => { if (e.status !== 401) pageError(name, e); }); };
    run();
    if (every) ui.pageTimer = setInterval(run, every);
  }
  if (name === "rules") requestAnimationFrame(redrawCharts);
  if (name === "flows") { flowConnect(); renderFlows(); } else flowDisconnect();
}

function pageError(name, e) {
  if (name === "config") cfgMessage("bad", e.message);
  else toast(`Could not load ${name === "certs" ? "certificates" : "the log"}: ${e.message}`, true);
}

for (const b of document.querySelectorAll(".tab")) b.addEventListener("click", () => selectTab(b.dataset.tab));
window.addEventListener("hashchange", () => selectTab(location.hash.slice(1)));

// ---------- flow log ----------
//
// Every connection, short ones included: api/flows sends an opened, routed
// and closed event for each, and every 5 s the authoritative list of open
// connections, which repairs whatever a dropped event lost (a connection
// missing from two snapshots in a row is taken as closed). Every view carries
// a sequence number, and a card only ever moves to a newer one, so a snapshot
// taken just before an event can't undo it. The socket is open only while
// this page shows; on (re)connect the server starts it with the last 35 s of
// closed connections, or all it remembers (2000) when "Show all closed" is
// on. A closed card stays FLOW_FADE_MS, then collapses out, unless "Show all
// closed" is on. Cards are repainted only when their data changed, at most
// every FLOW_PAINT_MS; open ones' durations tick once a second.

const FLOW_FADE_MS = 30000;
const FLOW_KEEP = 2000; // closed connections kept here, as on the server
const FLOW_ROWS = 1000; // rows in the DOM at most
const FLOW_LEAVE_MS = 450; // as .flow.leaving in app.css
const FLOW_PAINT_MS = 200;
const FLOW_RESULT = {
  closed: ["chip", "closed"], denied: ["chip bad", "denied"], failed: ["chip bad", "failed"],
  rejected: ["chip warn", "rejected"], acme: ["chip tls", "ACME"],
};

const flows = {
  ws: null, map: new Map(), skew: 0, retry: 0, timer: 0, raf: 0, painted: 0, filter: "", showAll: false, shown: new Set(), stripe: 0,
  history: "recent", // what the open socket was asked for: "recent" or "all"
  armed: new Map(), // id -> disarm timer
};

function flowUpsert(v, fresh) {
  const e = flows.map.get(v.id);
  if (!e) {
    flows.map.set(v.id, { f: v, tr: null, cells: null, misses: 0, ver: 1, painted: 0, fresh: fresh && !v.ended });
    return;
  }
  if (!v.ended || e.f.ended) e.misses = 0; // seen: it is not missing
  // Closed is final, and an older view (a snapshot taken before an event
  // that arrived first) never replaces a newer one.
  if (e.f.ended && !v.ended) return;
  if (v.seq <= e.f.seq && !(v.ended && !e.f.ended)) return;
  e.f = v;
  e.ver++;
}

function flowPrune() {
  if (flows.map.size <= FLOW_KEEP) return; // cheap test first: most messages change nothing here
  const closed = [...flows.map.values()].filter((e) => e.f.ended);
  if (closed.length <= FLOW_KEEP) return;
  closed.sort((a, b) => a.f.ended - b.f.ended);
  for (const e of closed.slice(0, closed.length - FLOW_KEEP)) { if (e.tr) e.tr.remove(); flows.map.delete(e.f.id); }
}

function flowMessage(m) {
  if (m.type === "events") {
    for (const ev of m.events) flowUpsert(ev.flow, ev.type === "open");
  } else if (m.type === "snapshot") {
    flows.skew = Date.now() - m.now;
    if (m.full) {
      for (const e of flows.map.values()) if (e.tr) e.tr.remove();
      flows.map.clear();
      flows.shown.clear();
    }
    for (const v of m.closed) flowUpsert(v, false);
    const open = new Set();
    for (const v of m.active) { open.add(v.id); flowUpsert(v, false); }
    if (!m.truncated && !m.full) {
      for (const e of flows.map.values()) {
        if (e.f.ended || open.has(e.f.id) || e.f.started > m.now - 1000) continue;
        if (++e.misses >= 2) { e.f = { ...e.f, ended: m.now, result: "closed", reason: "closed (its close event was missed)" }; e.ver++; }
      }
    }
  }
  flowPrune();
  scheduleFlows();
}

// scheduleFlows renders on the next frame, but not more often than every
// FLOW_PAINT_MS however fast events come.
function scheduleFlows() {
  if (flows.raf) return;
  const wait = Math.max(0, flows.painted + FLOW_PAINT_MS - performance.now());
  flows.raf = setTimeout(() => requestAnimationFrame(() => { flows.raf = 0; renderFlows(); }), wait);
}

function flowMatches(f) {
  const q = flows.filter;
  if (!q) return true;
  if (q.startsWith("#")) return String(f.id) === q.slice(1);
  return [f.listener, f.src, f.local, f.sni, f.rule, f.dst, f.peer, f.result, f.reason, String(f.id), ...flowTags(f).map((t) => t[2])]
    .some((s) => s && s.toLowerCase().includes(q));
}

// flowIcon draws one of the small icons the tags use.
const FLOW_ICONS = {
  // A closed padlock: TLS end to end, never opened here.
  lock: "M5 7V5.5a3 3 0 0 1 6 0V7M4 7h8v6H4z",
  // A chain link broken in two: TLS ends at the proxy.
  broken: "M6.5 9.5 5 11a2.1 2.1 0 0 1-3-3l1.5-1.5M9.5 6.5 11 5a2.1 2.1 0 0 1 3 3l-1.5 1.5M6 3.5 6.5 5M3.5 6 5 6.5M10 12.5 9.5 11M12.5 10 11 9.5",
  bolt: "M9 1.5 3.5 9H8l-1 5.5L12.5 7H8z",
  arrow: "M2.5 8h10M9 4.5 12.5 8 9 11.5",
  gauge: "M2.5 11a5.5 5.5 0 1 1 11 0M8 11l3-4",
};
function flowIcon(name) {
  const svg = document.createElementNS(SVG, "svg");
  svg.setAttribute("viewBox", "0 0 16 16");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("class", "f-ico");
  const p = document.createElementNS(SVG, "path");
  p.setAttribute("d", FLOW_ICONS[name]);
  p.setAttribute("fill", name === "bolt" ? "currentColor" : "none");
  p.setAttribute("stroke", "currentColor");
  p.setAttribute("stroke-width", name === "bolt" ? "1" : "1.6");
  p.setAttribute("stroke-linecap", "round");
  p.setAttribute("stroke-linejoin", "round");
  svg.appendChild(p);
  return svg;
}

// flowTags says how a connection is handled, as [class, icon, text, title].
function flowTags(f) {
  const out = [];
  if (f.via) out.push(["t-via", "arrow", `via ${f.via.replace(/:\d+$/, "")}`, `A load balancer at ${f.via} sent a PROXY v${f.viaVersion} header with the client's address`]);
  if (f.tls === "http") {
    out.push(["t-warn", "", "plain HTTP → https://", "http_to_https_redirect: each request was answered with a redirect to the same URL on https://"]);
  } else if (f.tls === "passthrough") {
    out.push(["t-e2e", "lock", "end-to-end TLS", "Passed through: the TLS stream reaches the target untouched; the proxy never decrypts it"]);
  } else if (f.tls === "terminated") {
    out.push(["t-term", "broken", `terminated${f.clientTLS ? " · " + f.clientTLS : ""}`, `TLS ends here: the proxy decrypts with its own certificate${f.resumed ? " (resumed session)" : ""}`]);
    const up = { tls: ["t-up", "→ TLS", "A new TLS connection to the target, its certificate verified"],
      "tls-unverified": ["t-warn", "→ TLS, unverified", "A new TLS connection to the target, its certificate NOT verified (upstream_tls_verify = false)"],
      plain: ["t-warn", "→ plaintext", "The target gets plain, unencrypted traffic (upstream_tls = false)"] }[f.upstream];
    if (up) out.push([up[0], "", up[1], up[2]]);
  }
  if (f.alpn) out.push(["t-muted", "", f.tls === "terminated" ? f.alpn : `offers ${f.alpn.replaceAll(",", ", ")}`,
    f.tls === "terminated" ? "Application protocol agreed with the client (ALPN)" : "Application protocols the client offered (ALPN); the target chose"]);
  if (f.tls && f.tls !== "http") {
    out.push(f.proxyOut ? ["t-proxy", "", `PROXY v${f.proxyOut}`, `The target was told the client's address in a PROXY protocol v${f.proxyOut} header`]
      : ["t-muted", "", "no PROXY", "No PROXY protocol header is sent to the target"]);
  }
  if (f.relay === "splice") out.push(["t-zero", "bolt", "zero-copy", "Relayed with splice(2): bytes go socket → kernel pipe → socket and never enter the proxy"]);
  else if (f.relay === "splice+copy") out.push(["t-zero half", "bolt", "zero-copy one way", "One direction is spliced in the kernel, the other copied through a buffer"]);
  else if (f.relay === "copy") out.push(["t-muted", "", "copied", f.tls === "terminated" ? "Copied through a buffer: decrypted TLS can't be spliced" : "Copied through a buffer (splice off or unavailable)"]);
  if (f.connLimit) out.push(["t-limit", "gauge", `≤ ${fmtRate(f.connLimit)}`, "Speed limit for this connection, each direction"]);
  if (f.shareLimit) out.push(["t-limit", "gauge", `shared ≤ ${fmtRate(f.shareLimit)}`, "Speed limit it shares with the other connections of its rule or listener, each direction"]);
  if (f.cached) out.push(["t-muted", "", "cached route", "Routed from the route cache"]);
  return out;
}

function paintTags(box, f) {
  box.replaceChildren();
  for (const [cls, icon, text, title] of flowTags(f)) {
    const t = el("span", `f-tag ${cls}`);
    t.title = title;
    if (icon) t.appendChild(flowIcon(icon));
    t.appendChild(el("span", "", text));
    box.appendChild(t);
  }
  box.hidden = !box.children.length;
}

// A flow is a two-line card: what it is (name, target, result, duration)
// on top, where it came from and what it moved underneath.
function buildFlowRow(e) {
  const card = el("div", "flow");
  const top = el("div", "f-top");
  const sub = el("div", "f-sub");
  card.append(top, sub);
  const cells = {
    dot: el("span", "f-dot"), id: el("span", "f-id"), sni: el("span", "f-sni"), arrow: el("span", "f-arrow", "→"),
    dstMain: el("span", "f-dst"), dstSub: el("span", "f-peer"), chip: el("span", "chip"), duration: el("span", "f-dur"),
    listener: el("span", "f-l"), src: el("span", "f-src"), rule: el("span", "f-rule"), opened: el("span", "f-when"),
    bytes: el("span", "f-bytes"), up: el("span"), down: el("span"), reasonText: el("span", "f-reason"),
  };
  const stop = el("button", "stop");
  stop.type = "button";
  stop.appendChild(el("span", "sq"));
  const stopLabel = el("span", "", "Stop");
  stop.appendChild(stopLabel);
  stop.title = "Close both legs of this connection";
  stop.addEventListener("click", () => onFlowStop(e, stop, stopLabel));
  cells.stop = stop;
  const what = el("span", "f-what");
  what.append(cells.sni, cells.arrow, cells.dstMain, cells.dstSub);
  const end = el("span", "f-end");
  end.append(cells.chip, cells.duration, stop);
  top.append(cells.dot, cells.id, what, end);
  cells.bytes.append(arrowIcon("up"), cells.up, arrowIcon("down"), cells.down);
  cells.tags = el("div", "f-tags");
  sub.append(cells.listener, cells.src, cells.rule, cells.opened, cells.bytes, cells.reasonText);
  card.insertBefore(cells.tags, sub);
  e.tr = card;
  e.cells = cells;
  // Its stripe is chosen once, here: a card keeps its shade wherever it moves
  // (mint while open, the matching grey once closed).
  card.classList.toggle("alt", flows.stripe++ % 2 === 1);
  if (e.fresh) {
    card.classList.add("fresh");
    setTimeout(() => card.classList.remove("fresh"), 1700);
    e.fresh = false;
  }
}

function paintFlowRow(e, now) {
  const f = e.f, c = e.cells;
  setText(c.id, `#${f.id}`);
  if (c.openedFor !== f.started) { setText(c.opened, `opened ${fmtClock(f.started + flows.skew)}`); c.openedFor = f.started; }
  setText(c.listener, `listener=${f.listener}`);
  c.listener.title = "Listener";
  setText(c.src, `src=${f.src}`);
  c.src.title = f.local ? `Client; it connected to ${f.local}` : "Client";
  // The name with the port the client connected to: files.demo.test:443.
  const port = (/:(\d+)$/.exec(f.local || "") || [])[1];
  setText(c.sni, !f.routed ? "waiting for ClientHello…" : `${f.sni || "<no name>"}${port ? ":" + port : ""}`);
  c.sni.classList.toggle("pending", !f.routed);
  c.sni.title = !f.routed ? "The client has not sent its ClientHello yet" : f.sni ? "Server name (SNI)" : "The client sent no server name";
  c.arrow.hidden = !f.dst;
  setText(c.dstMain, f.dst || "");
  setText(c.dstSub, f.peer && f.peer !== f.dst ? `(${f.peer})` : "");
  c.dstSub.title = "The address it connected to";
  c.rule.hidden = !f.rule;
  setText(c.rule, f.rule ? `rule=${f.rule}` : "");
  setText(c.duration, fmtAge((f.ended || now) - f.started));
  c.duration.title = f.ended ? "How long it was open" : "Open for";
  setText(c.up, fmtBytes(f.bytesUp));
  setText(c.down, fmtBytes(f.bytesDown));
  c.bytes.title = "Bytes to the upstream / to the client";
  c.bytes.hidden = !f.routed;
  const [cls, label] = f.ended ? (FLOW_RESULT[f.result] || ["chip", f.result]) : ["chip live", f.terminated ? "open · terminated" : "open"];
  c.chip.className = cls;
  setText(c.chip, label);
  setText(c.reasonText, f.ended ? f.reason || "" : "");
  c.reasonText.hidden = !f.ended || !f.reason;
  c.reasonText.title = f.reason || "";
  c.stop.hidden = !!f.ended;
  paintTags(c.tags, f);
  const cl = e.tr.classList;
  cl.toggle("ended", !!f.ended);
  for (const r of ["denied", "failed", "rejected"]) cl.toggle(r, f.result === r);
}

// leaveFlow collapses a card that has been closed for FLOW_FADE_MS, then
// takes it out of the list, so nothing is left behind.
function leaveFlow(e) {
  if (e.leaving || !e.tr || !e.tr.isConnected) return;
  e.leaving = true;
  const card = e.tr;
  card.style.maxHeight = `${card.offsetHeight}px`; // collapse from its real height
  void card.offsetHeight; // apply it first, so the transition has a start
  card.classList.add("leaving");
  setTimeout(() => {
    card.remove();
    card.classList.remove("leaving");
    card.style.maxHeight = "";
    e.leaving = false;
  }, FLOW_LEAVE_MS);
}

function renderFlows() {
  flows.painted = performance.now();
  const now = Date.now() - flows.skew;
  const list = [];
  let open = 0, recent = 0, kept = 0;
  for (const e of flows.map.values()) {
    const f = e.f;
    if (!f.ended) open++;
    else { kept++; if (now - f.ended < FLOW_FADE_MS) recent++; }
    if (f.ended && !flows.showAll && now - f.ended >= FLOW_FADE_MS) continue;
    if (flowMatches(f)) list.push(e);
  }
  // Open connections first, newest first; then closed ones, latest closed first.
  list.sort((a, b) => (!a.f.ended !== !b.f.ended ? (a.f.ended ? 1 : -1)
    : a.f.ended ? b.f.ended - a.f.ended || b.f.id - a.f.id : b.f.started - a.f.started || b.f.id - a.f.id));
  const rows = list.slice(0, FLOW_ROWS);
  const want = new Set(rows);
  for (const e of flows.shown) {
    if (want.has(e) || !e.tr) continue;
    // Expired: collapse out. Filtered away or over the cap: gone at once.
    if (e.f.ended && !flows.showAll && now - e.f.ended >= FLOW_FADE_MS && flowMatches(e.f)) leaveFlow(e);
    else e.tr.remove();
  }
  const body = $("flows");
  let prev = null;
  for (const e of rows) {
    if (!e.tr) buildFlowRow(e);
    if (e.leaving) { // back before it finished leaving ("Show all closed" turned on)
      e.tr.classList.remove("leaving");
      e.tr.style.maxHeight = "";
      e.leaving = false;
    }
    if (e.painted !== e.ver) { paintFlowRow(e, now); e.painted = e.ver; }
    else if (!e.f.ended) setText(e.cells.duration, fmtAge(now - e.f.started)); // only the clock moved
    const at = prev ? prev.nextSibling : body.firstChild;
    if (at !== e.tr) body.insertBefore(e.tr, at);
    prev = e.tr;
  }
  flows.shown = want;
  $("flow-empty").hidden = rows.length > 0;
  setText($("flow-empty"), flows.map.size ? "No connection matches the filter." :
    "No connections yet. New ones show here as they open, and stay for 30 seconds after they close.");
  let meta = `${open} open · ${recent} closed in the last 30 s · ${kept} closed kept`;
  if (list.length > rows.length) meta += ` · showing the first ${rows.length}`;
  if (!flows.ws) meta += " · reconnecting";
  setText($("flow-meta"), meta);
}

function onFlowStop(e, btn, label) {
  const id = e.f.id;
  if (!flows.armed.has(id)) {
    btn.classList.add("armed");
    setText(label, "Confirm");
    flows.armed.set(id, setTimeout(() => { flows.armed.delete(id); btn.classList.remove("armed"); setText(label, "Stop"); }, ARM_MS));
    return;
  }
  clearTimeout(flows.armed.get(id));
  flows.armed.delete(id);
  btn.classList.remove("armed");
  btn.disabled = true;
  setText(label, "Closing");
  api("api/connections/stop", { id })
    .then(() => toast(`Stopped #${id}`))
    .catch((err) => toast(`Could not stop #${id}: ${err.message}`, true))
    .finally(() => { btn.disabled = false; setText(label, "Stop"); });
}

function flowConnect() {
  if (flows.ws || ui.tab !== "flows" || !ui.csrf) return;
  clearTimeout(flows.timer);
  const base = location.pathname.replace(/[^/]*$/, "");
  flows.showAll = $("flow-closed").checked; // a reload may have restored the box
  flows.history = flows.showAll ? "all" : "recent";
  const ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}${base}api/flows?history=${flows.history}`);
  flows.ws = ws;
  ws.onopen = () => { flows.retry = 0; };
  ws.onmessage = (ev) => {
    let m;
    try { m = JSON.parse(ev.data); } catch (_) { return; }
    flowMessage(m);
  };
  ws.onclose = (ev) => {
    if (flows.ws !== ws) return;
    flows.ws = null;
    renderFlows();
    if (ev.code === 4000) { showLogin(); return; }
    if (ui.tab !== "flows") return;
    const delay = Math.min(10000, 500 * 2 ** flows.retry);
    flows.retry = Math.min(flows.retry + 1, 5);
    flows.timer = setTimeout(flowConnect, delay);
  };
}

function flowDisconnect() {
  clearTimeout(flows.timer);
  if (flows.ws) { const ws = flows.ws; flows.ws = null; ws.close(); }
}

$("flow-filter").addEventListener("input", (ev) => { flows.filter = ev.target.value.trim().toLowerCase(); renderFlows(); });
$("flow-closed").addEventListener("change", (ev) => {
  flows.showAll = ev.target.checked;
  // The open socket only brought the last 35 s: fetch the whole history.
  if (flows.showAll && flows.history !== "all" && flows.ws) { flowDisconnect(); flowConnect(); }
  for (const e of flows.map.values()) e.painted = 0; // the fade state changes for every card
  renderFlows();
});
// Durations tick and faded rows leave, also when no event arrives.
setInterval(() => { if (ui.tab === "flows") renderFlows(); }, 1000);

// ---------- config reference ----------
//
// Every key by section, from reference.json (generated from config_keys.go
// and kept current by a test). Fetched once, the first time it is opened.

let refData = null;

function renderRef() {
  const q = $("ref-filter").value.trim().toLowerCase();
  const body = $("ref-body");
  const jump = $("ref-jump");
  body.replaceChildren();
  jump.replaceChildren();
  let shown = 0;
  refData.forEach((sec, i) => {
    const keys = sec.keys.filter((k) => !q || [k.key, k.default, k.meaning, sec.section].some((s) => s.toLowerCase().includes(q)));
    if (!keys.length) return;
    shown += keys.length;
    const box = el("section", "ref-sec");
    box.id = `ref-s${i}`;
    box.appendChild(el("h3", "ref-name", sec.section));
    box.appendChild(el("p", "ref-about", sec.about));
    const dl = el("div", "ref-keys");
    for (const k of keys) {
      const row = el("div", "ref-key");
      const name = el("code", "ref-k", k.key);
      name.title = `Copy "${k.key} = " to the clipboard`;
      name.addEventListener("click", () => {
        navigator.clipboard?.writeText(`${k.key} = `).then(() => toast(`Copied “${k.key} = ”`), () => {});
      });
      const def = el("span", "ref-def", k.default ? `default ${k.default}` : "");
      row.append(name, def, el("p", "ref-m", k.meaning));
      dl.appendChild(row);
    }
    box.appendChild(dl);
    body.appendChild(box);
    const a = el("button", "chip pick", sec.section);
    a.type = "button";
    a.addEventListener("click", () => box.scrollIntoView({ block: "start", behavior: "smooth" }));
    jump.appendChild(a);
  });
  if (!shown) body.appendChild(el("p", "page-note", "No key matches."));
}

$("cfg-ref").addEventListener("click", () => {
  const d = $("ref");
  const show = () => { renderRef(); d.showModal(); $("ref-filter").focus(); };
  if (refData) return show();
  fetch("reference.json", { credentials: "same-origin" })
    .then((r) => { if (!r.ok) throw new Error(r.statusText); return r.json(); })
    .then((data) => { refData = data; show(); })
    .catch((e) => toast(`Could not load the reference: ${e.message}`, true));
});
$("ref-close").addEventListener("click", () => $("ref").close());
$("ref-filter").addEventListener("input", () => renderRef());
$("ref").addEventListener("click", (ev) => { if (ev.target === $("ref")) $("ref").close(); }); // the backdrop

// ---------- certificate authorities ----------

let caNext = "";

function loadCAs() {
  return getJSON("api/cas").then(renderCAs);
}

// Each CA is a card: who it is and until when on top, what it issues in the
// middle, where it is used and its fingerprint below, actions on the right.
function renderCAs(d) {
  caNext = d.next;
  setText($("ca-meta"), `in ${d.caRoot}`);
  const list = $("cas");
  list.replaceChildren();
  if (!d.cas.length) {
    const empty = el("div", "empty");
    const img = el("img");
    img.src = "logo-sleep.svg";
    img.alt = "";
    empty.append(img, el("span", "", "No CA yet. Generate one, import yours, or save a rule with cert = local-ca (that makes ca001)."));
    list.appendChild(empty);
    return;
  }
  for (const ca of d.cas) {
    const card = el("div", "ca-card" + (ca.error ? " broken" : ""));
    const main = el("div", "ca-main");
    const head = el("div", "ca-head");
    head.append(el("span", "chip mono", ca.id), el("span", "ca-name", ca.name || "—"));
    if (!ca.error) {
      head.appendChild(el("span", ca.selfSigned ? "chip" : "chip tls", ca.selfSigned ? "self-signed root" : `intermediate of ${ca.issuer}`));
      head.appendChild(el("span", "chip t-muted", ca.keyType));
      const exp = el("span", ca.daysLeft < 30 ? "chip bad" : "chip ok", `until ${ca.notAfter} · ${ca.daysLeft} days`);
      exp.title = ca.selfSigned ? "Renewed with the same key before it expires" : "Issued elsewhere: import a renewed one before it expires";
      head.appendChild(exp);
    }
    main.appendChild(head);
    if (ca.error) {
      main.appendChild(el("div", "ca-line bad", ca.error));
    } else {
      const issues = el("div", "ca-line");
      issues.append(el("span", "ca-k", "issues"), el("span", "", ca.settings || "—"));
      main.appendChild(issues);
      if (ca.configError) main.appendChild(el("div", "ca-line bad", `config.toml: ${ca.configError} (previous settings in use)`));
      const facts = el("div", "ca-line ca-facts");
      facts.append(el("span", "ca-k", "issued"), el("span", "", `${ca.issued} certificate${ca.issued === 1 ? "" : "s"}`),
        el("span", "ca-k", "used by"), el("span", "", ca.rules.length ? ca.rules.map((l) => "line " + l).join(", ") : "no rule"));
      main.appendChild(facts);
      const fp = el("div", "ca-line");
      const v = el("span", "mono ca-fp", ca.fingerprint.match(/.{2}/g).join(":"));
      fp.append(el("span", "ca-k", "SHA-256"), v);
      main.appendChild(fp);
    }
    const act = el("div", "ca-actions");
    if (!ca.error) {
      const dl = el("a", "btn btn-quiet", "Download certificate");
      dl.href = `api/cas/cert?id=${encodeURIComponent(ca.id)}`;
      dl.title = "The CA certificate, for clients to trust (the key is never offered)";
      const [set] = actionButton("Settings", "");
      set.title = "Edit what this CA issues (its config.toml)";
      set.addEventListener("click", () => openCASettings(ca.id));
      act.append(dl, set);
    }
    const [del, delLabel] = actionButton("Delete", "danger");
    del.disabled = ca.rules.length > 0;
    del.title = ca.rules.length ? "Used by a rule: change the rule first" : "Move this CA to the archive (deleted after 14 days)";
    let armed = 0;
    del.addEventListener("click", () => {
      if (!armed) {
        del.classList.add("armed");
        setText(delLabel, "Confirm delete");
        armed = setTimeout(() => { armed = 0; del.classList.remove("armed"); setText(delLabel, "Delete"); }, ARM_MS);
        return;
      }
      clearTimeout(armed);
      del.disabled = true;
      api("api/cas/delete", { id: ca.id })
        .then(() => { toast(`Deleted ${ca.id}: moved to the archive`); return loadCAs(); })
        .catch((e) => { del.disabled = false; toast(`Could not delete ${ca.id}: ${e.message}`, true); });
    });
    act.appendChild(del);
    card.append(main, act);
    list.appendChild(card);
  }
}

$("ca-generate").addEventListener("click", () => {
  setText($("ca-gen-hint"), `It becomes ${caNext || "the next CA"}, in its own folder.`);
  setText($("ca-gen-error"), "");
  $("ca-gen-name").value = "";
  $("ca-gen-org").value = "";
  $("ca-gen").showModal();
  $("ca-gen-name").focus();
});
$("ca-gen-cancel").addEventListener("click", () => $("ca-gen").close());
$("ca-gen-form").addEventListener("submit", (ev) => {
  ev.preventDefault();
  $("ca-gen-save").disabled = true;
  const [alg, bits] = $("ca-gen-key").value.split(":");
  api("api/cas/generate", { commonName: val("ca-gen-name"), organization: val("ca-gen-org"), keyAlgorithm: alg, keyBits: +bits,
    hashAlgorithm: $("ca-gen-hash").value, validityDays: Math.round(+$("ca-gen-years").value * 365) || 3650 })
    .then((d) => { $("ca-gen").close(); toast(`Generated ${d.id}`); return loadCAs(); })
    .catch((e) => setText($("ca-gen-error"), e.message))
    .finally(() => { $("ca-gen-save").disabled = false; });
});

let caSetID = "";

function openCASettings(id) {
  caSetID = id;
  setText($("ca-set-title"), `${id} settings`);
  setText($("ca-set-error"), "");
  getJSON(`api/cas/config?id=${encodeURIComponent(id)}`).then((d) => {
    setText($("ca-set-path"), d.path);
    $("ca-set-text").value = d.text;
    if (d.error) setText($("ca-set-error"), `The file on disk is not in use: ${d.error}`);
    $("ca-set").showModal();
  }).catch((e) => toast(`Could not read ${id}'s settings: ${e.message}`, true));
}
$("ca-set-cancel").addEventListener("click", () => $("ca-set").close());
$("ca-set-form").addEventListener("submit", (ev) => {
  ev.preventDefault();
  $("ca-set-save").disabled = true;
  cfgPost("api/cas/config", { id: caSetID, text: $("ca-set-text").value })
    .then((d) => {
      if (!d.ok) { setText($("ca-set-error"), d.error); return; }
      $("ca-set").close();
      toast(`${caSetID} now issues: ${d.settings}`);
      return loadCAs();
    })
    .catch((e) => setText($("ca-set-error"), e.message))
    .finally(() => { $("ca-set-save").disabled = false; });
});

$("ca-import").addEventListener("click", () => {
  setText($("ca-imp-hint"), `It becomes ${caNext || "the next CA"}. Use it for your organisation's CA, so the certificates the proxy issues are trusted wherever that CA is.`);
  setText($("ca-imp-error"), "");
  $("ca-imp-cert").value = "";
  $("ca-imp-key").value = "";
  $("ca-imp").showModal();
  $("ca-imp-cert").focus();
});
$("ca-imp-cancel").addEventListener("click", () => $("ca-imp").close());
$("ca-imp").addEventListener("close", () => { $("ca-imp-key").value = ""; }); // don't keep a key in the page
$("ca-imp-form").addEventListener("submit", (ev) => {
  ev.preventDefault();
  $("ca-imp-save").disabled = true;
  api("api/cas/import", { cert: $("ca-imp-cert").value, key: $("ca-imp-key").value })
    .then((d) => { $("ca-imp").close(); toast(`Imported as ${d.id}`); return loadCAs(); })
    .catch((e) => setText($("ca-imp-error"), e.message))
    .finally(() => { $("ca-imp-save").disabled = false; });
});

// ---------- certificates ----------

const CERT_STATUS = { ok: "chip ok", expiring: "chip warn", missing: "chip warn", expired: "chip bad", failing: "chip bad" };

let certData = null;
let certFilter = "";

function loadCerts() {
  return getJSON("api/certs").then((d) => { certData = d; renderCerts(d); });
}

$("cert-filter").addEventListener("input", (ev) => {
  certFilter = ev.target.value.trim().toLowerCase();
  if (certData) renderCerts(certData);
});

// certMatches: the filter against the name, every name in the certificate,
// the CA and the status.
function certMatches(c) {
  if (!certFilter) return true;
  return [c.Name, ...(c.Names || []), c.Source === "auto" ? "acme" : c.CA, c.Status]
    .some((s) => s && s.toLowerCase().includes(certFilter));
}

// removeButton archives the certificate after a second click to confirm.
function removeButton(c) {
  const [b, label] = actionButton("Remove", "danger");
  b.title = c.Source === "auto"
    ? "Move it to cert_path's _archive (deleted after 14 days) and request a new one"
    : `Move it to CA ${c.CA}'s _archive (deleted after 14 days); a new one is issued when a client asks for it`;
  let armed = 0;
  b.addEventListener("click", () => {
    if (!armed) {
      b.classList.add("armed");
      setText(label, "Confirm remove");
      armed = setTimeout(() => { armed = 0; b.classList.remove("armed"); setText(label, "Remove"); }, ARM_MS);
      return;
    }
    clearTimeout(armed);
    b.disabled = true;
    api("api/certs/remove", { source: c.Source, ca: c.CA || "", name: c.Name })
      .then(() => { toast(`Removed ${c.Name}: moved to the archive`); return loadCerts(); })
      .catch((e) => { b.disabled = false; toast(`Could not remove ${c.Name}: ${e.message}`, true); });
  });
  return b;
}

function renderCerts(d) {
  setText($("cert-meta"), `automatic ones live in ${d.certPath || "—"} · ${d.acmeDirectory || ""}`);
  const list = $("certs");
  list.replaceChildren();
  const all = d.certs || [];
  const certs = all.filter(certMatches);
  if (!certs.length) {
    const empty = el("div", "empty");
    const img = el("img");
    img.src = "logo-sleep.svg";
    img.alt = "";
    empty.append(img, el("span", "", all.length ? `No certificate matches “${certFilter}”.` : "No rule terminates TLS, so there are no certificates."));
    list.appendChild(empty);
    return;
  }
  for (const c of certs) {
    const card = el("div", "ca-card" + (c.LastError ? " broken" : ""));
    const main = el("div", "ca-main");
    const head = el("div", "ca-head");
    head.append(el("span", "ca-name mono", c.Name), el("span", CERT_STATUS[c.Status] || "chip", c.Status));
    head.appendChild(el("span", c.Source === "auto" ? "chip tls" : "chip", c.Source === "auto" ? "ACME" : `local CA ${c.CA}`));
    if (c.NotAfter) {
      const exp = el("span", c.DaysLeft < 8 ? "chip bad" : c.DaysLeft < 30 ? "chip warn" : "chip ok", `until ${c.NotAfter} · ${c.DaysLeft} days`);
      if (c.RenewFrom) exp.title = `Renewed automatically from ${c.RenewFrom}`;
      head.appendChild(exp);
    }
    main.appendChild(head);
    if (c.Names && c.Names.length && c.Names.join(", ") !== c.Name) {
      const names = el("div", "ca-line");
      names.append(el("span", "ca-k", "names"), el("span", "mono", c.Names.join(", ")));
      main.appendChild(names);
    }
    const facts = el("div", "ca-line ca-facts");
    facts.append(el("span", "ca-k", "issuer"), el("span", "", c.Issuer || "—"),
      el("span", "ca-k", "renews from"), el("span", "num", c.RenewFrom || "—"),
      el("span", "ca-k", "used by"), el("span", "", (c.RuleLines || []).map((l) => "line " + l).join(", ") || "no rule"));
    main.appendChild(facts);
    if (c.LastError) {
      main.appendChild(el("div", "ca-line bad", `Last attempt failed: ${c.LastError}`));
      const next = el("div", "ca-line");
      next.append(el("span", "ca-k", "next attempt"), el("span", "num", c.NextAttempt || "—"));
      main.appendChild(next);
    } else if (c.Detail) {
      main.appendChild(el("div", "ca-line", c.Detail));
    }
    if (c.Dir) main.appendChild(el("div", "ca-line mono ca-fp", c.Dir));
    card.appendChild(main);
    const act = el("div", "ca-actions");
    if (c.Source === "auto" && c.LastError) {
      const [b] = actionButton("Retry now", "");
      b.addEventListener("click", () => {
        b.disabled = true;
        api("api/certs/retry", { domain: c.Name })
          .then(() => { toast(`Retrying ${c.Name}`); setTimeout(() => loadCerts().catch(() => {}), 1500); })
          .catch((e) => { b.disabled = false; toast(`Could not retry ${c.Name}: ${e.message}`, true); });
      });
      act.appendChild(b);
    }
    if (c.Removable) act.appendChild(removeButton(c));
    if (act.childElementCount) card.appendChild(act);
    list.appendChild(card);
  }
}

// ---------- log ----------

function loadLog() {
  return getJSON("api/log?n=800&filter=" + encodeURIComponent($("log-filter").value)).then((d) => {
    const box = $("log-lines");
    const text = (d.lines || []).join("\n");
    if (box.textContent !== text) box.textContent = text;
    if ($("log-follow").checked) box.scrollTop = box.scrollHeight;
  });
}

let logTimer = 0;
$("log-filter").addEventListener("input", () => {
  clearTimeout(logTimer);
  logTimer = setTimeout(() => loadLog().catch(() => {}), 250);
});

// ---------- config file editor ----------

const cfg = { hash: "", mtime: "", loaded: "", once: false };
const cfgDirty = () => cfg.once && $("cfg").value !== cfg.loaded;

function gutter() {
  const n = $("cfg").value.split("\n").length;
  let s = "";
  for (let i = 1; i <= n; i++) s += i + "\n";
  setText($("gutter"), s);
  $("gutter").scrollTop = $("cfg").scrollTop;
  $("cfg-dirty").hidden = !cfgDirty();
}

function cfgMessage(kind, text) {
  $("cfg-result").hidden = true;
  const m = $("cfg-msg");
  m.hidden = false;
  m.className = "msg " + kind;
  m.textContent = text;
  const at = /\bline (\d+)/.exec(text); // jump to the offending line
  if (kind === "bad" && at) cfgJump(+at[1]);
}

// cfgJump selects line n of the editor and scrolls it into view.
function cfgJump(n) {
  const area = $("cfg");
  const lines = area.value.split("\n");
  n = Math.max(1, Math.min(n, lines.length));
  const start = lines.slice(0, n - 1).join("\n").length + (n > 1 ? 1 : 0);
  area.focus();
  area.setSelectionRange(start, start + lines[n - 1].length);
  area.scrollTop = Math.max(0, (n - 8) * 19.5);
}

// lineButton is a "line N" link that jumps the editor there.
function lineButton(n) {
  const b = el("button", "v-line", `line ${n}`);
  b.type = "button";
  b.title = "Show this line in the editor";
  b.addEventListener("click", () => cfgJump(n));
  return b;
}

// problemRow is one warning or error, with its line and the text there.
function problemRow(kind, p) {
  const row = el("div", `v-problem ${kind}`);
  row.appendChild(el("span", `v-icon ${kind}`, kind === "bad" ? "✕" : "!"));
  const body = el("div", "v-pbody");
  const head = el("div", "v-phead");
  if (p.line) head.appendChild(lineButton(p.line));
  head.appendChild(el("span", "v-ptext", p.text));
  body.appendChild(head);
  const src = p.line ? $("cfg").value.split("\n")[p.line - 1] : undefined;
  if (src !== undefined && src.trim()) body.appendChild(el("code", "v-src", src));
  row.appendChild(body);
  return row;
}

function treeItems(items) {
  const dl = el("dl", "v-items");
  for (const it of items || []) {
    const dt = el("dt", "", it.key);
    const dd = el("dd");
    dd.appendChild(el("span", "v-val", it.value));
    if (it.from) dd.appendChild(el("span", "v-from", it.from === "default" ? "default" : `from ${it.from}`));
    if (it.from) dt.classList.add("inherited");
    dl.append(dt, dd);
  }
  return dl;
}

const TREE_TAGS = { passthrough: "chip", terminate: "chip tls", deny: "chip bad" };

function treeNodeEl(n, depth) {
  const d = el("details", `v-node d${depth}`);
  d.open = depth === 0 ? n.title === "Listeners" : depth === 1 && !!n.children;
  const sum = el("summary");
  sum.appendChild(el("span", "v-title", n.title));
  if (n.tag) sum.appendChild(el("span", TREE_TAGS[n.tag] || "chip", n.tag));
  if (n.note) sum.appendChild(el("span", "v-note", n.note));
  if (n.line) sum.appendChild(lineButton(n.line));
  d.appendChild(sum);
  const body = el("div", "v-body");
  if (n.items && n.items.length) body.appendChild(treeItems(n.items));
  for (const c of n.children || []) body.appendChild(treeNodeEl(c, depth + 1));
  d.appendChild(body);
  return d;
}

// showValidation renders the Validate answer: green with the settings tree
// when the file is valid, its warnings in yellow; red with the exact line
// when it is not.
function showValidation(d) {
  $("cfg-msg").hidden = true;
  const box = $("cfg-result");
  box.hidden = false;
  box.classList.remove("stale");
  box.replaceChildren();
  const head = el("div", "v-head");
  box.appendChild(head);
  if (!d.ok) {
    box.className = "vresult bad";
    head.append(el("span", "v-icon bad", "✕"), el("strong", "", "Not valid"), el("span", "v-note", "nothing was saved"));
    box.appendChild(problemRow("bad", { text: d.error, line: d.line }));
    if (d.line) cfgJump(d.line);
    return;
  }
  const problems = d.problems || [];
  box.className = problems.length ? "vresult warn" : "vresult ok";
  const tree = d.tree || [];
  const ls = (tree.find((n) => n.title === "Listeners") || { children: [] }).children;
  const rules = ls.reduce((n, l) => n + (l.children || []).length, 0);
  head.append(el("span", `v-icon ${problems.length ? "warn" : "ok"}`, problems.length ? "!" : "✓"),
    el("strong", "", problems.length ? `Valid, with ${problems.length} warning${problems.length === 1 ? "" : "s"}` : "Valid"),
    el("span", "v-note", `${ls.length} listener${ls.length === 1 ? "" : "s"} · ${rules} rule${rules === 1 ? "" : "s"}` +
      ((d.autoDomains || []).length ? ` · ${d.autoDomains.length} automatic certificate name${d.autoDomains.length === 1 ? "" : "s"}` : "")));
  for (const p of problems) box.appendChild(problemRow("warn", p));
  const t = el("div", "v-tree");
  for (const n of tree) t.appendChild(treeNodeEl(n, 0));
  box.appendChild(t);
}

function listBackups() {
  return getJSON("api/config/backups").then((d) => {
    const b = d.backups || [];
    const sel = $("cfg-backups");
    sel.replaceChildren(el("option", "", `Load a backup… (${b.length})`));
    sel.firstChild.value = "";
    for (const name of b) sel.appendChild(el("option", "", name));
  });
}

function loadConfigOnce() {
  if (cfg.once) return Promise.resolve();
  return loadConfig();
}

function loadConfig() {
  return getJSON("api/config").then((d) => {
    if (!d.ok) { cfgMessage("bad", d.error); return; }
    cfg.once = true;
    cfg.hash = d.hash; cfg.mtime = d.mtime; cfg.loaded = d.text;
    $("cfg").value = d.text;
    setText($("cfg-path"), d.path);
    gutter();
    $("cfg-msg").hidden = true;
    return listBackups();
  });
}

// cfgPost posts editor text; validation errors come back as {ok:false}.
function cfgPost(path, body) {
  return api(path, body).catch((e) => {
    if (e.status === 200 || e.status === 409) return { ok: false, error: e.message, line: e.data && e.data.line };
    throw e;
  });
}

$("cfg").addEventListener("input", () => {
  gutter();
  $("cfg-result").classList.add("stale"); // describes the text before this edit
});
$("cfg").addEventListener("scroll", () => { $("gutter").scrollTop = $("cfg").scrollTop; });
$("cfg").addEventListener("keydown", (e) => {
  if (e.key === "Tab") { e.preventDefault(); document.execCommand("insertText", false, "    "); }
  if ((e.metaKey || e.ctrlKey) && e.key === "s") { e.preventDefault(); $("cfg-save").click(); }
});
$("cfg-reload").addEventListener("click", () => {
  if (!cfgDirty() || confirm("Discard your changes?")) loadConfig().catch((e) => cfgMessage("bad", e.message));
});
$("cfg-backups").addEventListener("change", (e) => {
  const name = e.target.value;
  e.target.value = "";
  if (!name) return;
  getJSON("api/config/backup?name=" + encodeURIComponent(name))
    .then((d) => {
      if (!d.ok) return cfgMessage("bad", d.error);
      $("cfg").value = d.text;
      gutter();
      cfgMessage("warn", `Loaded ${name} into the editor. Nothing changes until you press Save & apply.`);
    })
    .catch((e) => cfgMessage("bad", e.message));
});
$("cfg-validate").addEventListener("click", () => {
  cfgPost("api/config/validate", { text: $("cfg").value })
    .then(showValidation)
    .catch((e) => cfgMessage("bad", e.message));
});
$("cfg-test").addEventListener("click", () => {
  const snis = $("cfg-snis").value.split(/[\s,]+/).filter(Boolean);
  if (!snis.length) return cfgMessage("warn", "Type one or more host names first.");
  cfgPost("api/config/test", { text: $("cfg").value, snis })
    .then((d) => {
      if (!d.ok) return cfgMessage("bad", d.error);
      cfgMessage("ok", (d.results || []).map((r) => r.error ? `${r.sni}  ->  ERROR ${r.error}`
        : r.allow ? `${r.sni}  ->  ${r.target}${r.terminated ? "  (TLS terminated here)" : "  (passed through)"}  [${r.kind}: ${r.pattern}]`
        : `${r.sni}  ->  DENY${r.ruleLine ? `  [${r.kind}: ${r.pattern}]` : "  (no rule matched)"}`).join("\n"));
    })
    .catch((e) => cfgMessage("bad", e.message));
});
$("cfg-save").addEventListener("click", () => {
  const text = $("cfg").value;
  cfgPost("api/config/save", { text, baseHash: cfg.hash, baseMtime: cfg.mtime })
    .then((d) => {
      if (!d.ok) return cfgMessage("bad", d.error);
      cfg.hash = d.hash; cfg.mtime = d.mtime; cfg.loaded = text;
      gutter();
      if (d.unchanged) return cfgMessage("ok", "Nothing to save: the text matches the file.");
      const problems = d.problems || [];
      cfgMessage(problems.length ? "bad" : d.restartNeeded || (d.warnings || []).length ? "warn" : "ok",
        (problems.length ? `Saved, but not everything could be applied. Previous version kept as ${d.backup}.` : `Saved and applied. Previous version kept as ${d.backup}.`) +
        problems.map((p) => "\n" + p).join("") +
        (d.restartNeeded ? "\nbind/port changed: that part needs a restart." : "") + (d.warnings || []).map((w) => "\nWarning: " + w).join(""));
      return listBackups();
    })
    .catch((e) => cfgMessage("bad", e.message));
});
window.addEventListener("beforeunload", (e) => { if (cfgDirty()) { e.preventDefault(); e.returnValue = ""; } });

// ---------- connection & sign-in ----------

function setStatus(state, text) {
  $("status").dataset.state = state;
  setText($("status-text"), text);
}

function scheduleReconnect() {
  clearTimeout(ui.reconnectTimer);
  const delay = Math.min(10000, 500 * 2 ** ui.retry);
  ui.retry = Math.min(ui.retry + 1, 5);
  ui.reconnectTimer = setTimeout(() => {
    checkSession().then((ok) => {
      if (ok) connect();
      else if (ok === null) scheduleReconnect();
    });
  }, delay);
}

function connect() {
  if (ui.ws) return;
  clearTimeout(ui.reconnectTimer);
  setStatus("connecting", "Connecting");
  if (!ui.state) {
    // First paint without waiting for the socket; never older than a frame.
    getJSON("api/state").then((s) => { if (!ui.state || s.now > ui.state.now) applyState(s); }).catch(() => {});
  }
  const base = location.pathname.replace(/[^/]*$/, "");
  const ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}${base}api/ws`);
  ui.ws = ws;
  ws.onopen = () => { ui.retry = 0; setStatus("live", "Live"); };
  ws.onmessage = (ev) => {
    let s;
    try { s = JSON.parse(ev.data); } catch (_) { return; }
    applyState(s);
  };
  ws.onclose = (ev) => {
    if (ui.ws !== ws) return;
    ui.ws = null;
    if (ev.code === 4000) { showLogin(); return; } // the server says: signed out
    setStatus("down", "Reconnecting");
    scheduleReconnect();
  };
}

// checkSession resolves true when the console should connect, false when
// the sign-in form is showing, and null when the server is unreachable.
function checkSession() {
  return fetch("api/session", { credentials: "same-origin" })
    .then(async (r) => {
      if (r.status === 401) { showLogin(); return false; }
      if (!r.ok) return null;
      const s = await r.json();
      if (!s.ok) { showLogin(); return false; }
      ui.csrf = s.csrf;
      showApp();
      return true;
    })
    .catch(() => null);
}

function showLogin() {
  if (ui.ws) { const ws = ui.ws; ui.ws = null; ws.close(); }
  flowDisconnect();
  clearTimeout(ui.reconnectTimer);
  clearInterval(ui.pageTimer);
  ui.pageTimer = 0;
  if ($("editor").open) $("editor").close();
  if ($("lst-editor").open) $("lst-editor").close();
  ui.csrf = "";
  $("app").hidden = true;
  $("tabs").hidden = true;
  $("logout").hidden = true;
  $("login").hidden = false;
  setStatus("down", "Signed out");
  $("password").focus();
}

let appShown = false;
function showApp() {
  const first = !appShown || !$("login").hidden;
  appShown = true;
  $("login").hidden = true;
  $("app").hidden = false;
  $("tabs").hidden = false;
  $("logout").hidden = false;
  if (first) selectTab(location.hash.slice(1), true);
}

$("login-form").addEventListener("submit", (ev) => {
  ev.preventDefault();
  const btn = $("login-submit");
  btn.disabled = true;
  setText($("login-error"), "");
  fetch("api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify({ password: $("password").value }),
  })
    .then(async (r) => {
      let d = {};
      try { d = await r.json(); } catch (_) { /* not JSON */ }
      if (r.status === 401) throw new Error("That password is not correct. Try again.");
      if (!r.ok || !d.ok) throw new Error(d.error || "Sign-in failed. Check that the proxy is running.");
      $("password").value = "";
      ui.csrf = d.csrf;
      showApp();
      connect();
    })
    .catch((e) => { setText($("login-error"), e.message); $("password").select(); })
    .finally(() => { btn.disabled = false; });
});

$("logout").addEventListener("click", () => {
  api("api/logout", {}).catch(() => {}).finally(showLogin);
});

// ---------- start ----------

setInterval(paint, 500);
setInterval(sample, 1000);
window.addEventListener("resize", redrawCharts);
window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", redrawCharts);
checkSession().then((ok) => {
  if (ok) connect();
  else if (ok === null) { showApp(); setStatus("down", "Reconnecting"); scheduleReconnect(); }
});
