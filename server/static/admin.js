const $ = (id) => document.getElementById(id);
const ESC = { "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" };
const esc = (v) => String(v == null ? "" : v).replace(/[&<>"']/g, (c) => ESC[c]);

const LANG = (navigator.language || "").toLowerCase().startsWith("ru") ? "ru" : "en";
const EN = {
  "VPNCheck · центр": "VPNCheck · center",
  "Админ-токен: его напечатал установщик сервера, на компьютере со стендом он в %APPDATA%\\VPNCheckStand\\agent.json; на сервере - /opt/vpnagent/admin_token":
    "Admin token: printed by the server installer; on the stand PC it is in %APPDATA%\\VPNCheckStand\\agent.json; on the server - /opt/vpnagent/admin_token",
  "токен": "token",
  "Войти": "Sign in",
  "Карта": "Map", "Агенты": "Agents", "Матрица": "Matrix", "Сайты": "Sites", "Ошибки": "Errors",
  "▶ Проверить всех": "▶ Check all",
  "⬆ Обновить агентов": "⬆ Update agents",
  "токен не принят": "token rejected",
  "сервер не ответил: ": "server did not respond: ",
  " назад": " ago",
  "Попросить всех агентов проверить узлы сейчас?": "Ask all agents to check the nodes now?",
  "Разослать всем агентам команду обновить приложение?": "Send all agents the command to update the app?",
  "последний отчёт ненадёжный (белые списки, VPN или неполный) - цифры из прошлого надёжного":
    "the last report is unreliable (whitelists, VPN or incomplete) - numbers are from the previous reliable one",
  "падение": "crash", "ошибка проверки": "check error", "ошибка установки обновления": "update install error",
  "геолокация": "geolocation", "пинг": "ping", "канал: запуск": "link: start", "канал: команда": "link: command",
  "канал: работа в фоне": "link: background work", "ответ на команду": "command reply",
  "команда обновиться": "update command", "ядро не запустилось": "core did not start",
  "отчёт не принят сервером": "report rejected by the server",
  "канал: связь": "link: connection", "обновление": "update", "push-токен": "push token", "отчёт отложен": "report deferred",
  "ядро не вышло в интернет": "core could not reach the internet", "ядро упало на узле": "core crashed on a node",
  "включён VPN": "VPN is on", "нет обычного интернета (белые списки?)": "no regular internet (whitelists?)",
  "ядро xray не вышло в интернет через эту сеть - узлы не проверены": "the xray core could not reach the internet over this network - nodes not checked",
  "выход совпал с Wi-Fi или маршрут разошёлся": "exit matched Wi-Fi or the route diverged",
  "маршрут под сомнением: ядро держалось сети только по адресу": "route in doubt: the core held the network by address only",
  "проверены не все узлы": "not all nodes were checked",
  "не проверен: %s": "not checked: %s",
  "приложение не поддерживает настройки узла": "the app does not support this node's settings",
  "агент отказался: частный адрес или небезопасные настройки": "the agent refused: private address or unsafe settings",
  "ядро xray упало на этом узле": "the xray core crashed on this node",
  "ядро xray не вышло в интернет через эту сеть": "the xray core could not reach the internet over this network",
  "на телефоне включён VPN": "VPN is on on the phone",
  "Telegram: не отправлено": "Telegram: not sent", "резервная копия": "backup", "TLS-порт": "TLS port", "сервер": "server",
  "нужен токен": "token required",
  "только что": "just now", " мин": " min", " ч": " h", " дн": " d",
  "за 12 ч отчитались: ": "reported in 12 h: ",
  "регионов: ": "regions: ", "всего: ": "total: ",
  " из ": " of ",
  "пока никого": "no one yet",
  "Узел": "Node", "Сайт": "Site",
  "DNS сети подменил адрес": "the network's DNS faked the address",
  "DNS сети не нашёл имя": "the network's DNS couldn't resolve the name",
  "DNS - DNS сети подменил адрес или не нашёл имя": "DNS - the network's DNS faked the address or couldn't resolve the name",
  "агент": "agent",
  "ошибок нет": "no errors",
  "Новых агентов: %s - появятся здесь в течение суток после подключения": "New agents: %s - they'll show up here within 24 hours of connecting",
  "Пока нет данных. Новые агенты попадают в матрицу через сутки после подключения - так выдуманные агенты не исказят картину; их последние отчёты уже видны во вкладке «Агенты».":
    "No data yet. New agents join the matrix 24 hours after connecting, so fake agents can't skew the picture; their latest reports are already on the Agents tab.",
  "Пока нет данных - сайты задаются в стенде: Центр управления агентами → «Узлы и обновления»":
    "No data yet - sites are set in the stand: Agent control center → \"Nodes and updates\"",
  "агенты заберут обновление в течение 15 минут": "agents will pick up the update within 15 minutes",
  "толчок отправлен: онлайн-агенты проверят сразу, остальные - при следующем выходе на связь (до 15 минут)": "nudge sent: online agents will check right away, the rest - next time they check in (up to 15 minutes)",
  "ключ Яндекс Карт не задан - задайте его в стенде: центр агентов → Карта → «Ключ Яндекс Карт…»": "Yandex Maps key is not set - set it in the stand: agent control center → Map → \"Yandex Maps key…\"",
  "Яндекс Карты не загрузились": "Yandex Maps failed to load",
  "%s: агентов %s, живых %s из %s": "%s: agents: %s, alive: %s of %s",
  "живых %s из %s": "alive: %s of %s",
  "нет данных по узлам": "no node data",
};
const tr = (text, ...args) => { let out = LANG === "en" && text in EN ? EN[text] : text; for (const a of args) out = out.replace("%s", () => String(a)); return out; };
if (LANG === "en") {
  document.documentElement.lang = "en";
  document.querySelectorAll("[data-tr]").forEach(el => { el.textContent = tr(el.textContent); });
  $("token").placeholder = tr($("token").placeholder);
}
let token = localStorage.getItem("vpncheck_token") || "";
let refreshTimer = null;
let map = null, ymapsReady = false, agents = [], regionsGeo = null, shapes = [], marks = [];
const api = async (path, opts = {}) => {
  const r = await fetch(path, { ...opts, headers: { "X-Admin-Token": token, "Content-Type": "application/json", ...(opts.headers || {}) } });
  if (r.status === 401) { const e = new Error("HTTP 401"); e.unauthorized = true; throw e; }
  if (!r.ok) throw new Error("HTTP " + r.status);
  return r.json();
};
const KINDS = { "crash": "падение", "check": "ошибка проверки", "install": "ошибка установки обновления", "locate": "геолокация",
  "ping": "пинг", "link-start": "канал: запуск", "link-command": "канал: команда", "link-foreground": "канал: работа в фоне",
  "cmd-result": "ответ на команду", "cmd-update": "команда обновиться", "core-start": "ядро не запустилось",
  "report": "отчёт не принят сервером", "telegram": "Telegram: не отправлено", "backup": "резервная копия", "tls": "TLS-порт",
  "link": "канал: связь", "update": "обновление", "push-token": "push-токен", "report-deferred": "отчёт отложен",
  "core-direct": "ядро не вышло в интернет", "core-exit": "ядро упало на узле" };
const DOUBTS = { "vpn": "включён VPN", "direct": "нет обычного интернета (белые списки?)",
  "core-direct": "ядро xray не вышло в интернет через эту сеть - узлы не проверены", "route": "выход совпал с Wi-Fi или маршрут разошёлся",
  "bind-ip": "маршрут под сомнением: ядро держалось сети только по адресу", "partial": "проверены не все узлы" };
const doubtText = (a) => (Array.isArray(a.doubts) ? a.doubts : []).filter(d => DOUBTS[d]).map(d => tr(DOUBTS[d])).join("; ");
const UNCHECKED = { "unsupported": "приложение не поддерживает настройки узла", "rejected": "агент отказался: частный адрес или небезопасные настройки",
  "core-direct": "ядро xray не вышло в интернет через эту сеть", "vpn": "на телефоне включён VPN" };
const uncheckedText = (code) => tr("не проверен: %s", tr(UNCHECKED[code] || (String(code || "").startsWith("core-exit") ? "ядро xray упало на этом узле" : UNCHECKED.rejected)));
const kindName = (k) => KINDS[k] ? tr(KINDS[k]) : String(k || "");
const joined = (...parts) => parts.map(p => String(p == null ? "" : p).trim()).filter(Boolean).join(" · ");
const untrusted = (a) => a.last_trusted === 0 || a.last_trusted === false || Boolean(a.last_partial);
const signOut = () => { localStorage.removeItem("vpncheck_token"); token = ""; $("app").style.display = "none"; $("login").style.display = "block"; $("status").textContent = tr("токен не принят"); };
let noticeTimer = null;
function notice(text, bad) {
  const n = $("notice"); n.textContent = text; n.className = "on" + (bad ? " bad" : "");
  clearTimeout(noticeTimer); noticeTimer = setTimeout(() => { n.className = ""; }, 15000);
}
function login() { token = $("token").value.trim(); localStorage.setItem("vpncheck_token", token); start(); }
async function start() {
  if (!token) return;
  try { await api("/health"); } catch (e) {}
  let state;
  try { state = await api("/v1/admin/state"); } catch (e) {
    if (e.unauthorized) return signOut();
    $("status").textContent = tr("сервер не ответил: ") + e.message; return;
  }
  $("login").style.display = "none"; $("app").style.display = "block";
  loadYandex(state.yandex_key || "");
  if (!state.yandex_key) showTab("agents");
  refresh(); if (!refreshTimer) refreshTimer = setInterval(refresh, 60000);
}
function showTab(name) {
  document.querySelectorAll("nav button").forEach(x => x.classList.toggle("on", x.dataset.s === name));
  document.querySelectorAll("section").forEach(s => s.classList.toggle("on", s.id === "s-" + name));
  if (name === "map" && map) map.container.fitToViewport();
}
document.querySelectorAll("nav button").forEach(d => d.onclick = () => showTab(d.dataset.s));
const ago = (ts) => { const d = Date.now() / 1000 - ts; return d < 90 ? tr("только что") : (d < 3600 ? Math.floor(d / 60) + tr(" мин") : d < 86400 ? Math.floor(d / 3600) + tr(" ч") : Math.floor(d / 86400) + tr(" дн")) + tr(" назад"); };
const cls = (a, t) => !t ? "dim" : a === t ? "ok" : a === 0 ? "bad" : "mid";
async function refresh() {
  try {
    const [ag, mx, er] = await Promise.all([api("/v1/admin/agents"), api("/v1/admin/matrix?hours=24"), api("/v1/admin/errors?limit=100")]);
    agents = ag.agents.map(a => ({ ...a, stale: (ag.server_time - a.last_seen) > 12 * 3600 }));
    const live = agents.filter(a => !a.stale);
    $("status").textContent = tr("за 12 ч отчитались: ") + live.length;
    $("chips").innerHTML = `<span class="chip g">${esc(tr("за 12 ч отчитались: "))}${live.length}</span><span class="chip b">${esc(tr("регионов: "))}${new Set(live.map(a => a.region || a.city).filter(Boolean)).size}</span><span class="chip">${esc(tr("всего: "))}${agents.length}</span>`;
    $("agents").innerHTML = agents.map(a => `<div class="agent"><div><div class="n">${esc(joined(a.city || a.region || "?", a.operator || a.network))}</div>
      <div class="m">${esc(joined(a.model, a.app_version, a.https ? "https" : "", ago(a.last_seen)))}</div>${doubtText(a) ? `<div class="m">⚠ ${esc(doubtText(a))}</div>` : ""}</div><div class="${a.stale || untrusted(a) ? "dim" : cls(a.alive, a.total)}"${untrusted(a) ? ` title="${esc(tr("последний отчёт ненадёжный (белые списки, VPN или неполный) - цифры из прошлого надёжного"))}"` : ""}>${a.total ? esc(a.alive + tr(" из ") + a.total) : esc(tr("нет данных по узлам"))}</div></div>`).join("") || "<div class='dim'>" + esc(tr("пока никого")) + "</div>";
    const fresh = Number.isInteger(mx.new_agents) && mx.new_agents > 0 ? mx.new_agents : 0;
    $("matrix").innerHTML = table(tr("Узел"), mx.columns, mx.matrix, mx.reasons || {}, fresh, NO_NODES, mx.unchecked || {});
    $("sitesm").innerHTML = table(tr("Сайт"), mx.columns, mx.sites || {}, {}, 0, NO_SITES);
    $("errors").innerHTML = er.errors.map(e => `<div class="err"><div class="t">${esc(joined(new Date(e.ts * 1000).toLocaleString(LANG), e.agent_id ? tr("агент") + " " + String(e.agent_id).slice(0, 8) : tr("сервер"), e.agent_id ? e.model : "", e.app_version, kindName(e.kind)))}</div><pre>${esc(String(e.text || "").slice(0, 600))}</pre></div>`).join("") || "<div class='dim'>" + esc(tr("ошибок нет")) + "</div>";
    drawMap();
  } catch (e) {
    if (e.unauthorized) return signOut();
    $("status").textContent = tr("сервер не ответил: ") + e.message;
  }
}
const DEAD = { "dns-sinkhole": "DNS сети подменил адрес", "dns-fail": "DNS сети не нашёл имя" };
const NO_NODES = "Пока нет данных. Новые агенты попадают в матрицу через сутки после подключения - так выдуманные агенты не исказят картину; их последние отчёты уже видны во вкладке «Агенты».";
const NO_SITES = "Пока нет данных - сайты задаются в стенде: Центр управления агентами → «Узлы и обновления»";
function table(first, columns, matrix, reasons = {}, fresh = 0, empty = NO_NODES, unchecked = {}) {
  const cols = Object.keys(columns);
  const rows = Object.keys(matrix).sort();
  if (!rows.length) return "<div class='dim'>" + esc(tr(empty)) +
    (fresh ? "<br><br>" + esc(tr("Новых агентов: %s - появятся здесь в течение суток после подключения", fresh)) : "") + "</div>";
  let dns = false;
  const body = rows.map(r => `<tr><td>${esc(r.replace(/^https?:\/\//, ""))}</td>${cols.map(c => { const v = matrix[r][c]; const skip = (unchecked[r] || {})[c]; if (!v) return skip ? `<td class="dim" title="${esc(uncheckedText(skip))}">?</td>` : "<td class='dim'>-</td>"; const k = v[0] === v[1] ? "ok" : v[0] === 0 ? "bad" : "mid"; const why = DEAD[(reasons[r] || {})[c]]; if (why) dns = true; return `<td class="${k}"${why ? ` title="${esc(tr(why))}"` : ""}>${esc(v[0])} / ${esc(v[1])}${why ? " <small>DNS</small>" : ""}</td>`; }).join("")}</tr>`).join("");
  return `<table><tr><th>${esc(first)}</th>${cols.map(c => `<th>${esc(c)}</th>`).join("")}</tr>` + body + "</table>" +
    (dns ? "<div class='dim legend'>" + esc(tr("DNS - DNS сети подменил адрес или не нашёл имя")) + "</div>" : "");
}
async function command(button, question, path, done) {
  if (!confirm(tr(question))) return;
  button.disabled = true;
  try { await api(path, { method: "POST", body: "{}" }); notice(tr(done)); }
  catch (e) { if (e.unauthorized) return signOut(); notice(tr("сервер не ответил: ") + e.message, true); }
  finally { button.disabled = false; }
}
const updateNow = () => command($("updateBtn"), "Разослать всем агентам команду обновить приложение?", "/v1/admin/update_now",
  "агенты заберут обновление в течение 15 минут");
const runNow = () => command($("runBtn"), "Попросить всех агентов проверить узлы сейчас?", "/v1/admin/run_now",
  "толчок отправлен: онлайн-агенты проверят сразу, остальные - при следующем выходе на связь (до 15 минут)");

function loadYandex(key) {
  if (!key) { $("map").innerHTML = "<div class='dim' style='padding:20px'>" + esc(tr("ключ Яндекс Карт не задан - задайте его в стенде: центр агентов → Карта → «Ключ Яндекс Карт…»")) + "</div>"; return; }
  const s = document.createElement("script");
  s.src = `https://api-maps.yandex.ru/2.1/?apikey=${encodeURIComponent(key)}&lang=${LANG === "en" ? "en_US" : "ru_RU"}&coordorder=longlat&csp=true`;
  s.onload = () => ymaps.ready(() => { map = new ymaps.Map("map", { center: [60, 58], zoom: 3, controls: ["zoomControl", "typeSelector"] }, { suppressMapOpenBlock: true }); ymapsReady = true; drawMap(); });
  s.onerror = () => { $("map").innerHTML = "<div class='dim' style='padding:20px'>" + esc(tr("Яндекс Карты не загрузились")) + "</div>"; };
  document.head.appendChild(s);
  fetch("/static/ru_regions.geojson").then(r => r.json()).then(g => { regionsGeo = g; drawMap(); }).catch(() => {});
}
const color = (a) => a.stale ? "#5b6772" : !a.total ? "#93c5fd" : a.alive === a.total ? "#22c55e" : a.alive === 0 ? "#ef4444" : "#f59e0b";
function inRing(p, ring) { let ins = false; for (let i = 0, j = ring.length - 1; i < ring.length; j = i++) { const xi = ring[i][0], yi = ring[i][1], xj = ring[j][0], yj = ring[j][1]; if (((yi > p[1]) !== (yj > p[1])) && (p[0] < (xj - xi) * (p[1] - yi) / (yj - yi) + xi)) ins = !ins; } return ins; }
function inF(p, f) { const g = f.geometry, polys = g.type === "Polygon" ? [g.coordinates] : g.coordinates; return polys.some(poly => inRing(p, poly[0]) && !poly.slice(1).some(h => inRing(p, h))); }
function drawMap() {
  if (!ymapsReady) return;
  marks.forEach(m => map.geoObjects.remove(m)); shapes.forEach(s => map.geoObjects.remove(s)); marks = []; shapes = [];
  if (regionsGeo) {
    const stats = new Map();
    for (const a of agents) { if (a.lat == null || a.stale) continue; const f = regionsGeo.features.find(f => inF([a.lon, a.lat], f)); if (!f) continue;
      const s = stats.get(f) || { n: 0, alive: 0, total: 0 }; s.n++; s.alive += a.alive || 0; s.total += a.total || 0; stats.set(f, s); }
    for (const f of regionsGeo.features) { const s = stats.get(f); if (!s) continue; const r = s.total ? s.alive / s.total : -1; const fill = r < 0 ? "#93c5fd" : r >= 0.8 ? "#22c55e" : r === 0 ? "#ef4444" : "#f59e0b";
      const polys = f.geometry.type === "Polygon" ? [f.geometry.coordinates] : f.geometry.coordinates;
      for (const poly of polys) { const sh = new ymaps.Polygon(poly, { hintContent: esc(tr("%s: агентов %s, живых %s из %s", LANG === "en" ? (f.properties.name || f.properties.name_ru) : f.properties.name_ru, s.n, s.alive, s.total)) }, { fillColor: fill, fillOpacity: 0.3, strokeColor: fill, strokeWidth: 1.5 }); map.geoObjects.add(sh); shapes.push(sh); } }
  }
  for (const a of agents) { if (a.lat == null) continue; const pm = new ymaps.Placemark([a.lon, a.lat], { hintContent: `${esc(a.city)} · ${esc(a.operator)}<br>${esc(tr("живых %s из %s", a.alive, a.total))}` }, { preset: "islands#circleDotIcon", iconColor: color(a) }); map.geoObjects.add(pm); marks.push(pm); }
}
$("loginBtn").addEventListener("click", login);
$("token").addEventListener("keydown", (e) => { if (e.key === "Enter") login(); });
$("runBtn").addEventListener("click", runNow);
$("updateBtn").addEventListener("click", updateNow);
if (token) start(); else $("status").textContent = tr("нужен токен");
