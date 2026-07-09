"""Live web dashboard (Flask) — real-time view of traffic and threats."""
import os

from flask import Flask, jsonify

HERE = os.path.dirname(os.path.abspath(__file__))


def create_app(engine):
    app = Flask(__name__)

    @app.route("/")
    def index():
        return PAGE

    @app.route("/api/state")
    def state():
        return jsonify(engine.snapshot())

    return app


PAGE = """<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Pi-Wall — AI Firewall</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:ui-monospace,Menlo,Consolas,monospace;background:#0b1020;color:#d6e2ff}
header{background:#111a33;padding:12px 20px;display:flex;justify-content:space-between;
 align-items:center;border-bottom:1px solid #24314f}
header h1{font-size:18px;color:#5eead4}header .mode{font-size:12px;color:#fca5a5}
.wrap{max-width:1200px;margin:0 auto;padding:16px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-bottom:16px}
.tile{background:#111a33;border:1px solid #24314f;border-radius:8px;padding:12px;text-align:center}
.tile b{display:block;font-size:22px;color:#7dd3fc}.tile span{font-size:11px;color:#8aa0c6;text-transform:uppercase}
.grid{display:grid;grid-template-columns:1.3fr 1fr;gap:16px}
@media(max-width:820px){.grid{grid-template-columns:1fr}}
.card{background:#111a33;border:1px solid #24314f;border-radius:8px;padding:12px;margin-bottom:16px}
.card h2{font-size:13px;color:#94a3b8;margin-bottom:8px;text-transform:uppercase;letter-spacing:.05em}
table{width:100%;border-collapse:collapse;font-size:12px}
td,th{padding:4px 6px;text-align:left;border-bottom:1px solid #1c2942;white-space:nowrap}
.allow{color:#4ade80}.deny{color:#f87171}
.sev-critical{color:#f87171;font-weight:700}.sev-high{color:#fb923c}.sev-medium{color:#fbbf24}.sev-low{color:#a3a3a3}
.threat{border-left:3px solid #fb923c;padding:8px 10px;margin-bottom:8px;background:#0f1730;border-radius:4px}
.threat .k{font-weight:700}.threat .advice{color:#5eead4;font-size:12px;margin-top:4px}
.threat .badge{background:#7f1d1d;color:#fecaca;font-size:10px;padding:1px 6px;border-radius:8px;margin-left:6px}
.talker{display:flex;justify-content:space-between;padding:3px 0;font-size:12px;border-bottom:1px solid #1c2942}
.pill{font-size:10px;padding:1px 6px;border-radius:8px;background:#1e293b;color:#94a3b8}
</style></head><body>
<header><h1>🛡️ Pi-Wall — AI Firewall</h1>
 <span class="mode">mode: <b id="mode">…</b> · uptime <span id="uptime">0</span>s
 · AI model <span id="trained" class="pill">learning</span></span></header>
<div class="wrap">
 <div class="tiles">
  <div class="tile"><b id="packets">0</b><span>packets</span></div>
  <div class="tile"><b id="allowed">0</b><span>allowed</span></div>
  <div class="tile"><b id="denied">0</b><span>denied</span></div>
  <div class="tile"><b id="flows">0</b><span>active flows</span></div>
  <div class="tile"><b id="nthreats">0</b><span>threats</span></div>
  <div class="tile"><b id="nblocked">0</b><span>blocked IPs</span></div>
 </div>
 <div class="grid">
  <div>
   <div class="card"><h2>Live traffic</h2>
    <table id="traffic"><thead><tr><th>src</th><th>→ dst</th><th>proto</th>
     <th>:port</th><th>len</th><th>verdict</th></tr></thead><tbody></tbody></table></div>
  </div>
  <div>
   <div class="card"><h2>🚨 AI threat feed</h2><div id="threats"></div></div>
   <div class="card"><h2>Blocked sources</h2><div id="blocked"></div></div>
   <div class="card"><h2>Top talkers</h2><div id="talkers"></div></div>
  </div>
 </div>
</div>
<script>
const $=id=>document.getElementById(id);
const esc=s=>{const d=document.createElement('div');d.textContent=(s??'');return d.innerHTML;};
async function tick(){
  let s; try{ s=await (await fetch('/api/state')).json(); }catch(e){ return; }
  $('mode').textContent=s.mode; $('uptime').textContent=s.uptime;
  $('trained').textContent=s.anomaly_trained?'trained':'learning';
  $('trained').style.color=s.anomaly_trained?'#4ade80':'#fbbf24';
  $('packets').textContent=s.packets; $('allowed').textContent=s.allowed;
  $('denied').textContent=s.denied; $('flows').textContent=s.active_flows;
  $('nthreats').textContent=s.threats.length; $('nblocked').textContent=s.blocked.length;
  $('traffic').querySelector('tbody').innerHTML=s.recent.map(r=>`<tr>
    <td>${esc(r.src)}</td><td>${esc(r.dst)}</td><td>${esc(r.proto)}</td>
    <td>:${r.dport}</td><td>${r.length}</td>
    <td class="${r.action==='allow'?'allow':'deny'}">${r.action}</td></tr>`).join('');
  $('threats').innerHTML=s.threats.map(t=>`<div class="threat">
    <span class="k sev-${t.severity}">${esc(t.kind)}</span> from ${esc(t.src)}
    ${t.blocked?'<span class="badge">BLOCKED</span>':''}
    <div>${esc(t.detail)}</div>
    ${t.advice?`<div class="advice">🤖 ${esc(t.advice.summary)} ${esc(t.advice.action||'')}
      <span class="pill">${t.advice.source}</span></div>`:''}
   </div>`).join('')||'<div class="pill">no threats yet</div>';
  $('blocked').innerHTML=s.blocked.map(b=>`<div class="talker">
    <span class="deny">${esc(b.ip)}</span><span class="pill">${esc(b.reason)}</span></div>`).join('')
    ||'<div class="pill">none</div>';
  $('talkers').innerHTML=s.top_talkers.map(t=>`<div class="talker">
    <span>${esc(t.src)}</span><span>${(t.bytes/1024).toFixed(1)} KB</span></div>`).join('');
}
tick(); setInterval(tick,1000);
</script></body></html>"""
