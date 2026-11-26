import json, re, os, collections
from pathlib import Path
from flask import Flask, jsonify, Response

B = Path("/root/containerguard")
SINCE = os.environ.get("SINCE", "")          # e.g. 2026-11-15T20:00:00
app = Flask(__name__)

def falco():
    counts, recent = collections.Counter(), []
    try:
        for l in open("/var/log/falco/events.json"):
            try: a = json.loads(l)
            except ValueError: continue
            if a["rule"].startswith("CG ") and a["time"] >= SINCE:
                counts[a["rule"]] += 1
                recent.append({"time": a["time"], "rule": a["rule"], "priority": a["priority"],
                               "container": a["output_fields"].get("container.name", "")})
    except FileNotFoundError:
        pass
    return dict(counts), recent[-15:][::-1]

def sev(name):
    try: j = json.load(open(B / "trivy" / name))
    except Exception: return None
    c = h = s = 0
    for r in j.get("Results") or []:
        for v in r.get("Vulnerabilities") or []:
            c += v["Severity"] == "CRITICAL"; h += v["Severity"] == "HIGH"
        s += len(r.get("Secrets") or [])
    return {"critical": c, "high": h, "secrets": s}

def score(name):
    try: m = re.findall(r"Score: (-?\d+)", (B / "reports" / name).read_text())
    except Exception: return None
    return int(m[-1]) if m else None

@app.route("/api/data")
def data():
    counts, recent = falco()
    pairs = [("web", "baseline-containerguard-web_latest.json", "after-high-containerguard-web_latest.json"),
             ("worker", "baseline-containerguard-worker_latest.json", "after-high-containerguard-worker_latest.json"),
             ("postgres (13 to 17-alpine)", "baseline-postgres_13.json", "baseline-postgres_17-alpine.json")]
    return jsonify(counts=counts, recent=recent,
                   trivy=[{"image": n, "before": sev(b), "after": sev(a)} for n, b, a in pairs],
                   cis={"before": score("bench-before.log"), "after": score("bench-after2-filtered.log")})

PAGE = """<!doctype html><meta charset=utf-8><title>ContainerGuard</title>
<style>body{font:14px system-ui;max-width:1000px;margin:1.5em auto;padding:0 1em;background:#111;color:#eee}
h1{margin-bottom:0}h2{border-bottom:1px solid #444;padding-bottom:4px;margin-top:1.4em}
table{border-collapse:collapse;width:100%}td,th{border:1px solid #444;padding:4px 8px;text-align:left}th{background:#222}
.bar{background:#2e7d32;height:16px;color:#fff;font-size:11px;padding-left:4px;white-space:nowrap}
.CRITICAL{color:#ff5252}.Warning{color:#ffb300}.Error{color:#ff5252}</style>
<h1>ContainerGuard</h1><small id=ts></small>
<h2>CIS Docker Benchmark score</h2><div id=cis></div>
<h2>Falco custom-rule alerts</h2><div id=counts></div>
<h2>Latest alerts</h2><table id=recent></table>
<h2>Trivy: HIGH / CRITICAL / secrets, before and after</h2><table id=trivy></table>
<script>
const fmt = s => s ? s.high + ' / ' + s.critical + ' / ' + s.secrets : 'n/a';
async function load(){
  const d = await (await fetch('/api/data')).json();
  document.getElementById('ts').textContent = 'updated ' + new Date().toLocaleTimeString();
  const bar = (label, v) => '<div style="margin:4px 0">' + label + '<div class=bar style="width:' + Math.max(v,1)*5 + 'px">' + v + '</div></div>';
  document.getElementById('cis').innerHTML = bar('Before', d.cis.before ?? 0) + bar('After', d.cis.after ?? 0);
  document.getElementById('counts').innerHTML = Object.keys(d.counts).length
    ? Object.entries(d.counts).map(([k,v]) => bar(k, v)).join('') : 'No alerts since filter';
  document.getElementById('recent').innerHTML = '<tr><th>Time</th><th>Rule</th><th>Priority</th><th>Container</th></tr>' +
    d.recent.map(a => '<tr><td>' + a.time + '</td><td>' + a.rule + '</td><td class=' + a.priority + '>' + a.priority + '</td><td>' + a.container + '</td></tr>').join('');
  document.getElementById('trivy').innerHTML = '<tr><th>Image</th><th>Before</th><th>After</th></tr>' +
    d.trivy.map(t => '<tr><td>' + t.image + '</td><td>' + fmt(t.before) + '</td><td>' + fmt(t.after) + '</td></tr>').join('');
}
load(); setInterval(load, 5000);
</script>"""

@app.route("/")
def index():
    return Response(PAGE, mimetype="text/html")

app.run(host="127.0.0.1", port=5001)
