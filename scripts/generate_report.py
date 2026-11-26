#!/usr/bin/env python3
"""usage: generate_report.py [incident-dir-name]   (default: newest incident)"""
import sys, json, re, hashlib
from pathlib import Path
from datetime import datetime, timezone
from jinja2 import Template

EV = Path("/root/containerguard/evidence")
OUT = Path("/root/containerguard/reports")
OUT.mkdir(exist_ok=True)

RESPONSE = {
 "CG Interactive Shell in Production Container": ["Identify who ran docker exec and why", "Review shell history and processes", "Restrict docker exec to admins"],
 "CG Sensitive File Read": ["Treat credentials in this container as exposed and rotate them", "Review what else the process read", "Rebuild the container from a clean image"],
 "CG Docker Socket Access": ["Remove any docker.sock mounts", "Assume host escape is possible and inspect the host", "Review container runtime config"],
 "CG Privilege Escalation Syscall": ["Confirm cap_drop ALL and no-new-privileges are active", "Check for exploit attempts in the logs", "Isolate the container"],
 "CG Unexpected Outbound Connection From Worker": ["Block egress at the network level", "Inspect the destination IP", "Check the worker code and dependencies for tampering"],
 "CG Privileged Container Created": ["Find and stop the privileged container", "Identify the user and session that created it", "Audit the host for changes"],
}

def read(p):
    try: return p.read_text(errors="replace")
    except FileNotFoundError: return ""

dirs = [p for p in EV.glob("incident-*") if p.is_dir()]
if not dirs: sys.exit("no incident directories found")
name = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else max(dirs, key=lambda p: p.stat().st_mtime).name
d = EV / name

summary = dict(l.split("=", 1) for l in read(d/"00-summary.txt").splitlines() if "=" in l)

alerts = []
for l in read(d/"06-falco-alerts.json").splitlines():
    try: alerts.append(json.loads(l))
    except json.JSONDecodeError: pass
alerts.sort(key=lambda a: a["time"])

hashes = []
for line in read(d/"SHA256SUMS").splitlines():
    if not line.strip(): continue
    h, f = line.split(None, 1); f = f.strip().lstrip("*")
    p = d / f
    actual = hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else "MISSING"
    hashes.append(dict(file=f, sha=h, ok=(actual == h)))

tar = EV / f"{name}.tar.gz"
bundle_sha = hashlib.sha256(tar.read_bytes()).hexdigest() if tar.exists() else "MISSING"

ioc = {"Commands": set(), "Files": set(), "Users": set(), "Established connections": set()}
tags = set()
for a in alerts:
    f = a.get("output_fields", {})
    if f.get("proc.cmdline"): ioc["Commands"].add(f["proc.cmdline"])
    if f.get("fd.name"): ioc["Files"].add(f["fd.name"])
    if f.get("user.name"): ioc["Users"].add(f["user.name"])
    tags.update(t for t in a.get("tags", []) if re.fullmatch(r"T\d+", t))
net = read(d/"05-network.txt")
for l in net.splitlines():
    if l.startswith("tcp") and "ESTAB" in l: ioc["Established connections"].add(" ".join(l.split()[3:5]))

rules = sorted({a["rule"] for a in alerts if a["rule"].startswith("CG ")} | ({summary.get("trigger_rule")} & set(RESPONSE)))
steps = []
for r in rules:
    steps += [s for s in RESPONSE.get(r, []) if s not in steps]
steps = steps or ["Review the evidence manually"]

HTML = """<!doctype html><html><head><meta charset="utf-8"><title>Incident {{ name }}</title>
<style>body{font:15px/1.5 system-ui,sans-serif;max-width:960px;margin:2em auto;padding:0 1em;color:#222}
table{border-collapse:collapse;width:100%;margin:.5em 0}td,th{border:1px solid #ccc;padding:4px 8px;text-align:left;font-size:13px;vertical-align:top}
th{background:#eee}code,pre{font-size:12px;background:#f5f5f5;padding:2px 4px;word-break:break-all}pre{padding:8px;overflow:auto;white-space:pre-wrap}
.ok{color:#087f23;font-weight:600}.bad{color:#c62828;font-weight:600}h2{border-bottom:2px solid #333;margin-top:1.6em}</style></head><body>
<h1>Forensic Incident Report</h1><p><b>{{ name }}</b> &middot; generated {{ now }}</p>
<h2>1. Summary</h2><table>
{% for k in ['container_name','container_id','image','image_id','trigger_rule','collected_utc','collector'] %}<tr><th>{{ k }}</th><td>{{ s.get(k,'') }}</td></tr>{% endfor %}
<tr><th>image_repo_digests</th><td>{{ s.get('image_repo_digests','') }} (empty means a local build, so image_id is the identifier)</td></tr>
<tr><th>alerts in bundle</th><td>{{ alerts|length }}</td></tr>
<tr><th>MITRE techniques</th><td>{{ tags|sort|join(', ') or 'n/a' }}</td></tr></table>
<h2>2. Timeline (UTC)</h2><table><tr><th>Time</th><th>Rule</th><th>Priority</th><th>Detail</th></tr>
{% for a in alerts %}<tr><td>{{ a.time }}</td><td>{{ a.rule }}</td><td>{{ a.priority }}</td><td><code>{{ a.output[:240] }}</code></td></tr>
{% else %}<tr><td colspan="4">No alerts captured</td></tr>{% endfor %}</table>
<h2>3. Artifacts and hashes</h2><table><tr><th>File</th><th>SHA-256</th><th>Verified</th></tr>
{% for h in hashes %}<tr><td>{{ h.file }}</td><td><code>{{ h.sha }}</code></td><td class="{{ 'ok' if h.ok else 'bad' }}">{{ 'OK' if h.ok else 'MISMATCH' }}</td></tr>{% endfor %}</table>
<p>Bundle: <code>{{ name }}.tar.gz</code><br>SHA-256: <code>{{ bundle_sha }}</code></p>
<h2>4. Indicators</h2>{% for k,v in ioc.items() %}<h3>{{ k }}</h3>{% if v %}<ul>{% for i in v|sort %}<li><code>{{ i }}</code></li>{% endfor %}</ul>{% else %}<p>None</p>{% endif %}{% endfor %}
<h2>5. Process list at collection</h2><pre>{{ procs }}</pre>
<h2>6. Network state at collection</h2><pre>{{ net }}</pre>
<h2>7. Filesystem changes</h2><pre>{{ fsdiff or '(none: root filesystem is read-only)' }}</pre><pre>{{ tmpfs }}</pre>
<h2>8. Recommended response</h2><ol>{% for s in steps %}<li>{{ s }}</li>{% endfor %}</ol>
<h2>9. Chain of custody</h2><table><tr><th>UTC</th><th>Incident</th><th>Container</th><th>Trigger</th><th>Bundle SHA-256</th><th>Collector</th></tr>
{% for r in coc %}<tr>{% for c in r %}<td>{{ c }}</td>{% endfor %}</tr>{% endfor %}</table></body></html>"""

coc = [l.split(",") for l in read(EV/"chain-of-custody.csv").splitlines()[1:] if name in l]
html = Template(HTML, autoescape=True).render(
    name=name, now=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), s=summary, alerts=alerts,
    tags=tags, hashes=hashes, bundle_sha=bundle_sha, ioc=ioc, procs=read(d/"02-processes.txt"), net=net,
    fsdiff=read(d/"04-fs-diff.txt").strip(), tmpfs=read(d/"04b-tmpfs.txt"), steps=steps, coc=coc)
out = OUT / f"report-{name}.html"
out.write_text(html)
print("REPORT:", out, "sha256=", hashlib.sha256(out.read_bytes()).hexdigest())
