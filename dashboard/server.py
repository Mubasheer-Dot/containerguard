import csv, hashlib, hmac, json, re, subprocess, collections
from pathlib import Path
from flask import Flask, jsonify, request, send_file, abort

B = Path("/root/containerguard")
EV = B / "evidence"
TOKEN = (B / "dashboard" / ".token").read_text().strip()
ALLOWED = {"cg-web", "cg-db", "cg-worker"}      # containers the API may collect from
ID_RE = re.compile(r"^incident-\d{8}T\d{6}Z-[a-z0-9_.-]+$")
app = Flask(__name__)

@app.before_request
def auth():
    if request.path.startswith("/api/"):
        t = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        if not hmac.compare_digest(t.encode(), TOKEN.encode()):
            return jsonify(error="unauthorized"), 401

def read_alerts():
    try:
        with open("/var/log/falco/events.json") as f:
            for l in f:
                try: yield json.loads(l)
                except ValueError: pass
    except FileNotFoundError:
        return

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def coc():
    p = EV / "chain-of-custody.csv"
    if not p.exists(): return []
    with open(p, newline="") as f: return list(csv.DictReader(f))

def check_id(iid):
    if not ID_RE.match(iid) or not (EV / iid).is_dir(): abort(404)

@app.route("/api/alerts")
def alerts():
    rule = request.args.get("rule", ""); cont = request.args.get("container", "")
    since = request.args.get("since", ""); everything = request.args.get("all") == "1"
    limit = min(request.args.get("limit", 100, type=int), 500)
    out, counts = [], collections.Counter()
    for a in read_alerts():
        r = a.get("rule", ""); f = a.get("output_fields", {})
        if not everything and not r.startswith("CG "): continue
        if rule and r != rule: continue
        if cont and f.get("container.name") != cont: continue
        if a.get("time", "") < since: continue
        counts[r] += 1
        out.append({"time": a["time"], "rule": r, "priority": a.get("priority"),
                    "container": f.get("container.name", ""), "output": a.get("output", "")[:300]})
    return jsonify(counts=dict(counts), alerts=out[-limit:][::-1])

@app.route("/api/incidents")
def incidents():
    return jsonify(coc())

@app.route("/api/incidents/<iid>")
def incident(iid):
    check_id(iid); d = EV / iid
    summary = dict(l.split("=", 1) for l in (d / "00-summary.txt").read_text().splitlines() if "=" in l)
    return jsonify(summary=summary, files=sorted(p.name for p in d.iterdir()))

@app.route("/api/incidents/<iid>/verify")
def verify(iid):
    check_id(iid); d = EV / iid; rows = []
    for line in (d / "SHA256SUMS").read_text().splitlines():
        if not line.strip(): continue
        h, name = line.split(None, 1)
        fp = d / Path(name.strip().lstrip("*")).name
        actual = sha(fp) if fp.is_file() else "MISSING"
        rows.append({"file": fp.name, "expected": h, "actual": actual, "ok": actual == h})
    tar = EV / f"{iid}.tar.gz"
    rec = next((r["bundle_sha256"] for r in coc() if r["incident"] == iid), None)
    actual = sha(tar) if tar.is_file() else "MISSING"
    bundle = {"recorded": rec, "actual": actual, "ok": rec is not None and rec == actual}
    return jsonify(files=rows, bundle=bundle, all_ok=bundle["ok"] and all(r["ok"] for r in rows))

@app.route("/api/incidents/<iid>/report")
def report(iid):
    check_id(iid)
    subprocess.run(["python3", str(B / "scripts/generate_report.py"), iid],
                   capture_output=True, timeout=60)
    p = B / "reports" / f"report-{iid}.html"
    if not p.is_file(): abort(500)
    return send_file(p, mimetype="text/html")

@app.route("/api/collect/<container>", methods=["POST"])
def collect(container):
    if container not in ALLOWED:
        return jsonify(error="container not allowed"), 400
    r = subprocess.run([str(B / "scripts/collect_evidence.sh"), container, "api request"],
                       capture_output=True, text=True, timeout=120)
    return jsonify(ok=r.returncode == 0, output=(r.stdout + r.stderr).strip()[-500:])

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

@app.route("/api/scans")
def scans():
    pairs = [("web", "baseline-containerguard-web_latest.json", "after-high-containerguard-web_latest.json"),
             ("worker", "baseline-containerguard-worker_latest.json", "after-high-containerguard-worker_latest.json"),
             ("postgres (13 to 17-alpine)", "baseline-postgres_13.json", "baseline-postgres_17-alpine.json")]
    return jsonify(trivy=[{"image": n, "before": sev(b), "after": sev(a)} for n, b, a in pairs],
                   cis={"before": score("bench-before.log"), "after": score("bench-final.log")})

@app.route("/")
def index():
    return send_file(B / "dashboard" / "index.html")

app.run(host="127.0.0.1", port=5001)
