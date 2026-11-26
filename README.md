# ContainerGuard

Docker runtime security and container forensics: detect (Falco), prevent (Trivy, CIS benchmark),
preserve (automated hashed evidence bundles with chain of custody), present (Jinja2 report, Flask dashboard).

**Lab use only.** Passwords such as `labpass123` are deliberately weak, to give the scanners something to find.

## Contents
| Path | What |
|---|---|
| `docker-compose.yml`, `app/`, `worker/` | Hardened target workload |
| `falco/` | 6 custom rules and Falco config |
| `scripts/` | Trivy gate, evidence collector, Falco watcher, report generator |
| `dashboard/` | Flask API and GUI |
| `config/` | Docker daemon and auditd settings |
| `docs/` | CIS benchmark logs (score 4 to 51) |
| `sample-evidence/` | One evidence bundle, its hash, its report and the chain-of-custody CSV |

## Requirements
Kali or Ubuntu VM, Docker, docker-compose, Falco (modern eBPF), Trivy, jq, Python 3 with Flask and Jinja2.
Falco needs a real Linux kernel, so it will not work on Docker Desktop.

## Quick start
    docker-compose up -d --build
    cp falco/falco_rules.local.yaml /etc/falco/ && systemctl restart falco-modern-bpf
    ./scripts/trivy_gate.sh after
    ./scripts/falco_watcher.sh &

## Results
CIS score 4 to 51. Trivy web/worker HIGH 51 to 5. Six custom Falco rules, each proven by a live attack.

## Limitations
The docker.sock attack is simulated. Rule 5 was tested with the worker briefly attached to the edge network.
The Trivy gate accepts one documented unfixed CVE through `.trivyignore`.
