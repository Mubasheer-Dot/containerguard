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

| Area | Before | After |
|---|---|---|
| CIS Docker Benchmark score (106 checks) | 4 | 51 |
| Trivy web image (HIGH) | 51 | 5 |
| Trivy worker image (HIGH) | 51 | 5 |
| Trivy database (CRITICAL) | 19 (`postgres:13`) | 0 in the final snapshot (`postgres:17-alpine`), with one documented exception |
| Trivy go/no-go gate | NO-GO (exit code 1) | GO (exit code 0) |
| Custom Falco rules proven by a live attack | 0 | 6 of 6 |
| Evidence bundles verified by SHA-256 | 0 | 3 (1 manual, 2 created by the watcher) |

### The six custom Falco rules

| # | Rule | Attack used |
|---|---|---|
| 1 | Interactive shell in a production container | `docker exec -it cg-web sh` |
| 2 | Sensitive file read | `cat /etc/shadow` in a container |
| 3 | Docker socket access | `touch` and `cat` of `/var/run/docker.sock` |
| 4 | Privilege escalation syscall | `mount` and `unshare` in a container |
| 5 | Unexpected outbound connection from the worker | Worker connecting to `8.8.8.8:53` |
| 6 | Privileged container created | `docker run --privileged` |

### Tuning rounds

1. Rule 5 fired on Docker's DNS lookups (`127.0.0.11`), so loopback and the lab subnet were excluded.
2. Falco's default `rule_matching: first` hid rules 1 and 2, so it was set to `all`.
3. Rule 5 broke when the network subnet changed, so all private ranges are now excluded.
4. Rule 4 fired on `runc` container startup, so `runc*` processes are excluded.

## Limitations
The docker.sock attack is simulated. Rule 5 was tested with the worker briefly attached to the edge network.
The Trivy gate accepts one documented unfixed CVE through `.trivyignore`.
