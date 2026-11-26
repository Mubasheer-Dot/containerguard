#!/usr/bin/env bash
# usage: collect_evidence.sh <container-name> "<triggering rule>"
C="$1"; RULE="${2:-manual}"
TS=$(date -u +%Y%m%dT%H%M%SZ)
BASE=/root/containerguard/evidence
DIR="$BASE/incident-$TS-$C"
mkdir -p "$DIR"

CID=$(docker inspect --format '{{.Id}}' "$C" 2>/dev/null) || { echo "no such container: $C"; exit 1; }
PID=$(docker inspect --format '{{.State.Pid}}' "$C")
IMGID=$(docker inspect --format '{{.Image}}' "$C")

{
  echo "collected_utc=$(date -u +%FT%TZ)"
  echo "collector=$(whoami)@$(hostname)"
  echo "trigger_rule=$RULE"
  echo "container_name=$C"
  echo "container_id=$CID"
  echo "image=$(docker inspect --format '{{.Config.Image}}' "$C")"
  echo "image_id=$IMGID"
  echo "image_repo_digests=$(docker image inspect --format '{{json .RepoDigests}}' "$IMGID")"
} > "$DIR/00-summary.txt"

docker inspect "$C"                                  > "$DIR/01-inspect.json"
docker top "$C" -eo pid,ppid,user,etime,args         > "$DIR/02-processes.txt" 2>&1
docker logs --timestamps --tail 500 "$C"             > "$DIR/03-container-logs.txt" 2>&1
docker diff "$C"                                     > "$DIR/04-fs-diff.txt" 2>&1
docker exec "$C" ls -laR /tmp > "$DIR/04b-tmpfs.txt" 2>&1
docker exec "$C" ls -laR /tmp > "$DIR/04b-tmpfs.txt" 2>&1
nsenter -t "$PID" -n ss -tunap                       > "$DIR/05-network.txt" 2>&1
jq -c --arg id "${CID:0:12}" 'select(.output_fields["container.id"]==$id)' \
   /var/log/falco/events.json | tail -50             > "$DIR/06-falco-alerts.json"

( cd "$DIR" && sha256sum * > SHA256SUMS )
tar -czf "$DIR.tar.gz" -C "$BASE" "$(basename "$DIR")"
BUNDLE_SHA=$(sha256sum "$DIR.tar.gz" | tee "$DIR.tar.gz.sha256" | cut -d' ' -f1)

[ -f "$BASE/chain-of-custody.csv" ] || echo "utc,incident,container,trigger_rule,bundle_sha256,collector" > "$BASE/chain-of-custody.csv"
echo "$(date -u +%FT%TZ),$(basename "$DIR"),$C,$RULE,$BUNDLE_SHA,$(whoami)@$(hostname)" >> "$BASE/chain-of-custody.csv"
echo "EVIDENCE: $DIR.tar.gz  sha256=$BUNDLE_SHA"
