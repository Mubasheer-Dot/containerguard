#!/usr/bin/env bash
# On a CG rule alert in a container, collect evidence (60s cooldown per container)
declare -A LAST
tail -n0 -F /var/log/falco/events.json | while read -r line; do
  rule=$(jq -r '.rule // empty' <<<"$line" 2>/dev/null)
  case "$rule" in "CG "*) ;; *) continue ;; esac
  cname=$(jq -r '.output_fields["container.name"] // empty' <<<"$line")
  if [ -z "$cname" ] || [ "$cname" = "host" ]; then continue; fi
  now=$(date +%s)
  if [ $(( now - ${LAST[$cname]:-0} )) -lt 60 ]; then continue; fi
  LAST[$cname]=$now
  /root/containerguard/scripts/collect_evidence.sh "$cname" "$rule" &
done
