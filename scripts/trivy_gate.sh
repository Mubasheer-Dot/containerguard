#!/usr/bin/env bash
# ContainerGuard go/no-go gate: fails on any CRITICAL finding
OUT=${1:-after}
mkdir -p ~/containerguard/trivy
FAIL=0
for img in $(docker ps --format '{{.Image}}' | sort -u | grep -v kali); do
  name=$(echo "$img" | tr ':/' '__')
  trivy image -q --scanners vuln,secret --severity CRITICAL --ignore-unfixed --ignorefile ~/containerguard/.trivyignore \
    --format json --output ~/containerguard/trivy/$OUT-$name.json "$img"
  n=$(jq '[.Results[]? | ((.Vulnerabilities // []) + (.Secrets // []))[]] | length' ~/containerguard/trivy/$OUT-$name.json)
  if [ "$n" -gt 0 ]; then
    echo "NO-GO  $img  ($n CRITICAL findings)"; FAIL=1
  else
    echo "GO     $img"
  fi
done
[ $FAIL -eq 0 ] && echo "RESULT: GO" || echo "RESULT: NO-GO (build failed)"
exit $FAIL
