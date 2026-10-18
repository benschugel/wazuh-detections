#!/usr/bin/env bash
# Deploy this repository's decoders and rules into a running Wazuh manager
# container, the way tests/harness.sh loads them into the test manager.
#
#   ./deploy.sh [--dry-run] [container]
#
# container defaults to $WAZUH_MANAGER, then single-node-wazuh.manager-1.
#
# Steps: back up the container's etc/rules and etc/decoders to backups/<date>/,
# remove the pre-split file names (unifi_decoder.xml, unifi_rules.xml,
# local_tuning_rules.xml) and any earlier detections-*/tuning-* copies, copy
# the current files in with their directory as a prefix so detections load
# before tuning, run wazuh-analysisd -t, and only then restart the manager.
# If the check fails or a rule would be ignored, the backup is put back and
# nothing is restarted. The deployed commit is written to
# /var/ossec/etc/wazuh-detections.version inside the container.
set -euo pipefail
export MSYS_NO_PATHCONV=1

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRY=0
if [ "${1:-}" = "--dry-run" ]; then DRY=1; shift; fi
C="${1:-${WAZUH_MANAGER:-single-node-wazuh.manager-1}}"
RULES=/var/ossec/etc/rules
DECODERS=/var/ossec/etc/decoders
LEGACY="$RULES/unifi_rules.xml $RULES/local_tuning_rules.xml $DECODERS/unifi_decoder.xml"

hostpath() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi; }
ex() { docker exec -u root "$C" "$@"; }
say() { printf '%s\n' "$*"; }
run() { if [ "$DRY" = 1 ]; then say "would: $*"; else "$@"; fi; }

docker inspect "$C" >/dev/null 2>&1 || { say "container $C not found" >&2; exit 1; }

commit="$(git -C "$(hostpath "$HERE")" rev-parse --short HEAD 2>/dev/null || echo unknown)"
if [ -n "$(git -C "$(hostpath "$HERE")" status --porcelain -- decoders detections tuning 2>/dev/null)" ]; then
  say "warning: decoders/, detections/ or tuning/ have uncommitted changes; deploying the working tree as $commit-dirty"
  commit="$commit-dirty"
fi

stamp="$(date +%Y%m%d-%H%M%S)"
backup="$HERE/backups/$stamp"
say "manager:  $C"
say "commit:   $commit"
say "backup:   $backup"

say "== backing up the container's rules and decoders"
run mkdir -p "$backup"
run docker cp "$C:$RULES" "$(hostpath "$backup")/rules"
run docker cp "$C:$DECODERS" "$(hostpath "$backup")/decoders"

say "== removing old copies"
run ex sh -c "rm -f $LEGACY $RULES/detections-*.xml $RULES/tuning-*.xml $RULES/*.bak $DECODERS/*.bak"

say "== copying files"
for f in "$HERE"/decoders/*.xml; do
  run docker cp "$(hostpath "$f")" "$C:$DECODERS/$(basename "$f")"
done
for d in detections tuning; do
  for f in "$HERE"/$d/*.xml; do
    run docker cp "$(hostpath "$f")" "$C:$RULES/$d-$(basename "$f")"
  done
done
run ex sh -c "chown wazuh:wazuh $RULES/*.xml $DECODERS/*.xml && chmod 660 $RULES/*.xml $DECODERS/*.xml"

say "== checking the rule set"
if [ "$DRY" = 1 ]; then
  say "would: wazuh-analysisd -t, then restart"
  exit 0
fi
restore() {
  say "restoring $backup into the container" >&2
  ex sh -c "rm -f $RULES/*.xml $DECODERS/*.xml"
  for f in "$backup"/rules/*.xml; do docker cp "$(hostpath "$f")" "$C:$RULES/$(basename "$f")"; done
  for f in "$backup"/decoders/*.xml; do docker cp "$(hostpath "$f")" "$C:$DECODERS/$(basename "$f")"; done
  ex sh -c "chown wazuh:wazuh $RULES/*.xml $DECODERS/*.xml && chmod 660 $RULES/*.xml $DECODERS/*.xml"
}
out="$(ex /var/ossec/bin/wazuh-analysisd -t 2>&1)" || { printf '%s\n' "$out" >&2; restore; exit 1; }
if printf '%s\n' "$out" | grep -q 'will be ignored'; then
  printf '%s\n' "$out" >&2
  say "a rule would be ignored by analysisd" >&2
  restore
  exit 1
fi

ex sh -c "printf 'commit %s\ndeployed %s\n' '$commit' '$(date -u +%Y-%m-%dT%H:%M:%SZ)' > /var/ossec/etc/wazuh-detections.version"

say "== restarting the manager"
ex /var/ossec/bin/wazuh-control restart
for _ in $(seq 1 60); do
  if ex test -S /var/ossec/queue/sockets/logtest 2>/dev/null; then
    say "deployed $commit to $C"
    exit 0
  fi
  sleep 2
done
say "manager restarted but the logtest socket did not come back within two minutes; check docker logs $C" >&2
exit 1
