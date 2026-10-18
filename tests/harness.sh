#!/usr/bin/env bash
# Throwaway wazuh-manager for testing the rules in this repository.
#
#   tests/harness.sh all [rule ids]   up, load, test, down (exit code of test)
#   tests/harness.sh up               start the container and patch stock rules
#   tests/harness.sh load             copy decoders and rules in, check, restart
#   tests/harness.sh test [rule ids]  copy tests/ in and run run_cases.py
#   tests/harness.sh shell            open a shell in the container
#   tests/harness.sh down             remove the container
#
# Environment: HARNESS_CONTAINER (default wazuh-detections-test),
#              WAZUH_IMAGE (default wazuh/wazuh-manager:4.14.8).
#
# wazuh-logtest cannot evaluate Windows event channel or SCA events as
# shipped: their base rules 60000 and 19000 only accept the agent's own
# decoders. The harness patches those two rules in the throwaway container
# so JSON copies of recorded events are evaluated by the same rule tree.
# Never apply these patches to a live manager.
set -euo pipefail
export MSYS_NO_PATHCONV=1

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
C="${HARNESS_CONTAINER:-wazuh-detections-test}"
IMAGE="${WAZUH_IMAGE:-wazuh/wazuh-manager:4.14.8}"
PY=/var/ossec/framework/python/bin/python3
STOCK=/var/ossec/ruleset/rules

# docker on Windows (Git Bash) wants C:\ style host paths
hostpath() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi; }
ex() { docker exec -u root "$C" "$@"; }

wait_ready() {
  for _ in $(seq 1 120); do
    if ex "$PY" -c 'import socket; s = socket.socket(socket.AF_UNIX); s.connect("/var/ossec/queue/sockets/logtest")' 2>/dev/null; then
      return 0
    fi
    sleep 2
  done
  echo "manager did not become ready" >&2
  docker logs --tail 30 "$C" >&2 || true
  return 1
}

cmd_up() {
  if docker inspect "$C" >/dev/null 2>&1; then
    echo "container $C already exists; run 'down' first" >&2
    return 1
  fi
  docker run -d --name "$C" "$IMAGE" >/dev/null
  echo "started $C from $IMAGE, waiting for analysisd"
  wait_ready
  cmd_patch
}

cmd_patch() {
  ex sed -i -e 's#<decoded_as>windows_eventchannel</decoded_as>#<decoded_as>json</decoded_as>#' \
            -e 's#^ *<category>ossec</category>##' "$STOCK/0575-win-base_rules.xml"
  ex sed -i -e 's#<decoded_as>sca</decoded_as>#<decoded_as>json</decoded_as><field name="sca.type" type="pcre2">.+</field>#' \
            -e 's#^ *<category>ossec</category>##' "$STOCK/0570-sca_rules.xml"
  echo "patched stock rules 60000 and 19000 for JSON input"
}

cmd_load() {
  ex sh -c 'rm -f /var/ossec/etc/rules/detections-*.xml /var/ossec/etc/rules/tuning-*.xml'
  for f in "$REPO"/decoders/*.xml; do
    docker cp "$(hostpath "$f")" "$C:/var/ossec/etc/decoders/$(basename "$f")"
  done
  # etc/rules is one flat directory read in name order, and the tuning files
  # depend on rules in the detection files, so the prefix keeps that order.
  for d in detections tuning; do
    for f in "$REPO"/$d/*.xml; do
      docker cp "$(hostpath "$f")" "$C:/var/ossec/etc/rules/$d-$(basename "$f")"
    done
  done
  ex sh -c 'chown wazuh:wazuh /var/ossec/etc/rules/*.xml /var/ossec/etc/decoders/*.xml && chmod 660 /var/ossec/etc/rules/*.xml /var/ossec/etc/decoders/*.xml'
  # analysisd -t exits 0 when a rule's if_sid parent is not loaded yet; the
  # rule is silently dropped with a warning, so treat that warning as an error.
  out="$(ex /var/ossec/bin/wazuh-analysisd -t 2>&1)" || { printf '%s
' "$out" >&2; return 1; }
  if printf '%s
' "$out" | grep -q 'will be ignored'; then
    printf '%s
' "$out" >&2
    echo "a rule was ignored by analysisd, see the warnings above" >&2
    return 1
  fi
  echo "rules loaded, restarting the manager"
  ex /var/ossec/bin/wazuh-control restart >/dev/null
  wait_ready
}

cmd_test() {
  ex rm -rf /tests
  docker cp "$(hostpath "$HERE")" "$C:/tests"
  ex "$PY" /tests/run_cases.py "$@"
}

cmd_shell() { docker exec -it -u root "$C" bash; }

cmd_down() { docker rm -f -v "$C" >/dev/null 2>&1 || true; }

cmd_all() {
  cmd_up
  cmd_load
  rc=0
  cmd_test "$@" || rc=$?
  cmd_down
  exit $rc
}

case "${1:-}" in
  up|patch|load|test|shell|down|all) cmd="$1"; shift; "cmd_$cmd" "$@" ;;
  *) sed -n '2,15p' "$0"; exit 1 ;;
esac
