# wazuh-detections

Custom detection content for a home Wazuh 4.14 manager: a UniFi gateway
decoder, detection rules for UniFi and Windows (Sysmon and event log),
the noise tuning that keeps the stock Sysmon rules usable on real desktops,
the Sysmon configuration the agents run, and a test harness that proves
every rule still does what its test cases say.

The rules were split out of the [homelab-docker](https://github.com/benschugel/homelab-docker)
repository, which runs the manager. This repository is the source of truth
for them.

## Layout

| Path | Holds |
|---|---|
| `decoders/unifi.xml` | Decoder for UniFi Network CEF syslog (`unifi-cef`, `unifi-cef-fields`) |
| `detections/` | Detection rules by source: `unifi.xml`, `windows-sysmon.xml`, `windows-eventlog.xml` |
| `tuning/` | Suppressions and benign labels by source: UniFi, Sysmon, Windows event log, syscheck and rootcheck, Docker, SCA |
| `docs/detections/` | One page per detection: what it catches, why, MITRE ATT&CK, how to trigger it, false positives, tuning |
| `tests/` | `run_cases.py` (the runner), `cases/<rule>.json` (test cases per rule), `logtest.py` (socket client), `replay.py` (replay recorded alerts), `harness.sh` (throwaway manager) |
| `sysmon/` | The SwiftOnSecurity Sysmon configuration both agents run, with attribution and the apply procedure |

Rule ids: 100100 to 100199 are UniFi, 100200 to 100499 Windows tuning,
100500 and up Windows detections. 19007 to 19009 overwrite stock SCA rules.

### Detections

| Rule | Level | Catches |
|---|---|---|
| [100101](docs/detections/100101-unifi-firewall-block.md) | 5 | UniFi firewall block |
| [100102](docs/detections/100102-unifi-honeypot.md) | 10 | UniFi honeypot triggered |
| [100103](docs/detections/100103-unifi-ips-threat.md) | 10 | UniFi IPS threat detected |
| [100104](docs/detections/100104-unifi-firewall-block-burst.md) | 12 | 8+ blocks from one source in 60 s |
| [100241](docs/detections/100241-kernel-driver-install.md) | 12 | Kernel mode driver installed |
| [100500](docs/detections/100500-temp-drop-burst.md) | 15 | Burst of executables dropped in Temp by one process |

## Rule level convention

Level 0 is pure telemetry or a fully identified benign pattern and ends
processing; level 1 is stored and indexed but easy to filter with
`rule.level >= 3`; level 3 is a security-relevant event from a trusted
admin-only path, kept for audit but below the Home Assistant threshold
(level 10). Scope every rule by full image path, command line or target
path, and never silence a stock rule outright unless it is pure telemetry.

Writing rules for the Windows agent:

- Field values contain doubled backslashes. Match them with `\\\\`.
- Write a literal `$` as `\x24` and a literal `&` as `\x26`. The rule
  loader does not decode `&amp;`, so a pattern written that way loads but
  never matches.
- A `<field>` without `type="pcre2"` uses OS_Regex, which rejects `\{`.
  Use pcre2 for anything with braces or GUIDs.
- A negated `<field>` never matches when the field is absent. Check the
  full event text instead (rule 100233).
- Frequency rules fire on the Nth event and re-arm, so a long run re-fires
  every N events. Events taken by a child rule do not count toward the
  parent's `if_matched_sid`.

## Deploy

The manager reads `etc/decoders` and `etc/rules` as flat directories in
file name order. The tuning rules for UniFi depend on the UniFi detections
(`if_sid` 100100 and 100101), so the files are copied in with their
directory as a prefix, which keeps `detections-*` ahead of `tuning-*`:

```
decoders/unifi.xml            -> /var/ossec/etc/decoders/unifi.xml
detections/unifi.xml          -> /var/ossec/etc/rules/detections-unifi.xml
tuning/windows-sysmon.xml     -> /var/ossec/etc/rules/tuning-windows-sysmon.xml
```

Into a manager container by hand (`M` is the container name):

```
export MSYS_NO_PATHCONV=1
for f in decoders/*.xml; do docker cp "$f" $M:/var/ossec/etc/decoders/; done
for d in detections tuning; do for f in $d/*.xml; do docker cp "$f" $M:/var/ossec/etc/rules/$d-$(basename "$f"); done; done
docker exec -u root $M sh -c 'chown wazuh:wazuh /var/ossec/etc/rules/*.xml /var/ossec/etc/decoders/*.xml; chmod 660 /var/ossec/etc/rules/*.xml /var/ossec/etc/decoders/*.xml'
docker exec -u root $M /var/ossec/bin/wazuh-analysisd -t && docker exec -u root $M /var/ossec/bin/wazuh-control restart
```

Files that stay in homelab-docker: the manager's `ossec.conf`, the shared
`agent.conf` (rule 100262 pairs with its `report_changes` FIM entries), the
Docker listener and the Home Assistant integration.

## Tests

Every rule with test cases has a `tests/cases/<rule>.json` file. A case is
one event and the rule id and level it must produce; sequence cases send
several events through one logtest session for the frequency rules. Both
the rule under test and its negative cases ("look-alike path is NOT
lowered") live in the same file.

Run them in a throwaway manager (needs Docker; about two minutes):

```
tests/harness.sh all            # start, load rules, run everything, remove
tests/harness.sh all 100500     # one rule
```

Or step by step: `up`, `load`, `test [rule ids]`, `shell`, `down`. The
harness patches stock rules 60000 and 19000 in the throwaway container so
that JSON copies of Windows event channel and SCA events go through the
same rule tree they would on a live manager, where only the agent's own
decoders feed those rules. Never apply those patches to a live manager.

`tests/replay.py` replays an `alerts.json` copied out of a live manager
and reports which alerts would land on a different rule or level now. The
alerts hold real host data; the `.gitignore` keeps them out.

Rootcheck and FIM rules (`tuning/syscheck-rootcheck.xml`) cannot be
replayed through logtest and are checked live.

## Continuous integration

`.github/workflows/test.yml` runs on every push and pull request:
`tests/check_xml.py` (well-formedness of every decoder, rule and Sysmon
file), then `tests/harness.sh all` in a throwaway 4.14.8 manager. A rule
that analysisd ignores, or any case landing on a different rule or level,
fails the build.

## Attribution

`sysmon/sysmonconfig.xml` is the unmodified SwiftOnSecurity
[sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config), CC BY 4.0;
see `sysmon/README.md`. Everything else is covered by the BSD 3-Clause
license in `LICENSE`. The test harness patches two files of the Wazuh
ruleset (GPLv2) inside a container at run time and ships no copy of them.
