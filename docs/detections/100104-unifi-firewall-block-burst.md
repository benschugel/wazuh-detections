# 100104: UniFi firewall block burst

| | |
|---|---|
| Level | 12 (Home Assistant notification threshold is 10) |
| Source | UniFi Network gateway CEF syslog, built on 100101 |
| File | `detections/unifi.xml` |
| Depends on | `if_matched_sid` 100101, `same_srcip`, frequency 8 in 60 s |

## What it detects

Eight or more firewall blocks from the same source address inside sixty
seconds. A device that hits a closed door once is noise; one that hits it
eight times in a minute is scanning ports or sweeping hosts.

## Why it matters

Port and host scans are the first move of anything that has landed on the
LAN, and a scan that crosses zones is exactly what the zone policies exist
to stop. This is the rule that pages for it.

## MITRE ATT&CK

- T1046 Network Service Discovery

## How to trigger it in a lab

From a client in a zone with a block policy toward the gateway (or another
zone), scan a handful of ports in quick succession:

```
nmap -p 1-20 <gateway address>
```

or a loop of `curl -m 1` calls to different ports. The eighth block within
the window becomes the 100104 alert.

## Behaviour of Wazuh frequency rules

Verified on 4.14.8 while building rule 100500:

- The rule fires on the eighth matching event, not the ninth; events one to
  seven and nine onwards keep rule 100101.
- The counter re-arms, so a long scan re-fires every eight blocks.
- Events taken by a child rule of 100101 (for example 100242) do not count.
- `wazuh-logtest` keeps frequency state per session token but only counts
  events in different seconds, so test cases send one event per second.

## Known false positives

- A device retrying a blocked destination in a tight loop (the phone on
  gateway port 80 did this before 100242 took those events out of the
  count).
- Discovery protocols that fan out across a subnet when a zone blocks them.

## Tuning notes

Never raise the threshold to silence a chatty device. Add a child rule
under 100101 for that device's specific pattern instead; it then stops
counting here automatically.
