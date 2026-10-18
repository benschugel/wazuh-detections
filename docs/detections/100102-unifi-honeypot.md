# 100102: UniFi honeypot triggered

| | |
|---|---|
| Level | 10 (Home Assistant notification threshold) |
| Source | UniFi Network gateway CEF syslog, event name `Honeypot` |
| File | `detections/unifi.xml` |
| Depends on | base rule 100100 |

## What it detects

A client touched the gateway's internal honeypot, an unused address on a
network that answers common service ports and logs whoever connects. The
description carries the UniFi client alias and the source MAC.

## Why it matters

Nothing legitimate talks to the honeypot address. A hit means something on
the LAN is sweeping the subnet or trying services on hosts it has never
been told about, which is what a worm, a compromised IoT device or an
attacker with a foothold does first.

## MITRE ATT&CK

- T1046 Network Service Discovery
- T1018 Remote System Discovery

## How to trigger it in a lab

Enable the honeypot on a network in UniFi Network (Security settings) and
note its address. From a client on that network:

```
nmap -p 22,80,443 <honeypot address>
```

or simply `curl -m 2 http://<honeypot address>/`. One connection is enough.

## Known false positives

- Network scanners and device-discovery tools that sweep the whole subnet:
  Home Assistant integrations that probe for devices, phone apps such as
  Fing, printer and media discovery on some vendors' software.
- A deliberate audit scan from the admin workstation.

## Tuning notes

Do not lower this rule for a whole zone. If a known scanner trips it on a
schedule, add a child rule keyed on `unifi.client_alias` and keep it at
level 3 so the audit trail stays.
