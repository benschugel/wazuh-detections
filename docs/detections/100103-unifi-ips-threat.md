# 100103: UniFi IPS threat detected

| | |
|---|---|
| Level | 10 (Home Assistant notification threshold) |
| Source | UniFi Network gateway CEF syslog, event name `Threat Detected` |
| File | `detections/unifi.xml` |
| Depends on | base rule 100100 |

## What it detects

A signature match from the gateway's intrusion detection and prevention
engine (Suricata with the Emerging Threats rule set, as shipped by UniFi).
The description is the gateway's own message, which names the signature
and the two endpoints.

## Why it matters

The IPS is the only network-layer control that inspects payloads, so it
catches command-and-control beacons, exploit attempts against exposed
services and known-bad downloads that the firewall zones let through. Any
match is worth a phone notification, and a blocked match still tells you
which host tried.

## MITRE ATT&CK

The technique depends on the signature. The rule carries the two that cover
the bulk of the Emerging Threats categories the gateway enables:

- T1190 Exploit Public-Facing Application
- T1071 Application Layer Protocol (command and control)

## How to trigger it in a lab

With intrusion prevention enabled and the "Attack Response" (or equivalent)
category on, fetch the standard Suricata test page from a client:

```
curl -m 5 http://testmyids.com/
```

The response matches the classic "GPL ATTACK_RESPONSE id check returned
root" signature. UniFi logs it as a threat and, in prevention mode, resets
the connection.

## Known false positives

- "ET POLICY" and "ET INFO" style signatures on legitimate software
  (torrent clients, remote desktop tools, unusual user agents).
- Security scanners or vulnerability tooling run on purpose from the admin
  workstation.
- Signatures on DNS or TLS metadata that fire on ad networks and CDNs.

## Tuning notes

Prefer disabling a noisy signature or category in UniFi over suppressing
the Wazuh alert, so the gateway stops blocking the traffic too. If a Wazuh
child rule is needed, key it on `unifi.msg` (the signature text) and the
client alias, and keep it at level 3.
