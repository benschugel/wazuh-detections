# 100101: UniFi firewall block

| | |
|---|---|
| Level | 5 |
| Source | UniFi Network gateway CEF syslog, event name `Blocked by Firewall` |
| File | `detections/unifi.xml` |
| Depends on | base rule 100100, decoder `unifi-cef-fields` |
| Feeds | 100104 (block burst), 100242 (phone to gateway port 80, tuning) |

## What it detects

Every connection the gateway's zone-based firewall dropped and logged. The
description names the source address and zone, the destination zone and
port, and the policy that blocked it, so a single alert reads as "IoT device
tried to reach Trusted on port 445".

## Why it matters

Zone policies are the main control between the home networks. A block is
the first sign of a device probing where it should not, a misconfigured
client, or a compromised IoT device looking for neighbours. One block is
mostly audit material at level 5; the burst rule 100104 turns a run of them
into a page.

## MITRE ATT&CK

- T1046 Network Service Discovery. A single block is a weak signal; this tag
  mainly serves the dashboards that group by technique.

## How to trigger it in a lab

From a client in a zone that has a block policy toward the gateway or
another zone, make one connection that the policy covers, for example:

```
curl -m 2 http://<gateway address>/
```

The gateway must have syslog export of firewall logs enabled for the policy
(the policy's "Logging" switch in UniFi Network). The alert shows up within
a few seconds on the manager listening on UDP 514.

## Known false positives

- Devices that retry a blocked destination on their own: a phone fetching
  the gateway's captive-portal page on port 80 every few minutes was the
  first case and is handled by 100242 at level 2.
- Browsers and apps that try DNS over TLS or HTTPS when a "block DoT" policy
  exists.
- Multicast and discovery chatter when a zone forbids it.

## Tuning notes

Add a child rule under 100101 keyed on `unifi.client_alias`, the policy
name, or the zone pair rather than on an address, so a new DHCP lease does
not break it and the rule carries no LAN addresses. Children that take the
event out of 100101 also remove it from the 100104 count.
