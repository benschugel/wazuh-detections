# 100500: Burst of executables dropped in Temp by one process

| | |
|---|---|
| Level | 15 |
| Source | Sysmon event 11 (file create), via the Wazuh agent |
| File | `detections/windows-sysmon.xml` |
| Depends on | `if_matched_sid` 92213 (executable dropped in Temp, stock level 15), `same_field` `win.eventdata.processGuid`, frequency 10 in 120 s |

## What it detects

One process (by Sysmon ProcessGuid) that has written ten executable files
into a user's Temp folder inside two minutes. Stock rule 92213 keeps firing
at level 15 per file; the tenth event becomes this summary, whose
description names the writing image, so a burst reads as one line with the
per-file alerts under it.

## Why it matters

Droppers and loaders stage their payload in Temp, and they rarely write a
single file. The summary gives the analyst the process name at the top of
the burst instead of thirty identical file alerts. Trusted installers that
do the same thing are already taken out of the count by the tuning rules
100240, 100243, 100250 and 100251, so a burst that reaches this rule comes
from a writer nobody has vouched for.

## MITRE ATT&CK

- T1105 Ingress Tool Transfer

## How to trigger it in a lab

From a normal PowerShell prompt on an agent running the Sysmon
configuration in `sysmon/`:

```
1..12 | ForEach-Object { Copy-Item C:\Windows\System32\calc.exe "$env:TEMP\burst$_.exe" }
Remove-Item "$env:TEMP\burst*.exe"
```

Sysmon logs each `.exe` create, 92213 alerts on each, and the tenth becomes
100500 naming `powershell.exe`. Nothing is executed.

## Behaviour of Wazuh frequency rules

Verified on 4.14.8 while building this rule:

- It fires on the tenth matching event, not the twelfth. Events one to nine
  and eleven onwards keep 92213.
- The counter re-arms, so a long burst re-fires every ten files (144 files
  gave 14 summaries). `ignore` on the rule changes nothing.
- Events taken by a child rule of 92213 do not count.
- `wazuh-logtest` only counts events in different seconds, so the test
  cases send one event per second in a shared session.

## Known false positives

- Installers and self-updaters unpacking into Temp. Known ones are scoped
  by writer and target folder in `tuning/windows-sysmon.xml`; a new one
  will show up here first.
- Build tools and package managers writing launcher stubs (uv is handled by
  100203).

## Tuning notes

Scope any exemption by the full writer image path and the exact Temp
subfolder it uses, as a child of 92213 at level 3 (or 0 for pure
telemetry). That both lowers the per-file alerts and removes them from
this count. Do not raise the threshold.
