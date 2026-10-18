# 100241: Kernel mode driver installed

| | |
|---|---|
| Level | 12 (Home Assistant notification threshold is 10) |
| Source | Windows System event log, Service Control Manager event 7045, via the Wazuh agent |
| File | `detections/windows-eventlog.xml` |
| Depends on | stock rule 61138 (service installed, level 5), `serviceType` is `kernel mode driver` |

## What it detects

A new service of type kernel mode driver registered on a Windows agent. The
description names the service and the driver image path. User mode services
stay at the stock level 5.

## Why it matters

A kernel driver runs with the highest privilege on the machine. Vendor
utilities (GIGABYTE RGB Fusion, MSI, AMD and Intel tools) ship signed but
exploitable drivers, and "bring your own vulnerable driver" is the standard
way malware with admin rights disables EDR or reads kernel memory. Even an
intended install is worth a phone notification so it can be matched to what
you were doing at the time.

## MITRE ATT&CK

- T1543.003 Create or Modify System Process: Windows Service
- T1068 Exploitation for Privilege Escalation

## How to trigger it in a lab

Register a driver service without starting it, from an elevated prompt,
then remove it:

```
sc create TestKernelDrv type= kernel binPath= C:\Windows\System32\drivers\null.sys
sc delete TestKernelDrv
```

Event 7045 is written at `sc create`; the driver is never loaded.
Reinstalling Sysmon (`Sysmon64.exe -i`) also produces it for `SysmonDrv`.

## Known false positives

- Graphics, chipset and audio driver updates.
- Anti-cheat drivers installed by games.
- VPN and virtual adapter installers (TAP, WireGuard, Tailscale).
- Sysmon and other monitoring agents on upgrade.

All of these are real driver installs. The rule is meant to fire on them;
the value is in confirming each one was expected.

## Tuning notes

If a specific driver is reinstalled on a schedule, add a child rule keyed
on `win.eventdata.serviceName` and `win.eventdata.imagePath` at level 3.
Do not lower 100241 itself.
