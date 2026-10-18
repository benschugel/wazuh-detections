# Detection backlog

Candidates for new detections, written 2026-10-18. Each one uses a channel
the agents already send. None of them has rules yet.

Conventions for any of these: child rules under a stock base rule, ids from
100510 up, scope by full path. Validate by running the Atomic Red Team test
for the technique on your own machine and running its documented cleanup.

## Order

| Priority | Item | Difficulty | Why this slot |
|---|---|---|---|
| 1 | [Scheduled task from a user-writable path](#1-scheduled-task-from-a-user-writable-path) | Low to medium | Cheap, low noise; needs the TaskScheduler log enabled first |
| 1 | [Service installed from a user-writable path](#2-service-installed-from-a-user-writable-path) | Low | Sibling of 100241, channel already flowing, quiet in 30 days of data |
| 1 | [Permanent WMI event subscription](#5-permanent-wmi-event-subscription) | Low | Near-zero noise on a home PC, channel already flowing |
| 2 | [Defender disabled or exclusion added](#6-defender-disabled-or-exclusion-added) | Medium | High value; a few installer exclusions to tune out |
| 2 | [Remote interactive logon](#7-remote-interactive-logon) | Low to medium | Only noise is your own RDP use |
| 3 | [Encoded or download-and-run PowerShell](#3-encoded-or-download-and-run-powershell) | High | Overlaps stock rules; Claude Code and uv run PowerShell constantly |
| 3 | [LOLBins with download or script arguments](#4-lolbins-with-download-or-script-arguments) | High | Installers use the same binaries legitimately |
| 3 | [Execution from Downloads](#8-execution-from-downloads) | High | Every installer you download matches; value is in the audit trail |

Priority 1 items are cheap and quiet. Priority 2 next. Priority 3 items need
the most tuning and are best done one at a time with a replay of a week of
alerts (`tests/replay.py`), the way the Oct 8 and Oct 9 passes went.

## 1. Scheduled task from a user-writable path

- **MITRE:** T1053.005 Scheduled Task
- **Difficulty:** Low for the Sysmon and FIM parts, medium for the
  TaskScheduler log once enabled
- **Status:** Researched, not written

Persistence that survives reboots and needs no admin for the user's own
tasks. Fire when the task action points under Users, ProgramData, Temp or a
drive root; keep Microsoft and installer-created tasks at audit level.

Sources: TaskScheduler/Operational 106 (registered) and 140 (updated),
Security 4698, Sysmon 1 for `schtasks.exe`, FIM on `C:\Windows\System32\Tasks`.

Findings from 2026-10-18:

- **Prerequisite:** zero TaskScheduler/Operational alerts in 30 days despite
  stock rule 67014 at level 3, so the log is disabled on both agents. Enable
  it with `wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true`.
- Security 4698 needs the Object Access audit policy (Other Object Access
  Events), probably also off.
- What flows today: FIM on the Tasks folder (185 events in 30 days, including
  noisy Edge updater rewrites at level 7 worth tuning separately) and Sysmon
  event 1. Stock has no `schtasks.exe` rule. The Sysmon event 1 group is
  `sysmon_event1` (no underscore before the 1).
- Stock 0580-win-security has rule 60228 for 4698 at level 4; a child
  rule hangs on it.

Noise: Windows setup "SoftLanding" tasks are already handled by 100234;
OneDrive, Edge and GPU vendor updaters create tasks on a schedule.

## 2. Service installed from a user-writable path

- **MITRE:** T1543.003 Windows Service
- **Difficulty:** Low
- **Status:** Researched, not written

The user-mode sibling of 100241. Fire at level 10 when the service image is
outside Program Files, Windows and the DriverStore.

Source: System 7045, stock rule 61138 at level 5.

Findings from 2026-10-18:

- The image path arrives quoted, and the quote reaches the field as a
  backslash-escaped quote; handle it the same way rule 100245 does.
- 36 service installs in 30 days, all from Program Files, so the rule would
  have been silent.

Noise: per-user services are already tuned by 100227; Docker Desktop and
game launchers install from Program Files.

## 3. Encoded or download-and-run PowerShell

- **MITRE:** T1059.001 PowerShell, T1027.010 Command Obfuscation
- **Difficulty:** High
- **Status:** Idea

Sources: Sysmon 1 command line, PowerShell/Operational 4104 script blocks.
Stock already covers `-EncodedCommand` in 0800-sysmon_id_1 and some 4104
keywords in 0915-win-powershell, so step one is a logtest pass to see what
stock produces and at what level. The gap is 4104 content that decodes or
downloads and then invokes, and command lines using the short forms of the
encoding flag.

Noise: Claude Code sessions and `uv run` start PowerShell constantly; scope
by parent image the way 100213 and 100214 do.

## 4. LOLBins with download or script arguments

- **MITRE:** T1218.010 Regsvr32, T1197 BITS Jobs, T1047 WMI, T1218.007 Msiexec
- **Difficulty:** High
- **Status:** Idea

Source: Sysmon 1. Stock has rules for certutil, mshta and rundll32; nothing
for regsvr32, bitsadmin, wmic or msiexec with a URL. Fire on those four when
the command line carries a URL or remote path.

Noise: installers use regsvr32 and msiexec legitimately, so match on the URL
or remote path, never the binary alone.

## 5. Permanent WMI event subscription

- **MITRE:** T1546.003 WMI Event Subscription
- **Difficulty:** Low
- **Status:** Researched, not written

Classic fileless persistence and almost never legitimate on a home PC.

Sources: WMI-Activity/Operational 5861, Sysmon 19, 20 and 21 (the
SwiftOnSecurity config in `sysmon/` already logs them).

Findings from 2026-10-18:

- WMI-Activity events reach the manager today; stock rule 92654 has fired.
- Stock Sysmon rules 89501 and 89502 already cover event 20 consumers of
  the CommandLine and Script types at levels 12 and 14.
- Gaps: Sysmon 19 (filter) and 21 (binding), and channel event 5861, have
  no stock rule. Base to hang on: 60018 for the channel, groups
  `sysmon_event_19` and `sysmon_event_21` for Sysmon.

Noise: near zero. SCCM and some monitoring agents create subscriptions;
neither runs here.

## 6. Defender disabled or exclusion added

- **MITRE:** T1562.001 Disable or Modify Tools
- **Difficulty:** Medium
- **Status:** Idea

Sources: Defender/Operational 5001, 5010 and 5012; Sysmon 13 on the Windows
Defender policy and exclusion registry keys. Stock 62100-series covers the
Defender events at modest levels; the registry side is new. Fire at level 10
for a disable, or for a new exclusion path not under Program Files.

Noise: Docker Desktop and Visual Studio installers add exclusions; one
child rule per known installer.

## 7. Remote interactive logon

- **MITRE:** T1021.001 Remote Desktop Protocol
- **Difficulty:** Low to medium
- **Status:** Idea

Sources: TerminalServices-LocalSessionManager 21 and 25, Security 4624
logon type 10. Stock 0840-win_event_channel has a type 10 rule. Fire at
level 10 for any RDP session; lower to 3 when the source is in the
Tailscale range (100.64.0.0/10).

Noise: only your own RDP use. Validate by connecting from the laptop over
Tailscale, then once from the LAN.

## 8. Execution from Downloads

- **MITRE:** T1204.002 Malicious File
- **Difficulty:** High
- **Status:** Idea

Downloads is under real-time FIM, but nothing watches what runs from it.
Sources: Sysmon 1 with the image under Downloads, Sysmon 15 (alternate
data stream) for mark-of-the-web on new executables. No stock sysmon_id_15
rules ship. Fire at level 7 for execution of a marked file, level 3 for the
download itself.

Noise: every installer you download, so the level stays below the Home
Assistant threshold on purpose.
