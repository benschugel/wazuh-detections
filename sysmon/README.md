# Sysmon configuration

`sysmonconfig.xml` is the unmodified SwiftOnSecurity
[sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)
(`sysmonconfig-export.xml`, source version 74, 2021-07-08, schema 4.50),
licensed under
[Creative Commons Attribution 4.0](https://creativecommons.org/licenses/by/4.0/).
The attribution header inside the file is the author's. It is tracked here
with `-text` in `.gitattributes` so its bytes, and therefore its hash, never
change on checkout.

Both Windows agents run it from `C:\Sysmon\sysmonconfig.xml`. Its SHA256 is

```
055FEBC600E6D7448CDF3812307275912927A62B1F94D0D933B64B294BC87162
```

which is also the "Config hash" that `Sysmon64.exe -c` prints when the
active configuration matches this file.

Check a machine (elevated PowerShell):

```
(Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters).ConfigHash
```

Apply it (elevated, no reboot needed):

```
C:\Windows\Sysmon64.exe -c C:\Sysmon\sysmonconfig.xml
```

Any change to this file changes the hash, so update this page and re-apply
on every machine together.

## Known weak spot

A driver install writes tens of thousands of registry values that the
configuration's include list catches (`\FriendlyName`, `\DriverVersion`,
`\Start`, `\ImagePath`). An Intel graphics update once overflowed the Sysmon
driver queue (event 255, about 41,000 registry events dropped) and the
process events that survived came through with an all-zero parent GUID.
Tuning rules 100252 and 100253 in `tuning/windows-sysmon.xml` handle that
fallout.
