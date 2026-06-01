# Detection 04 — Registry Run Key Persistence Detection

## MITRE ATT&CK

**Technique:** T1547.001 — Registry Run Keys / Startup Folder

**Tactic:** Persistence

## Why This Matters

Registry Run Keys are a legitimate Windows feature that allows applications to automatically execute when a user logs in. However, attackers frequently abuse these registry locations to establish persistence and ensure malicious payloads are executed automatically after system reboot or user logon.

Because Run Keys are commonly used by legitimate software, malicious entries can blend into normal system activity and remain undetected for long periods. This technique is frequently observed in malware infections, ransomware campaigns, commodity malware and advanced persistent threat (APT) operations.

Monitoring modifications to Run Keys provides defenders with visibility into one of the most common persistence mechanisms used by attackers to maintain access to compromised systems.

## What Was Detected

Sysmon Event ID 13 captures registry value modification activity and records important details such as:

* Registry path
* Registry value name
* Modified data
* User context
* Execution timestamp

This detection monitors modifications to Windows Run Key locations such as:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

and

```text
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
```

When a new entry is added, modified or removed, the resulting telemetry provides valuable insight into potential persistence-related activity.

## Detection Query

### KQL Query

```kql
event.code: "13" AND registry.path: "*CurrentVersion\\Run*"
```

## Validation

A registry Run Key entry was created on the monitored Windows endpoint.

Sysmon generated a Registry Value Set event which was forwarded through Winlogbeat, indexed in Elasticsearch and successfully visualized within Kibana.

The detection confirmed visibility into Run Key modifications and validated the ability to identify a persistence technique commonly used by attackers.

## Key Fields to Investigate

| Field          | Purpose                                  |
| -------------- | ---------------------------------------- |
| registry.path  | Registry location modified               |
| registry.value | Registry value name                      |
| process.name   | Process responsible for the modification |
| user.name      | User account associated with the action  |
| @timestamp     | Time of registry modification            |

## Outcome

Successfully detected Registry Run Key modification activity and validated the ability to monitor a widely abused persistence mechanism used by attackers to automatically execute malicious payloads during user logon.
