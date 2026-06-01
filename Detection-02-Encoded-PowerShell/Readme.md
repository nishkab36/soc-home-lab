# Detection 02 — Encoded PowerShell Detection

## MITRE ATT&CK

**Technique:** T1027 — Obfuscated Files or Information

**Tactic:** Defense Evasion

## Why This Matters

Attackers frequently use Base64-encoded PowerShell commands to hide their intentions and make malicious activity harder to detect. Instead of executing readable commands, the payload is encoded and supplied to PowerShell using parameters such as `-enc` or `-encodedcommand`.

This technique is commonly observed in malware infections, ransomware campaigns, phishing attacks, red team operations and post-exploitation activities. Encoded commands help adversaries bypass basic monitoring and reduce the likelihood of immediate detection by defenders.

Monitoring for encoded PowerShell execution provides visibility into potentially suspicious activity and enables analysts to investigate commands that may otherwise remain hidden.

## What Was Detected

Sysmon Event ID 1 captures process creation activity and records important details such as:

* Process name
* Command-line arguments
* Parent process
* User context
* Execution timestamp

This detection monitors for PowerShell executions where encoded commands are supplied through command-line parameters such as:

```text
-enc
```

or

```text
-encodedcommand
```

While encoded PowerShell is not always malicious, it is frequently associated with attacker tradecraft and should be investigated to determine the purpose of the executed command.

## Detection Query

### KQL Query

```kql
event.code: "1" AND process.name: "powershell.exe" AND process.command_line: "*-enc*"
```

## Validation

A Base64-encoded PowerShell command was executed on the monitored Windows endpoint.

Sysmon generated a Process Creation event which was forwarded through Winlogbeat, indexed in Elasticsearch and successfully visualized within Kibana.

The detection confirmed visibility into encoded PowerShell activity and verified that command-line arguments were captured correctly within the monitoring pipeline.

## Key Fields to Investigate

| Field                | Purpose                                      |
| -------------------- | -------------------------------------------- |
| process.command_line | Full encoded PowerShell command              |
| process.parent.name  | Process responsible for launching PowerShell |
| user.name            | User account associated with the execution   |
| host.name            | Endpoint where the activity occurred         |
| @timestamp           | Time of execution                            |

## Outcome

Successfully detected encoded PowerShell execution activity and validated the ability to identify obfuscated command execution techniques commonly associated with attacker operations.
