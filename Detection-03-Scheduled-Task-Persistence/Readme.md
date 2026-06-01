# Detection 03 — Scheduled Task Persistence Detection

## MITRE ATT&CK

**Technique:** T1053.005 — Scheduled Task

**Tactic:** Persistence

## Why This Matters

Scheduled Tasks are a legitimate Windows feature used to automate administrative and maintenance activities. However, attackers frequently abuse them to establish persistence, execute malicious payloads at predefined intervals or launch malware automatically after system startup.

Because Scheduled Tasks are a trusted Windows mechanism, malicious tasks can blend into normal system activity and remain unnoticed for extended periods. They are commonly observed in malware infections, ransomware operations, red team engagements and post-exploitation scenarios.

Monitoring the creation of new Scheduled Tasks provides defenders with visibility into a persistence technique frequently leveraged by adversaries to maintain access to compromised systems.

## What Was Detected

Sysmon Event ID 1 captures process creation activity and records important details such as:

* Process name
* Command-line arguments
* Parent process
* User context
* Execution timestamp

This detection monitors for execution of:

```text
schtasks.exe
```

particularly when used to create new Scheduled Tasks.

When a task is created, the associated command-line arguments provide valuable context regarding the task name, execution schedule and intended action.

## Detection Query

### KQL Query

```kql
event.code: "1" AND process.name: "schtasks.exe"
```

## Validation

A Scheduled Task was created on the monitored Windows endpoint.

Sysmon generated a Process Creation event which was forwarded through Winlogbeat, indexed in Elasticsearch and successfully visualized within Kibana.

The detection confirmed visibility into Scheduled Task creation activity and validated the ability to identify a common persistence mechanism used by attackers.

## Key Fields to Investigate

| Field                | Purpose                                        |
| -------------------- | ---------------------------------------------- |
| process.command_line | Full schtasks command executed                 |
| process.parent.name  | Process responsible for launching schtasks.exe |
| user.name            | User account associated with the action        |
| host.name            | Endpoint where the activity occurred           |
| @timestamp           | Time of task creation                          |

## Outcome

Successfully detected Scheduled Task creation activity and validated the ability to monitor a persistence technique commonly used by attackers to maintain long-term access to compromised systems.
