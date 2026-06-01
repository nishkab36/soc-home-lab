# Detection 01 — PowerShell Execution Monitoring

## MITRE ATT&CK

**Technique:** T1059.001 — Command and Scripting Interpreter: PowerShell

**Tactic:** Execution

## Why This Matters

PowerShell is one of the most powerful and most abused tools in Windows environments. It is built into every modern Windows system, trusted by the operating system and capable of performing a wide range of actions including downloading files, executing code in memory, modifying the registry, enumerating the network and interacting with system components.

Because PowerShell is a legitimate administrative utility, attackers frequently leverage it to blend malicious activity into normal system operations. It is commonly observed during ransomware deployment, post-exploitation activity, malware execution, reconnaissance and red team operations.

Monitoring PowerShell execution is not about blocking it. It is about maintaining visibility into when and how it is being used so that suspicious activity can be identified and investigated within context.

## What Was Detected

Sysmon Event ID 1 captures process creation activity and records important details such as:

* Process name
* Command-line arguments
* Parent process
* User context
* Execution timestamp

This detection monitors for process creation events where the executed process is:

```text
powershell.exe
```

While PowerShell execution alone is not inherently malicious, it serves as an important signal for threat hunting and investigation. The true value comes from analyzing execution context, parent-child process relationships and command-line arguments.

For example:

* PowerShell launched from the Start Menu may be normal.
* PowerShell launched from Microsoft Word, Outlook, a browser or another scripting engine may warrant further investigation.

## Detection Query

KQL Query

```kql
event.code: "1" AND process.name: "powershell.exe"
```

## Validation

PowerShell was executed on the monitored Windows endpoint.

Sysmon generated a Process Creation event which was forwarded through Winlogbeat, indexed in Elasticsearch and successfully visualized within Kibana.

The detection confirmed end-to-end visibility across the monitoring pipeline and verified that PowerShell execution activity could be identified and investigated from the SOC platform.

## Key Fields to Investigate

| Field                | Purpose                                             |
| -------------------- | --------------------------------------------------- |
| process.command_line | Exact PowerShell command executed                   |
| process.parent.name  | Parent process responsible for launching PowerShell |
| user.name            | User account associated with the execution          |
| host.name            | Endpoint where the activity occurred                |
| @timestamp           | Time of execution                                   |

## Outcome

Successfully detected PowerShell execution activity and validated telemetry collection, log forwarding, indexing and investigation capabilities within the SOC Home Lab environment.
