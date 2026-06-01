# Detection 05 — LOLBin Abuse Detection (CertUtil)

## MITRE ATT&CK

**Technique:** T1218 — System Binary Proxy Execution

**Tactic:** Defense Evasion

## Why This Matters

Attackers frequently abuse legitimate Windows utilities to perform malicious actions while blending into normal system activity. These trusted binaries are commonly referred to as Living Off The Land Binaries (LOLBins).

One of the most commonly abused LOLBins is `certutil.exe`, a Microsoft-signed utility originally designed for certificate management and troubleshooting. Adversaries often leverage CertUtil to download payloads, encode or decode files, transfer data and evade security controls without introducing additional tools onto the system.

Because CertUtil is a legitimate Windows component, its execution may appear normal unless proper monitoring and investigation are in place.

Monitoring CertUtil activity provides defenders with visibility into a tool that is frequently abused during malware delivery, post-exploitation activity and defense evasion operations.

## What Was Detected

Sysmon Event ID 1 captures process creation activity and records important details such as:

* Process name
* Command-line arguments
* Parent process
* User context
* Execution timestamp

This detection monitors for execution of:

```text
certutil.exe
```

and captures the associated command-line arguments to determine how the utility was used.

During validation, CertUtil was used to encode a file, generating telemetry that demonstrated visibility into LOLBin execution activity.

## Detection Query

### KQL Query

```kql
event.code: "1" AND process.name: "certutil.exe"
```

## Validation

CertUtil was executed on the monitored Windows endpoint to perform a file encoding operation.

Sysmon generated a Process Creation event which was forwarded through Winlogbeat, indexed in Elasticsearch and successfully visualized within Kibana.

The detection confirmed visibility into CertUtil execution activity and validated the ability to identify abuse of a trusted Windows binary frequently leveraged by attackers.

## Key Fields to Investigate

| Field                | Purpose                                    |
| -------------------- | ------------------------------------------ |
| process.command_line | Full CertUtil command executed             |
| process.parent.name  | Process responsible for launching CertUtil |
| user.name            | User account associated with the execution |
| host.name            | Endpoint where the activity occurred       |
| @timestamp           | Time of execution                          |

## Outcome

Successfully detected CertUtil execution activity and validated the ability to monitor a commonly abused LOLBin used by attackers for payload staging, file manipulation and defense evasion activities.
