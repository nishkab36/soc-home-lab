# SOC Home Lab

A Security Operations Center (SOC) Home Lab built using ELK Stack, Sysmon and Winlogbeat to simulate real world attacker behavior, collect endpoint telemetry, validate security detections and perform threat investigations.

This project focuses on Detection Engineering, Security Monitoring, Threat Hunting and MITRE ATT&CK based detection development through practical attack simulations conducted in an isolated lab environment.

## Project Overview

Modern Security Operations Centers rely on centralized logging, endpoint telemetry and threat detection capabilities to identify suspicious activities across enterprise environments.

The objective of this project was to design and deploy a functional SOC monitoring environment capable of:

* Collecting endpoint telemetry
* Centralizing security logs
* Detecting attacker techniques
* Investigating security events
* Mapping detections to MITRE ATT&CK

Rather than simply forwarding logs, this lab validates real world detection scenarios commonly investigated by SOC analysts and blue team defenders.

## Technologies Used

| Technology            | Purpose                      |
| --------------------- | ---------------------------- |
| Elasticsearch 7.17.29 | Log Storage & Indexing       |
| Kibana 7.17.29        | Log Analysis & Visualization |
| Sysmon                | Advanced Endpoint Telemetry  |
| Winlogbeat            | Log Collection & Forwarding  |
| Windows 10            | Monitored Endpoint           |
| Ubuntu Linux          | SOC Server                   |

## Detection Use Cases Implemented

### Detection 01 – PowerShell Execution Monitoring

MITRE ATT&CK:

* T1059.001 – PowerShell

Objective:
Detect PowerShell execution activity on monitored endpoints.

### Detection 02 – Encoded PowerShell Detection

MITRE ATT&CK:

* T1027 – Obfuscated Files or Information

Objective:
Detect PowerShell commands executed using Base64 encoding techniques.

### Detection 03 – Scheduled Task Persistence Detection

MITRE ATT&CK:

* T1053.005 – Scheduled Task

Objective:
Detect creation of Windows Scheduled Tasks commonly used for persistence.

### Detection 04 – Registry Run Key Persistence Detection

MITRE ATT&CK:

* T1547.001 – Registry Run Keys / Startup Folder

Objective:
Detect modifications to Windows Run Registry Keys used for persistence.

### Detection 05 – LOLBin Abuse Detection (CertUtil)

MITRE ATT&CK:

T1218 – System Binary Proxy Execution

Objective:
Detect execution of CertUtil, a trusted Windows binary frequently abused by attackers for file transfer, encoding, decoding and payload staging activities.

### Detection 06 – Failed Logon Detection

MITRE ATT&CK:

* T1110 – Brute Force

Objective:
Detect failed authentication attempts that may indicate password spraying or brute-force activity.

## Key Learning Outcomes

Through this project, I gained hands-on experience with:

* Building a centralized logging platform
* Deploying endpoint telemetry collection
* Investigating Windows security events
* Developing and validating detections
* Mapping detections to MITRE ATT&CK
* Threat hunting using Kibana
* Understanding attacker persistence techniques
* Monitoring authentication-related activity

## Future Enhancements

Planned future improvements include:

* Service Creation Detection
* PsExec Detection
* WMI Event Subscription Detection
* Privilege Escalation Monitoring
* RDP Activity Monitoring
* Lateral Movement Detection
* Sigma Rule Integration
* Automated Alerting
* Threat Intelligence Enrichment
* Detection Dashboard Development

## Disclaimer

All attack simulations and detection validations were performed in an isolated lab environment for educational, research and defensive security purposes only.
