# Detection 06 — Failed Logon Monitoring

## MITRE ATT&CK

**Technique:** T1110 — Brute Force

**Tactic:** Credential Access

## Why This Matters

Failed logon attempts are one of the most common indicators of unauthorized access attempts within an environment. Attackers frequently attempt to gain access to systems through password guessing, brute-force attacks and password spraying campaigns.

While a single failed logon may be the result of a user typing an incorrect password, repeated authentication failures can indicate malicious activity targeting user accounts.

Monitoring failed authentication events provides defenders with visibility into potential credential-based attacks and enables early detection of unauthorized access attempts before a compromise occurs.

## What Was Detected

Windows generates Event ID 4625 whenever an authentication attempt fails.

These events contain valuable information including:

* Account name
* Failure reason
* Source workstation
* Logon type
* Authentication status
* Timestamp

This detection monitors failed authentication events and provides visibility into unsuccessful logon activity occurring on monitored systems.

By analyzing these events, defenders can identify patterns associated with brute-force attacks, password spraying campaigns and other credential-focused attack techniques.

## Detection Query

### KQL Query

```kql id="mth97v"
event.code: "4625"
```

## Validation

Multiple failed logon attempts were generated on the monitored Windows endpoint using incorrect credentials.

The resulting authentication events were successfully forwarded through Winlogbeat, indexed in Elasticsearch and visualized within Kibana.

The detection confirmed visibility into failed authentication activity and validated the ability to identify events commonly associated with credential access attacks.

## Key Fields to Investigate

| Field                            | Purpose                                |
| -------------------------------- | -------------------------------------- |
| winlog.event_data.TargetUserName | Account targeted during authentication |
| winlog.event_data.Status         | Authentication failure status code     |
| host.name                        | Endpoint where the activity occurred   |
| event.action                     | Authentication action performed        |
| @timestamp                       | Time of authentication attempt         |

## Outcome

Successfully detected failed logon activity and validated the ability to monitor authentication events that may indicate brute-force attacks, password spraying attempts or other unauthorized access activity.
