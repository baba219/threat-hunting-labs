# IOC-Driven Hunt


## Overview

In this lab, you investigate a multi-stage adversary campaign using an **indicator-driven approach** in Kibana and Elasticsearch.

Your SOC has received a threat intelligence report indicating a **phishing campaign targeting educational institutions**, with suspected follow-on activity involving malicious infrastructure, malware execution, account abuse, and privilege misuse.

Instead of starting from alerts or user behavior, you begin with a set of **Indicators of Compromise (IOCs)** and use them to uncover attacker activity across multiple telemetry sources.

You analyze network, DNS, authentication, audit, workload, and cloud storage telemetry to:

* Enrich IOCs with contextual data
* Pivot across related entities (users, hosts, processes, IPs)
* Identify attacker behavior beyond exact IOC matches
* Reconstruct the attack timeline
* Build detection logic based on observed techniques

**Important:** Not all IOCs are guaranteed to be valid or relevant. Some may be outdated, incomplete, or benign. Part of your task is to validate their relevance.

You map your findings to MITRE ATT&CK techniques such as:

* T1566 – Phishing  
* T1071 – Application Layer Protocol  
* T1059 – Command and Scripting Interpreter  
* T1078 – Valid Accounts  
* T1098 – Account Manipulation  
* T1567.002 – Exfiltration to Cloud Storage  


## What you'll learn

In this lab, you learn how to:

* Enrich IOCs using multiple telemetry sources
* Validate the relevance of threat intelligence indicators
* Pivot from indicators to affected users, hosts, and processes
* Correlate activity across datasets
* Move from IOC matching to behavioral detection
* Reconstruct an attack timeline
* Build detection logic based on real attack patterns
* Produce a structured investigation report


## Prerequisites

Before you start, you should be familiar with:

* IOC types (IP, domain, URL, hash, email, OAuth client)
* MITRE ATT&CK framework
* Kibana Discover and basic KQL queries
* Threat hunting workflows and pivoting techniques


## Setup

**Before you click the Start Lab button**

Read these instructions carefully before starting the lab.

* **Labs are timed.**
* **You cannot pause the lab.**
* This is a **simulation environment** with temporary credentials.

To complete this lab, you need:

* A modern web browser (Chrome recommended)

<div><ql-infobox>
<strong>Note:</strong> Use an Incognito or private browser window.
</ql-infobox></div>

<div><ql-infobox>
<strong>Note:</strong> Allow <strong>5 minutes</strong> for environment initialization.
</ql-infobox></div>


## Scenario

Your SOC received a threat intelligence alert from an external provider indicating a potential compromise linked to a phishing campaign.

The campaign is known to:

* Deliver malware through phishing infrastructure
* Use suspicious external infrastructure for callback or staging activity
* Execute payloads on compromised hosts
* Abuse valid accounts and cloud privileges
* Stage or transfer data to external destinations

### Provided IOC Feed

You receive the following indicators:

* **Suspicious TOR exit node IP:** `171.25.193.35`
* **Suspicious TOR exit node IP:** `193.189.100.204`
* **Phishing URL:** `https://rh.cloud-drive.services/`
* **Phishing domain:** `rh.cloud-drive.services`
* **Known malicious SHA256 hash**: `87f4b996f0ca6b937577109cb4b74ea7c6bd32bea76f38d938153176af5174a5`

Some indicators may be:

* Outdated
* False positives
* Only partially related

Your goal is to:

* Validate IOCs
* Enrich them
* Pivot across datasets
* Identify attacker behavior
* Confirm or refute suspected compromise
* Build detections


## Task 1. Analyze the IOC feed and form hypotheses

In this task, you review the IOC feed and decide how to prioritize your investigation.

### Step 1: Categorize IOCs

Identify IOC types:

* IP
* Domain
* URL
* File hash
* Identity-based indicators

### Step 2: Assess IOC reliability

Ask yourself:

* Is this IOC likely high-confidence or low-confidence?
* Does the indicator suggest phishing, staging, callback, or post-compromise activity?
* What context is missing?

### Step 3: Form hypotheses

Think about:

* What stage of the attack each IOC might represent
* Which datasets are relevant
* Which indicators deserve immediate prioritization

**Expected result:**

You define investigation hypotheses and prioritize the most relevant indicators.


## Task 2. Enrich IP, domain, and URL indicators

In this task, you investigate suspicious infrastructure in network and DNS telemetry.

### Step 1: Search network activity

Data view: `network-flow-*`


  ```
destination.ip:("171.25.193.35" or "193.189.100.204") or destination.domain:"rh.cloud-drive.services"
  ```


Analyze:

* Source hosts
* Source users
* Frequency and timing patterns
* Relative data transfer patterns
* Whether the same host repeatedly connects to the suspicious infrastructure

### Step 2: Search DNS activity

Data view: `dns-logs-*`


  ```
dns.question.name:"*rh.cloud-drive.services"
  ```


Evaluate:

* Which hosts queried the domain
* Whether subdomains are involved
* Whether the activity is concentrated on one host or spread across many hosts
* Whether the timing lines up with network or process activity

### Step 3: Consider the phishing URL context

The IOC feed includes the phishing URL:

`https://rh.cloud-drive.services/`

Even if full URL visibility is not available in every dataset, consider how the following artifacts may still support the investigation:

* DNS resolution of the phishing domain
* Outbound network connections to the domain
* Suspicious process activity occurring shortly after domain contact
* Related authentication or audit activity for the same user or host

**Save your investigation step**

Save this query in Kibana using the **exact name**:

```
THL04-IOC-Network
```

Click **Save** and confirm that the saved query appears in your list of saved searches.

**Expected result:**

You identify the most suspicious host-user pair communicating with suspicious infrastructure and determine whether the TOR-linked IPs and phishing domain are relevant to the same activity chain.

Click **Check my progress** to verify the objective.

<ql-activity-tracking Step=1>
    Validate IOC Network Investigation
</ql-activity-tracking>


## Task 3. Enrich file hash indicators

### Step 1: Search workload telemetry

Data view: `workload-telemetry-*`


  ```
file.hash.sha256:"<MALICIOUS_HASH>" or process.hash.sha256:"<MALICIOUS_HASH>"
  ```


### Step 2: Analyze execution context

Review:

* host.name
* user.email
* process.name
* process.command_line
* process.parent.name
* @timestamp

Ask:

* Did execution occur on the same host seen contacting the phishing domain or suspicious IPs?
* Does the process name appear legitimate or deceptive?
* What happened immediately after execution?

### Step 3: Review nearby process activity

Use the affected host and user to search for related process launches.

Example pivot idea:


  ```
host.name:"<affected_host>" and user.email:"<affected_user>"
  ```


Look for suspicious tools such as:

* curl
* python
* wget
* zip

**Save your investigation step**

Save this query in Kibana using the **exact name**:

```
THL04-Hash-Execution
```

Click **Save** and confirm that the saved query appears in your list of saved searches.

**Expected result:**

You identify the compromised host, the affected user, and suspicious follow-on execution consistent with staging, download activity, or attacker tooling.

Click **Check my progress** to verify the objective.

<ql-activity-tracking Step=2>
    Validate Malicious Execution Detection
</ql-activity-tracking>


## Task 4. Pivot across entities

In this task, you expand from the initial IOC matches to broader related activity.

Pivot using:

* host.name
* user.email
* source.ip
* destination.ip
* destination.domain
* process.name

Look for:

* Additional suspicious connections from the affected host
* Authentication anomalies linked to the same user
* Related workload execution shortly before or after the IOC match
* Signs that the same user or host appears across multiple suspicious datasets

Ask yourself:

* Are multiple datasets telling the same story?
* Is there a shared user-host pair across network, auth, audit, and workload telemetry?
* Does the activity cluster around a narrow time window?

**Expected result:**

You correlate multiple telemetry sources and expand the scope of the attack beyond the original IOC lookup.


## Task 5. Reconstruct the attack timeline

In this task, you rebuild the sequence of the intrusion.

Build a timeline including:

* Contact with the phishing domain
* Connections to suspicious external IPs
* Malicious file execution
* Suspicious follow-on tooling
* Suspicious login activity
* Privilege changes
* Possible cloud storage upload or transfer

Order events chronologically and identify likely cause-and-effect relationships.

You should aim to answer questions such as:

* What happened first?
* Which activity appears to mark initial compromise?
* Which activity suggests post-compromise execution?
* Which activity suggests persistence or privilege abuse?
* Which activity suggests data staging or transfer?

**Expected result:**

You produce a clear attack chain timeline from suspicious infrastructure contact to possible exfiltration.


## Task 6. Expand to behavior-based hunting

In this task, you move beyond exact IOC matching and search for attacker behavior. 

### Step 1: Detect suspicious logins

Data view: auth-logs-*


  ```
event.action:"login" and event.outcome:"success" and
not geo.country_name:"United States" and
user.email:"<pivoted_user>"
  ```


### Step 2: Detect privilege escalation

Data view: audit-logs-*


  ```
event.action:("setIamPolicy" or "iam.policy.update") and actor.email:"<pivoted_user>"
  ```


Refine by reviewing high-risk role assignments or unusual account changes.

### Step 3: Detect C2-like activity

Data view: network-flow-*


  ```
destination.ip:("171.25.193.35" or "193.189.100.204") 
or destination.domain:"rh.cloud-drive.services" 
or destination.domain:*.rh.cloud-drive.services
  ```


Look for repeated outbound communications over time.

### Step 4: Detect suspicious process execution

Data view: workload-telemetry-*


  ```
host.name:"<pivoted_hostname>" 
and process.name:("python" or "curl" or "wget" or "bash") 
and event.type:"start"
  ```


Ask:

* Does this behavior align with normal activity for this user or host?
* Is it repeated or isolated?
* Does the timing correlate with other suspicious events?
* Does the process name, command line, or parent process suggest staging, download, or masquerading?

**Save your investigation step**

Save this query in Kibana using the **exact name**:

```
THL04-Behavioral-Hunt
```

Click **Save** and confirm that the saved query appears in your list of saved searches.

**Expected result:**

You identify behavioral attack patterns such as:

* Repeated contact with suspicious infrastructure
* Suspicious authentication behavior
* Privilege abuse
* Malicious or deceptive process execution
* Data staging activity

Click **Check my progress** to verify the objective.

<ql-activity-tracking Step=3>
    Validate Behavioral Hunting Detection
</ql-activity-tracking>


## Task 7. Investigate persistence and cloud abuse

In this task, you focus on persistence-like behavior, token usage, and possible cloud-side abuse.

### Step 1: Investigate token and session behavior

Data view: auth-logs-*


  ```
user.email:"<pivoted_user>" and 
event.action:"token_refresh"
  ```


Review:

* Source IP
* Country
* Device name
* Time relationship to suspicious login activity

### Step 2: Investigate suspicious IAM changes

Data view: audit-logs-* 


  ```
actor.email:"<pivoted_user>" and 
iam.change:"add"
  ```

    
Look for grants that could support persistence, privilege expansion, or access to storage and service accounts.

### Step 3: Investigate possible exfiltration

Data view: cloud-storage-* 


  ```
actor.email:"<pivoted_user>"
  ```
  
    
Review:

* Uploaded object names
* Bucket names
* Source IP
* Timing relative to process execution and privilege changes

**Save your investigation step**

Save this query in Kibana using the **exact name**:

```
THL04-Persistence-Cloud
```

Click **Save** and confirm that the saved query appears in your list of saved searches.

**Expected result:**

You identify suspicious token activity, cloud privilege abuse, and evidence consistent with possible data transfer or exfiltration.

Click **Check my progress** to verify the objective.

<ql-activity-tracking Step=4>
    Validate Persistence and Cloud Abuse
</ql-activity-tracking>


## Task 8. Build detection logic

In this task, you convert findings into detection rules.

Your detection logic should include:

* Data sources used
* Query
* Investigation context
* MITRE ATT&CK mapping
* False positive considerations
* Tuning recommendations

### Step 1: Define candidate detections

Examples:

* Repeated outbound traffic from one host to suspicious TOR-linked IPs
* Repeated DNS lookups for a phishing domain followed by suspicious process execution
* Foreign login followed by token refresh for the same user
* IAM role assignment followed by cloud storage activity
* Malicious hash execution followed by curl, python, wget, or zip

### Step 2: Reduce false positives

Consider:

* Shared infrastructure
* Benign use of command-line tools
* Administrative activity
* Backup, reporting, or automation accounts

### Step 3: Document detection logic

At minimum, capture:

* Query
* Why it is suspicious
* What context an analyst should review next
* How to tune it safely

**Expected result:**

You create at least one high-confidence behavioral detection rule and one medium-confidence correlation rule.


## Task 9. Report findings

In this final task, you summarize your investigation.

### Include:

* The original IOC feed
* Which indicators were validated
* Which indicators were deprioritized or required additional context
* The affected host and user
* Timeline reconstruction
* Behavioral detections
* MITRE ATT&CK mapping

### Provide recommendations:

* Block malicious infrastructure
* Reset or review affected credentials
* Revoke suspicious tokens or OAuth access
* Review recent IAM changes
* Investigate cloud storage transfers
* Improve monitoring and detection coverage

**Expected result:**

You produce a structured investigation report linking validated IOCs to attacker behavior and suspected impact.


## Congratulations

You performed an IOC-driven threat hunt using multiple telemetry sources.

You moved beyond simple IOC matching to uncover:

* Suspicious infrastructure contact
* Suspicious authentication activity
* Privilege abuse
* Possible cloud storage exfiltration
* Behavioral indicators suitable for detection engineering

These skills are critical for detecting attackers who rotate infrastructure, abuse trusted services, and blend with legitimate tools.


## Continue Your Learning Journey

To further develop your threat hunting skills:

* Practice building behavior-based detections
* Study attacker infrastructure patterns
* Explore advanced correlation across datasets
* Improve detection engineering workflows


## End Your Lab

1. Click **End Lab**
2. Click **Submit**
