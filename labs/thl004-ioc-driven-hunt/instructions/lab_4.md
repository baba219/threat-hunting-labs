# IOC-Driven Hunt

## Overview

In this lab, you investigate a multi-stage adversary campaign using an **indicator-driven approach** in Kibana and Elasticsearch.

Your SOC has received a threat intelligence report indicating a **phishing campaign targeting educational institutions**, with suspected follow-on activity involving malicious infrastructure, malware execution, account abuse, and privilege misuse.

Instead of starting from alerts or user behavior, you begin with a set of **Indicators of Compromise (IOCs)** and use them to uncover attacker activity across multiple telemetry sources.

You analyze network, DNS, authentication, audit, workload, and cloud storage telemetry to:

- Enrich IOCs with contextual data
- Pivot across related entities (users, hosts, processes, IPs)
- Identify attacker behavior beyond exact IOC matches
- Reconstruct the attack timeline
- Build detection logic based on observed techniques

**Important:** Not all IOCs are guaranteed to be valid or relevant. Some may be outdated, incomplete, or benign. Part of your task is to validate their relevance.

You map your findings to MITRE ATT&CK techniques such as:

- T1566 – Phishing
- T1071 – Application Layer Protocol
- T1059 – Command and Scripting Interpreter
- T1078 – Valid Accounts
- T1098 – Account Manipulation
- T1567.002 – Exfiltration to Cloud Storage

## What you'll learn

In this lab, you learn how to:

- Enrich IOCs using multiple telemetry sources
- Validate the relevance of threat intelligence indicators
- Pivot from indicators to affected users, hosts, and processes
- Correlate activity across datasets
- Move from IOC matching to behavioral detection
- Reconstruct an attack timeline
- Build detection logic based on real attack patterns
- Produce a structured investigation report

## Prerequisites

Before you start, you should be familiar with:

- IOC types (IP, domain, URL, hash, email, OAuth client)
- MITRE ATT&CK framework
- Kibana Discover and basic KQL queries
- Threat hunting workflows and pivoting techniques

## Setup

**Before you click the Start Lab button**

Read these instructions carefully before starting the lab.

- **Labs are timed.** When you click **Start Lab**, the timer starts immediately and shows how long your lab environment will remain available.
- **You cannot pause the lab.** Once the lab has started, the time continues to run until the session ends.
- This is a **simulation environment**. You will receive **temporary credentials** to sign in to Kibana for the duration of the lab.

To complete this lab, you need:

- Access to a standard internet browser (Chrome browser recommended).

<div><ql-infobox>

<strong>Note:</strong> Use an Incognito or private browser window to run this lab. This prevents conflicts with any existing sessions that may affect access to the lab environment.
</ql-infobox></div>

<div><ql-infobox>

<strong>Note:</strong> After clicking <strong>Start Lab</strong>, please allow <strong>5 minutes</strong> for the environment to fully initialize. During this time, Elasticsearch, Kibana, and the simulated security telemetry are starting and data is being ingested. If Kibana does not load immediately, wait a few minutes and refresh the page. The lab timer continues to run during initialization.
</ql-infobox></div>

**How to start your lab and access Kibana**

### Step 1: Launch the Lab Environment

1. Click **Start Lab** to launch your investigation environment.

On the left is the **Lab details** pane which is populated with the temporary credentials needed for this lab.

![Workspace Attack Diagram](https://raw.githubusercontent.com/baba219/threat-hunting-labs/baba-structure-gps-thr/labs/thl004-ioc-driven-hunt/instructions/img/Screenshot%202026-03-03%20072948.png)

### Step 2: Access Kibana

1. Wait for the environment to initialize. Allow **5 minutes** for Kibana to become accessible.
2. In the left panel, copy the **Kibana URL** provided.
3. Paste the URL into your browser and press **Enter**.
4. If you see a message saying **"This site doesn't support a secure connection"**, click **Continue to site** to proceed.
5. In the left panel, copy the **Kibana Username** and **Kibana Password**.
6. Paste the credentials into the login page and click **Log in**.
7. Dismiss initial warnings inside Kibana.

<div><ql-infobox>

<strong>Tip:</strong> Keep the lab instructions and the Kibana page open in separate windows, side-by-side, to make investigation easier.
</ql-infobox></div>

**Verify access to the lab environment**

After signing in, confirm that you have access to the investigation environment.

1. In the upper-left corner of Kibana, click the hamburger menu (☰), then select **Discover**.
2. In Discover, locate the blue **Data view** drop-down in the upper-left area of the page. It may currently display `audit-logs`.
3. Open the Data view selector and confirm that the following data views are available:
   - network-flow
   - dns-logs
   - auth-logs
   - audit-logs
   - workload-telemetry
   - cloud-storage

**Expected result:**

You successfully access Kibana and confirm that all required data views are available for the lab.

## Scenario

Your SOC received a threat intelligence alert from an external provider indicating a potential compromise linked to a phishing campaign.

The campaign is known to:

- Deliver malware through phishing infrastructure
- Use suspicious external infrastructure for callback or staging activity
- Execute payloads on compromised hosts
- Abuse valid accounts and cloud privileges
- Stage or transfer data to external destinations

### Provided IOC Feed

You receive the following indicators:

- **Suspicious TOR exit node IP:** `171.25.193.35`
- **Suspicious TOR exit node IP:** `193.189.100.204`
- **Phishing URL:** `https://rh.cloud-drive.services/`
- **Phishing domain:** `rh.cloud-drive.services`
- **Known malicious SHA256 hash**: `87f4b996f0ca6b937577109cb4b74ea7c6bd32bea76f38d938153176af5174a5`

Some indicators may be:

- Outdated
- False positives
- Only partially related

Your goal is to:

- Validate IOCs
- Enrich them
- Pivot across datasets
- Identify attacker behavior
- Confirm or refute suspected compromise
- Build detections

![Workspace Attack Diagram](https://raw.githubusercontent.com/baba219/threat-hunting-labs/baba-structure-gps-thr/labs/thl004-ioc-driven-hunt/instructions/img/Screenshot%202026-04-26%20163051.png)

## Task 1. Analyze the IOC feed and form hypotheses

In this task, you review the IOC feed and decide how to prioritize your investigation.

### Step 1: Categorize IOCs

Identify IOC types:

- IP
- Domain
- URL
- File hash
- Identity-based indicators

### Step 2: Assess IOC reliability

Ask yourself:

- Is this IOC likely high-confidence or low-confidence?
- Does the indicator suggest phishing, staging, callback, or post-compromise activity?
- What context is missing?

### Step 3: Form hypotheses

Think about:

- What stage of the attack each IOC might represent
- Which datasets are relevant
- Which indicators deserve immediate prioritization

**Expected result:**

You define investigation hypotheses and prioritize the most relevant indicators.

## Task 2. Enrich IP, domain, and URL indicators

In this task, you investigate suspicious infrastructure in network and DNS telemetry.

### Step 1: Search network activity

1. In **Discover**, open the **Data view** drop-down and select **network-flow**.
2. In the query bar, paste the following query, and then press **Enter**.

```
destination.ip:("171.25.193.35" or "193.189.100.204") or destination.domain:"rh.cloud-drive.services"
```

Analyze:

- Source hosts
- Source users
- Frequency and timing patterns
- Relative data transfer patterns
- Whether the same host repeatedly connects to the suspicious infrastructure

### Step 2: Search DNS activity

1. In **Discover**, open the **Data view** drop-down and select **dns-logs**.
2. In the query bar, paste the following query, and then press **Enter**.

```
dns.question.name:"*rh.cloud-drive.services"
```

Evaluate:

- Which hosts queried the domain
- Whether subdomains are involved
- Whether the activity is concentrated on one host or spread across many hosts
- Whether the timing lines up with network or process activity

### Step 3: Consider the phishing URL context

The IOC feed includes the phishing URL:

`https://rh.cloud-drive.services/`

Even if full URL visibility is not available in every dataset, consider how the following artifacts may still support the investigation:

- DNS resolution of the phishing domain
- Outbound network connections to the domain
- Suspicious process activity occurring shortly after domain contact
- Related authentication or audit activity for the same user or host

**Save your investigation step**

1. Click **Save** in Kibana.
2. In the **Title** field, enter the following exact value:

```
THL04-IOC-Network
```

3. Click **Save** to confirm.

**Important:** Enter the title exactly as shown, including capitalization and hyphens.

**Expected result:**

You identify the most suspicious host-user pair communicating with suspicious infrastructure and determine whether the TOR-linked IPs and phishing domain are relevant to the same activity chain.

Click **Check my progress** to verify the objective.

<ql-activity-tracking Step=1>
    Validate IOC Network Investigation
</ql-activity-tracking>

## Task 3. Enrich file hash indicators

### Step 1: Search workload telemetry

1. In **Discover**, open the **Data view** drop-down and select **workload-telemetry**.
2. In the query bar, paste the following query, and then press **Enter**.

```
file.hash.sha256:"87f4b996f0ca6b937577109cb4b74ea7c6bd32bea76f38d938153176af5174a5"
or process.hash.sha256:"87f4b996f0ca6b937577109cb4b74ea7c6bd32bea76f38d938153176af5174a5"
```

### Step 2: Analyze execution context

Review:

- host.name
- user.email
- process.name
- process.command_line
- process.parent.name
- @timestamp

Ask:

- Did execution occur on the same host seen contacting the phishing domain or suspicious IPs?
- Does the process name appear legitimate or deceptive?
- What happened immediately after execution?

### Step 3: Review nearby process activity

Use the affected host and user to search for related process launches.

Example pivot idea:

```
host.name:"<affected_host>" and user.email:"<affected_user>"
```

Replace `<affected_host>` and `<affected_user>` with the values identified in the previous step.

Look for suspicious tools such as:

- curl
- python
- wget
- zip

**Save your investigation step**

1. Click **Save** in Kibana.
2. In the **Title** field, enter the following exact value:

```
THL04-Hash-Execution
```

3. Click **Save** to confirm.

**Important:** Enter the title exactly as shown, including capitalization and hyphens.

**Expected result:**

You identify the compromised host, the affected user, and suspicious follow-on execution consistent with staging, download activity, or attacker tooling.

Click **Check my progress** to verify the objective.

<ql-activity-tracking Step=2>
    Validate Malicious Execution Detection
</ql-activity-tracking>

## Task 4. Pivot across entities

In this task, you expand from the initial IOC matches to broader related activity.

Pivot using:

- host.name
- user.email
- source.ip
- destination.ip
- destination.domain
- process.name

Look for:

- Additional suspicious connections from the affected host
- Authentication anomalies linked to the same user
- Related workload execution shortly before or after the IOC match
- Signs that the same user or host appears across multiple suspicious datasets

Ask yourself:

- Are multiple datasets telling the same story?
- Is there a shared user-host pair across network, auth, audit, and workload telemetry?
- Does the activity cluster around a narrow time window?

**Expected result:**

You correlate multiple telemetry sources and expand the scope of the attack beyond the original IOC lookup.

## Task 5. Reconstruct the attack timeline

Use the timestamps and entities identified in the previous tasks to correlate activity across the relevant data views.

Focus on the affected host, user, suspicious IP addresses, phishing domain, and malicious file hash.

Build a timeline including:

- Contact with the phishing domain
- Connections to suspicious external IPs
- Malicious file execution
- Suspicious follow-on tooling
- Suspicious login activity
- Privilege changes
- Possible cloud storage upload or transfer

Order events chronologically and identify likely cause-and-effect relationships.

You should aim to answer questions such as:

- What happened first?
- Which activity appears to mark initial compromise?
- Which activity suggests post-compromise execution?
- Which activity suggests persistence or privilege abuse?
- Which activity suggests data staging or transfer?

**Expected result:**

You produce a clear attack chain timeline from suspicious infrastructure contact to possible exfiltration.

## Task 6. Expand to behavior-based hunting

In this task, you move beyond exact IOC matching and search for attacker behavior.

### Step 1: Detect suspicious logins

1. In **Discover**, open the **Data view** drop-down and select **auth-logs**.
2. In the query bar, paste the following query, replace `<pivoted_user>` with the user identified during your earlier investigation, and then press **Enter**.

```
event.action:"login" and event.outcome:"success" and
not geo.country_name:"United States" and
user.email:"<pivoted_user>"
```

### Step 2: Detect privilege escalation

1. In **Discover**, open the **Data view** drop-down and select **audit-logs**.
2. In the query bar, paste the following query, and then press **Enter**.

```
event.action:("setIamPolicy" or "iam.policy.update") and actor.email:"<pivoted_user>"
```

Refine by reviewing high-risk role assignments or unusual account changes.

### Step 3: Detect C2-like activity

1. In **Discover**, open the **Data view** drop-down and select **network-flow**.
2. In the query bar, paste the following query, and then press **Enter**.

```
destination.ip:("171.25.193.35" or "193.189.100.204")
or destination.domain:"rh.cloud-drive.services"
or destination.domain:*.rh.cloud-drive.services
```

Look for repeated outbound communications over time.

### Step 4: Detect suspicious process execution

1. In **Discover**, open the **Data view** drop-down and select **workload-telemetry**.
2. In the query bar, paste the following query, replace `<pivoted_hostname>` with the host identified during your earlier investigation, and then press **Enter**.

```
host.name:"<pivoted_hostname>"
and process.name:("python" or "curl" or "wget" or "bash")
and event.type:"start"
```

Ask:

- Does this behavior align with normal activity for this user or host?
- Is it repeated or isolated?
- Does the timing correlate with other suspicious events?
- Does the process name, command line, or parent process suggest staging, download, or masquerading?

**Save your investigation step**

1. Click **Save** in Kibana.
2. In the **Title** field, enter the following exact value:

```
THL04-Behavioral-Hunt
```

3. Click **Save** to confirm.

**Important:** Enter the title exactly as shown, including capitalization and hyphens.

**Expected result:**

You identify behavioral attack patterns such as:

- Repeated contact with suspicious infrastructure
- Suspicious authentication behavior
- Privilege abuse
- Malicious or deceptive process execution
- Data staging activity

Click **Check my progress** to verify the objective.

<ql-activity-tracking Step=3>
    Validate Behavioral Hunting Detection
</ql-activity-tracking>

## Task 7. Investigate persistence and cloud abuse

In this task, you focus on persistence-like behavior, token usage, and possible cloud-side abuse.

### Step 1: Investigate token and session behavior

1. In **Discover**, open the **Data view** drop-down and select **auth-logs**.
2. In the query bar, paste the following query, replace `<pivoted_user>` with the user identified during your earlier investigation, and then press **Enter**.

```
user.email:"<pivoted_user>" and
event.action:"token_refresh"
```

Review:

- Source IP
- Country
- Device name
- Time relationship to suspicious login activity

### Step 2: Investigate suspicious IAM changes

1. In **Discover**, open the **Data view** drop-down and select **audit-logs**.
2. In the query bar, paste the following query, replace `<pivoted_user>` with the user identified during your earlier investigation, and then press **Enter**.

```
actor.email:"<pivoted_user>" and
iam.change:"add"
```

Look for grants that could support persistence, privilege expansion, or access to storage and service accounts.

### Step 3: Investigate possible exfiltration

1. In **Discover**, open the **Data view** drop-down and select **cloud-storage**.
2. In the query bar, paste the following query, replace `<pivoted_user>` with the user identified during your earlier investigation, and then press **Enter**.

```
actor.email:"<pivoted_user>"
```

Review:

- Uploaded object names
- Bucket names
- Source IP
- Timing relative to process execution and privilege changes

**Save your investigation step**

1. Click **Save** in Kibana.
2. In the **Title** field, enter the following exact value:

```
THL04-Persistence-Cloud
```

3. Click **Save** to confirm.

**Important:** Enter the title exactly as shown, including capitalization and hyphens.

**Expected result:**

You identify suspicious token activity, cloud privilege abuse, and evidence consistent with possible data transfer or exfiltration.

Click **Check my progress** to verify the objective.

<ql-activity-tracking Step=4>
    Validate Persistence and Cloud Abuse
</ql-activity-tracking>

## Task 8. Build detection logic

In this task, you convert findings into detection rules.

Your detection logic should include:

- Data sources used
- Query
- Investigation context
- MITRE ATT&CK mapping
- False positive considerations
- Tuning recommendations

### Step 1: Define candidate detections

Examples:

- Repeated outbound traffic from one host to suspicious TOR-linked IPs
- Repeated DNS lookups for a phishing domain followed by suspicious process execution
- Foreign login followed by token refresh for the same user
- IAM role assignment followed by cloud storage activity
- Malicious hash execution followed by curl, python, wget, or zip

### Step 2: Reduce false positives

Consider:

- Shared infrastructure
- Benign use of command-line tools
- Administrative activity
- Backup, reporting, or automation accounts

### Step 3: Document detection logic

At minimum, capture:

- Query
- Why it is suspicious
- What context an analyst should review next
- How to tune it safely

**Expected result:**

You create at least one high-confidence behavioral detection rule and one medium-confidence correlation rule.

## Task 9. Report findings

In this final task, you summarize your investigation.

### Include:

- The original IOC feed
- Which indicators were validated
- Which indicators were deprioritized or required additional context
- The affected host and user
- Timeline reconstruction
- Behavioral detections
- MITRE ATT&CK mapping

### Provide recommendations:

- Block malicious infrastructure
- Reset or review affected credentials
- Revoke suspicious tokens or OAuth access
- Review recent IAM changes
- Investigate cloud storage transfers
- Improve monitoring and detection coverage

**Expected result:**

You produce a structured investigation report linking validated IOCs to attacker behavior and suspected impact.

## Congratulations

You performed an IOC-driven threat hunt using multiple telemetry sources.

You moved beyond simple IOC matching to uncover:

- Suspicious infrastructure contact
- Suspicious authentication activity
- Privilege abuse
- Possible cloud storage exfiltration
- Behavioral indicators suitable for detection engineering

These skills are critical for detecting attackers who rotate infrastructure, abuse trusted services, and blend with legitimate tools.

## Continue Your Learning Journey

To further develop your threat hunting skills:

- Practice building behavior-based detections
- Study attacker infrastructure patterns
- Explore advanced correlation across datasets
- Improve detection engineering workflows

## End Your Lab

Congratulations! You’ve completed **IOC-Driven Hunt**.

Now that you’re finished:

1. Click the **End Lab** button.
2. Click **Submit** to close your session.

Please take a moment to rate the lab. Your feedback helps improve future training content and detection-focused exercises.

### Rating Scale

- ⭐ 1 star = Very dissatisfied
- ⭐⭐ 2 stars = Dissatisfied
- ⭐⭐⭐ 3 stars = Neutral
- ⭐⭐⭐⭐ 4 stars = Satisfied
- ⭐⭐⭐⭐⭐ 5 stars = Very satisfied

Ending the lab removes access to the investigation environment and associated resources.

If you return to the environment after ending the lab, you will be automatically signed out.

**Manual Last Updated:** August 2026
**Lab Last Tested:** March 2026
