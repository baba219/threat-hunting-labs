# Artifact Exploration and IAM Compromise

## Overview

In this lab, you investigate a stealthy IAM compromise using Kibana and Elasticsearch.

You analyze authentication events, audit activity, and service account artifacts. You correlate evidence across multiple data views to reconstruct the attacker's timeline. This scenario focuses on identity abuse without malware or noisy exploits.

You map your findings to these MITRE ATT&CK techniques:

- T1078 – Valid Accounts
- T1098 – Account Manipulation
- T1550.001 – Use of Authentication Tokens
- T1078.004 – Cloud Accounts

### **What you'll learn**

In this lab, you learn how to perform the following tasks:

- Identify IAM-relevant telemetry in Kibana.
- Investigate authentication anomalies using behavioral context.
- Validate suspicious IAM policy changes with supporting evidence.
- Correlate service account key activity to confirm identity pivoting.

### **Prerequisites**

Before you start, you should be familiar with:

- Cloud IAM concepts and audit logging
- The MITRE ATT&CK framework
- Kibana Query Language (KQL)
- Basic RBAC and service account authentication

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

<strong>Note:</strong> After clicking <strong>Start Lab</strong>, please allow <strong>5 minutes</strong> for the environment to fully initialize. During this time, the virtual machine, Elasticsearch, and Kibana services are starting and data is being ingested. If Kibana does not load immediately, wait a few minutes and refresh the page. The lab timer continues to run during initialization.
</ql-infobox></div>

**How to start your lab and access Kibana**

### Step 1: Launch the Lab Environment

1. Click **Start Lab** to launch your investigation environment.

On the left is the **Lab details** pane which is populated with the temporary credentials needed for this lab.

![IAM Attack Diagram](https://raw.githubusercontent.com/baba219/threat-hunting-labs/baba-structure-gps-thr/labs/thl001-iam-compromise/instructions/img/Screenshot%202026-03-03%20072948.png)

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

1. In the upper-left corner of Kibana, click the hamburger menu (☰), then select **Discover**.
2. In Discover, locate the blue **Data view** drop-down in the upper-left area of the page. It may currently display `auth-logs`.
3. Open the Data view selector and confirm that the following data views are available:
   - auth-logs
   - audit-logs
   - service-accounts
   - iam-activity

**Expected result:**

You successfully access Kibana and confirm that all required data views are available for the lab.

## Scenario

An attacker obtains valid credentials for a low-privilege cloud user. The attacker moves slowly to blend in with normal operations:

- Successful logins occur from multiple geographic locations.
- IAM policy changes happen in small steps and look operationally justified.
- A new service account key is created and later used for access.
- The service account is later used to access sensitive resources through legitimate API calls.

Your goal is to determine whether this activity is normal administration or a coordinated identity-based attack. You do this by reconstructing the timeline from log evidence.

![IAM Attack Diagram](https://raw.githubusercontent.com/baba219/threat-hunting-labs/baba-structure-gps-thr/labs/thl001-iam-compromise/instructions/img/92a4cb75d0cd0084.png)

## Task 1. Explore the Kibana environment

In this task, you confirm what telemetry is available and how the investigation is organized. You use this context to avoid jumping to conclusions based on a single data source.

**Open Kibana and review data views**

1. Log in to Kibana using the provided credentials.
2. In the upper-left corner of Kibana, click the hamburger menu (☰), then select **Discover**.
3. In Discover, locate the blue **Data view** drop-down in the upper-left area of the page. It may currently display `auth-logs`.
4. Open the Data view selector and confirm that the following data views are available:
   - auth-logs
   - audit-logs
   - service-accounts
   - iam-activity

**Expected result:**

You confirm which data views exist and how to pivot between them during an investigation.

## Task 2. Identify suspicious IAM policy updates

In this task, you find IAM policy changes that look valid but may be suspicious in context. You focus on elevated roles and timing relationships.

### Step 1: Review IAM Policy Modification Events

1. In **Discover**, open the blue **Data view** drop-down and select **audit-logs**.
2. Set the time range to **Last 7 days**.
3. In the query bar, paste the following query, and then press **Enter**.

```
event.action:"setIamPolicy" and iam.change:"add"
```

This query surfaces IAM role assignments where permissions were added.

### Step 2: Filter for High-Impact Roles

Now narrow to **high-impact roles**:

```
event.action:"setIamPolicy"
and iam.change:"add"
and iam.role:("roles/owner" or "roles/editor" or "roles/storage.admin")
```

These roles represent high-impact access capable of privilege escalation or data access.

### Step 3: Analyze Contextual Indicators

Identify suspicious candidates, and then note the following fields: `actor.email`, `@timestamp`, `iam.role`, `source.ip`, and `geo.country_name`.

Evaluate:

- Is the actor expected to modify IAM policies?
- Does the geographic location match normal behavior?
- Did this event occur shortly after an unusual login?

<div><ql-infobox>
<strong>Note:</strong> A single IAM policy update is not enough to prove malicious activity. You validate it using authentication and service account evidence in later tasks.
</ql-infobox></div>

**Save your investigation step**

1. Click **Save** in Kibana.
2. In the **Title** field, enter the following exact value:

```
THL01-IAM-Policy-Updates
```

3. Click **Save** to confirm.

**Important:** Enter the title exactly as shown, including capitalization and hyphens.

**Expected result:**

You identify IAM policy updates that require validation through correlation.

Click **Check my progress** to verify the objective.

<ql-activity-tracking step=1>
  Validate IAM Policy Modification Detection
</ql-activity-tracking>

## Task 3. Detect abnormal successful logins

In this task, you identify authentication anomalies that may indicate valid account abuse. You avoid treating every foreign login as malicious and focus on patterns.

### Step 1: Review Successful Authentication Events

1. In **Discover**, open the **Data view** drop-down and select **auth-logs**.
2. In the query bar, paste the following query, and then press **Enter**.

```
event.action:"user_login"
and event.outcome:"success"
and not geo.country_name:"Canada"
```

This query surfaces successful authentication events originating outside Canada within the selected time range.

### Step 2: Analyze Contextual Indicators

1. Review the results, and then identify accounts that exhibit multiple geographic locations within a short time frame or behavior that deviates from their normal access pattern.
2. Note the usernames and timestamps that you want to validate.

Evaluate:

- Does the account normally authenticate from this country?
- Are there multiple geographic locations within a short time window?
- Is there evidence of “impossible travel”?
- Did this login occur shortly before an IAM role modification?
- Does the source IP align with previous activity?

Focus on behavioral patterns and correlation rather than isolated events.

<div><ql-infobox>
<strong>Note:</strong> A foreign login alone does not confirm compromise. Correlate authentication anomalies with IAM policy updates and service account activity before drawing conclusions.
</ql-infobox></div>

**Save your investigation step**

1. Click **Save** in Kibana.
2. In the **Title** field, enter the following exact value:

```
THL01-Auth-Outside-Canada
```

3. Click **Save** to confirm.

**Important:** Enter the title exactly as shown, including capitalization and hyphens.

**Expected result:**

You identify candidate user accounts for deeper investigation and correlation.

Click **Check my progress** to verify the objective.

<ql-activity-tracking step=2>
  Validate Suspicious Authentication Activity Detection
</ql-activity-tracking>

## Task 4. Investigate service account key activity

In this task, you determine whether service account key operations support persistence or pivoting. You treat service account key creation as potentially suspicious when it aligns with other anomalies.

### Step 1: Review Service Account Key Creation Events

1. In **Discover**, open the **Data view** drop-down and select **service-accounts**.
2. In the query bar, paste the following query, and then press **Enter**.

```
event.action:"createServiceAccountKey"
```

### Step 2: Filter by Suspicious Actor

Now focus on suspicious actor:

```
event.action:"createServiceAccountKey"
and actor.email:"bob@corp.com"
```

This filter isolates key creation activity performed by a specific identity.

### Step 3: Analyze Contextual Indicators

Identify the service account and key ID involved, note the timestamp, and then correlate this activity with the suspicious authentication events from Task 3 and the IAM policy changes from Task 2.

Evaluate:

- Is this actor authorized to create service account keys?
- Does this event occur shortly after an unusual login?
- Does this follow an IAM privilege escalation event?
- Is the source IP consistent with prior behavior?
- Does the timing suggest preparation for persistence?

<div><ql-infobox>
<strong>Note:</strong> Service account keys can provide long-lived access. When key creation aligns with authentication anomalies or IAM modifications, it may indicate persistence or pivoting.
</ql-infobox></div>

**Save your investigation step**

1. Click **Save** in Kibana.
2. In the **Title** field, enter the following exact value:

```
THL01-Service-Account-Key
```

3. Click **Save** to confirm.

**Important:** Enter the title exactly as shown, including capitalization and hyphens.

**Expected result:**

You identify service account key activity that could enable persistence or pivoting.

Click **Check my progress** to verify the objective.

<ql-activity-tracking step=3>
  Validate Service Account Key Creation Detection
</ql-activity-tracking>

## Task 5. Trace compromised key usage across IAM activity

In this task, you validate whether a specific key is used to access sensitive resources. You focus on what the key does, not only that it exists.

### Step 1: Search for Key-Related Activity

1. In **Discover**, open the **Data view** drop-down and select **iam-activity**.
2. In the query bar, paste the following query, and then press **Enter**.

```
service.key_id:"key-99999"
```

### Step 2: Isolate High-Risk Operations

To focus on potentially sensitive behavior, refine the query:

```
service.key_id:"key-99999"
and event.action:("data_download" or "data_access" or "token_generate")
```

This filter highlights token usage and potential data access operations.

### Step 3: Analyze Key Usage Context

Review the following fields: event.action, resource.name, source.ip, geo.country_name, and @timestamp.

Evaluate:

- Is the key being used to generate authentication tokens?
- Are sensitive resources being accessed?
- Is there evidence of bulk data download?
- Does the geographic origin match previous activity?
- Does this activity follow service account key creation?

<div><ql-infobox>
<strong>Note:</strong> A compromised key is validated not only by its creation but by how it is used. Token generation and download behavior often indicate actions on objectives.
</ql-infobox></div>

**Save your investigation step**

1. Click **Save** in Kibana.
2. In the **Title** field, enter the following exact value:

```
THL01-Key-Usage
```

3. Click **Save** to confirm.

**Important:** Enter the title exactly as shown, including capitalization and hyphens.

**Expected result:**

You confirm whether service account activity supports attacker pivoting and resource access.

Click **Check my progress** to verify the objective.

<ql-activity-tracking step=4>
  Validate Compromised Key Usage Investigation
</ql-activity-tracking>

## Task 6. Reconstruct the attack timeline and document findings

In this task, you combine evidence into a defensible narrative. You build a timeline that explains the attacker's sequence of actions and why it is suspicious.

### Step 1: Identify Privilege Escalation

Review IAM role modifications identified in **Task 2**.

Evidence source: audit-logs

Focus on:

- event.action:"setIamPolicy"
- High-impact roles such as roles/owner
- Actor identity and timing correlation

Mapped technique:

- **T1098 – Account Manipulation**

### Step 2: Establish Initial Access

Review suspicious authentication events identified in **Task 3**.

Evidence source: auth-logs

Focus on:

- Geographic anomalies
- Short-window multi-country activity
- Impossible travel patterns

Mapped technique:

- **T1078 – Valid Accounts**

### Step 3: Confirm Persistence Mechanism

Review service account key creation events identified in **Task 4**.

Evidence source: service-accounts

Focus on:

- createServiceAccountKey
- Service account identity
- Key ID and timestamp

Mapped technique:

- **T1078.004 – Cloud Accounts**

### Step 4: Validate Actions on Objectives

Review key usage behavior identified in **Task 5**.

Evidence source: iam-activity

Focus on:

- token_generate
- data_access
- data_download

Mapped technique:

- **T1550.001 – Use of Authentication Tokens**

### Step 5: Build the Investigation Narrative

Construct a timeline including:

1. Suspicious login (Initial Access)
2. IAM role escalation (Privilege Escalation).
3. Service account key creation (Persistence)
4. Key-based resource access (Actions on Objectives)

Your narrative should explain:

- Why each step is suspicious
- How events correlate across data views
- Why the behavior represents coordinated identity abuse

**Expected result:**

You produce a structured attack timeline supported by log evidence and mapped to MITRE ATT&CK techniques.

## Congratulations

You investigated a stealthy IAM compromise using Kibana and Elasticsearch. You correlated identity events across authentication, audit logs, and service account activity to reconstruct an attack narrative.

These skills transfer to other cloud investigations where attackers avoid malware and use legitimate identity operations.

## Continue Your Learning Journey

This lab is part of the **Threat Hunting in Google Cloud for Public Sector** learning path.

Throughout this investigation, you analyzed identity telemetry, correlated IAM changes, and reconstructed a stealthy cloud compromise.

To deepen your expertise, continue exploring:

- Advanced cloud identity detection strategies
- Behavioral analytics using Elasticsearch and Kibana
- Multi-source log correlation techniques
- Detection engineering aligned to MITRE ATT&CK

Each lab in this series builds progressively toward real-world SOC-level cloud threat hunting capabilities.

## Take the Next Lab

Continue building your investigation skills in:

### Lab 2 – Beacon and Exfiltration Hunt

In the next lab, you will:

- Detect command-and-control beacon patterns
- Identify suspicious outbound traffic and data exfiltration behavior
- Correlate network activity with authentication telemetry
- Apply structured hunting methodology to validate suspicious signals

This lab introduces network-based persistence and covert data movement techniques.

## Next Steps / Learn More

To expand your knowledge beyond this lab:

- Review MITRE ATT&CK techniques related to cloud identity compromise and persistence.
- Practice writing advanced detection queries using Kibana Query Language (KQL).
- Study identity abuse patterns in cloud-native environments.
- Explore detection engineering principles used by mature SOC teams.

Continuous practice in structured hunting improves investigative confidence and reduces false positives in production environments.

## End Your Lab

Congratulations! You’ve completed **Artifact Exploration and IAM Compromise**.

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
**Lab Last Tested:** February 2026
