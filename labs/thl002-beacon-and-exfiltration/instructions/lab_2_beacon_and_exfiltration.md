# Beacon and Exfiltration Hunt


## Overview



In this lab, you investigate covert Command-and-Control (C2) beaconing and data exfiltration using Kibana and Elasticsearch.

You analyze network flow logs, DNS telemetry, workload process activity, and cloud storage audit events. You correlate activity across multiple data views to reconstruct the attacker’s operational timeline. This scenario focuses on low-noise network persistence and stealthy data movement techniques.

You map your findings to these MITRE ATT&CK techniques:

* T1071 – Application Layer Protocol
* T1095 – Non-Application Layer Protocol
* T1567.002 – Exfiltration to Cloud Storage
* T1041 – Exfiltration Over C2 Channel

### **What you'll learn**

In this lab, you learn how to:

* Detect periodic beaconing behavior in network telemetry.
* Distinguish benign outbound traffic from low-volume C2 activity.
* Correlate DNS, network, and workload telemetry.
* Identify data staging behaviors (archive creation, tool usage).
* Confirm data exfiltration using cloud storage audit logs.
* Build a structured attack timeline aligned to MITRE ATT&CK.

### **Prerequisites**

Before you start, you should be familiar with:

* Networking fundamentals and DNS behavior
* Beaconing concepts (periodicity, jitter, low-volume patterns)
* Kibana Query Language (KQL)
* Elasticsearch Discover and Lens visualizations
* Basic cloud storage audit logging concepts


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

<strong>Note:</strong> After clicking <strong>Start Lab</strong>, please allow <strong>5 minutes</strong> for the environment to fully initialize. During this time, the virtual machine, Elasticsearch, and Kibana services are starting and data is being ingested. If Kibana does not load immediately, wait a few minutes and refresh the page. The lab timer continues to run during initialization.
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

* network-flow
* dns-logs
* workload-telemetry
* cloud-storage-audit

**Expected result:**

You successfully access Kibana and confirm that all required data views are available for the lab.


## Scenario



A compromised VM or container inside the cloud environment is communicating with an external C2 domain.
The attacker:

* Beacons to an external domain at regular intervals
* Downloads tools and prepares data for exfiltration
* Compresses internal files into an archive
* Uploads the archive to external cloud storage
* Attempts to blend in with legitimate outbound traffic

Your goal is to detect the beaconing pattern, pivot into DNS and host telemetry, identify data staging activity, and confirm exfiltration.

![IAM Attack Diagram](https://raw.githubusercontent.com/baba219/threat-hunting-labs/baba-structure-gps-thr/labs/thl002-beacon-and-exfiltration/instructions/img/Screenshot%202026-03-14%20160831.png)


## Task 1. Identify suspicious outbound network behavior



In this task, you begin investigating network telemetry to identify potential Command-and-Control (C2) beaconing activity.
Attackers often maintain persistence by establishing low-volume outbound connections from compromised systems to an external command server. These connections typically appear as small, repeated network flows over time.

Your goal is to identify external hosts that receive repeated low-volume outbound traffic.

### Step 1: Review Outbound Network Flows

1.	In the navigation menu, click **Discover**.
2.	For **Data view**, select **network-flow**.
3.	Set time range: **Last 7 days**
4.	In the query bar, paste the following query, and then press **ENTER**.

    ```
    network.direction:"outbound" and bytes_out < 5000
    ```

This query filters for small outbound data transfers, which can sometimes represent beaconing activity from compromised systems communicating with a command server.

### Step 2: Analyze Contextual Indicators

Review:

* destination.ip
* destination.domain
* bytes_out
* @timestamp

Look for patterns that may indicate suspicious behavior.

Evaluate:


* Are the same external IPs contacted repeatedly?
* Are the flow sizes consistent?
* Does the traffic appear low-volume and periodic?

**Save your investigation step**

Save this query in Kibana using the **exact name**:

```
THL02-Beacon-Detection
```

Click **Save** and confirm that the saved query appears in your list of saved searches.

**Expected result:**

You identify one or more external hosts receiving repeated low-volume outbound traffic.

Click **Check my progress** to verify the objective.

<ql-activity-tracking Step=1> 
    Validate Suspicious Beacon Detection 
</ql-activity-tracking> 


## Task 2. Validate periodic beaconing behavior



In this task, you analyze network traffic patterns to determine whether the outbound flows identified in the previous task exhibit **periodic beaconing behavior**.

Command-and-control (C2) malware typically communicates with its control server using regular, low-volume network requests, often referred to as beacons. These connections frequently occur at predictable intervals and may persist for long periods of time.

You will use **Kibana Lens** to visualize outbound traffic and determine whether the communication pattern is consistent with C2 beaconing.

### Step 1: Visualize outbound traffic

1.	In the navigation menu, click **Visualize Library**.
2.	Click **Create visualization**.
3.	Select **Lens**.
4.	Configure the visualization as follows:

* **Horizontal axis:** @timestamp
* **Vertical axis:** Count
* **Break down by:** destination.ip.keyword
* Click **Breakdown**,Set **Number of values:** 14

Look for:

* Evenly spaced spikes
* Consistent flow sizes
* Predictable heartbeat intervals

### Step 2: Look for beaconing patterns

Examine the visualization and look for:

* Repeated connections to the **same external IP**
* **Evenly spaced spikes** in traffic
* **Low-volume traffic** occurring regularly
* Activity that persists for **multiple hours**

These patterns may indicate **C2 beaconing**.

### Step 3: Evaluate the communication pattern

Consider the following questions:

* Does one **destination IP** appear repeatedly?
* Do connections occur at **regular intervals**?
* Does the communication continue for **several hours**?

Regular outbound communication to the same host is a strong indicator of **command-and-control activity**.

<div><ql-infobox> 
<strong>Note:</strong> True beaconing often shows predictable intervals with minimal data transfer. 
</ql-infobox></div> 

**Expected result:**

You identify a steady heartbeat pattern consistent with C2 beaconing.


## Task 3. Pivot to DNS telemetry


In this task, you pivot from the suspicious outbound traffic to **DNS telemetry** to investigate whether a suspicious domain is being resolved by internal systems.

Beaconing malware often performs **repeated DNS lookups** to locate its command-and-control (C2) infrastructure.

### Step 1: Investigate DNS Queries

1.	In the navigation menu, click **Discover**.
2.	Select Data view: **dns-logs**.
3.	In the query bar, paste the following query, and then press **ENTER**.

```
dns.question.name:"*.c2-example.com"
```

This query searches for DNS requests related to the suspicious C2 domain.

### Step 2: Analyze DNS activity

Review:

* dns.question.name
* source.ip
* @timestamp

Look for patterns that may indicate suspicious activity.

Evaluate the following:

* Are there **many DNS queries** for this domain?
* Do you see **multiple subdomains** being queried?
* Do the DNS queries occur **around the same time as the beaconing activity**?

Repeated DNS lookups to a suspicious domain may indicate **active command-and-control communication**.

**Save your investigation step**

Save this query in Kibana using the **exact name**:

```
THL02-DNS-telemetry
```

Click **Save** and confirm that the saved query appears in your list of saved searches.

**Expected result:**

DNS logs confirm repeated resolution of a suspicious C2 domain.

Click **Check my progress** to verify the objective.

<ql-activity-tracking Step=2>
 Validate DNS Correlation 
</ql-activity-tracking> 


## Task 4. Investigate workload telemetry and data staging



In this task, you investigate **workload telemetry** to identify suspicious activity on the compromised system.

Attackers often prepare data for exfiltration by **downloading tools, executing scripts, or compressing files into archives** before transferring the data outside the environment.

### Step 1: Review Process Activity

1.	In the navigation menu, click **Discover**.
2.	Select Data view: **workload-telemetry**.
3.	In the query bar, paste the following query, and then press **ENTER**.

```
process.name:("curl" or "wget" or "python" or "tar" or "zip")
```

This query helps identify processes commonly used for **tool download, scripting, and archive creation**.

### Step 2: Analyze host activity

Review the following fields:

* process.name
* process.command_line
* file.name
* @timestamp
* device.name

Look for suspicious behavior such as:

* **Tool downloads** using curl or wget
* **Script execution** using python
* **Archive creation** using zip or tar

### Step 3: Correlate with previous findings

Evaluate the following:

* Is an **archive file created** on the system?
* Does the activity occur **around the same time as the beaconing activity**?
* Does the archive creation occur **shortly before a large outbound transfer**?

These behaviors may indicate **data staging prior to exfiltration**.

**Save your investigation step**

Save this query in Kibana using the **exact name**:

```
THL02-Workload-Telemetry
```

Click **Save** and confirm that the saved query appears in your list of saved searches.

**Expected result:**

You identify archive creation and staging activity on the compromised workload.

Click **Check my progress** to verify the objective.

<ql-activity-tracking Step=3>
 Validate Data Staging Detection 
</ql-activity-tracking> 


## Task 5. Detect large outbound transfers



In this task, you search for **large outbound data transfers** that may indicate data exfiltration.

After staging data on a compromised system, attackers often transfer large volumes of data to external infrastructure.

### Step 1: Search for High-Volume Outbound Traffic

1. In the navigation menu, click **Discover**.
2. Select Data view: **network-flow**.
3. In the query bar, paste the following query, and then press **ENTER**.

```
bytes_out > 5000000
```

This query filters for **large outbound network transfers**, which may represent data exfiltration.

### Step 2: Correlate with Staging

Review the following fields:

* destination.ip
* bytes_out
* @timestamp

Look for evidence of suspicious activity.

Evaluate the following:

* Does the transfer occur **shortly after archive creation** identified in the previous task?
* Is the **destination external** to the environment?
* Does the timing align with the **beaconing infrastructure** observed earlier?

A large outbound transfer occurring shortly after data staging may indicate **data exfiltration**.

**Save your investigation step**

Save this query in Kibana using the **exact name**:

```
THL02-Outbound-Transfers
```

Click **Save** and confirm that the saved query appears in your list of saved searches.

**Expected result:**

You identify a large outbound transfer consistent with data exfiltration.

Click **Check my progress** to verify the objective.

<ql-activity-tracking Step=4>
 Validate Large Outbound Transfer Detection
</ql-activity-tracking> 


## Task 6. Confirm exfiltration via cloud storage audit logs


In this task, you validate the data exfiltration using **cloud storage audit telemetry**.

Attackers often upload stolen data to external cloud storage services after staging and transferring the files from the compromised system.

### Step 1: Review cloud storage events

1.	In the navigation menu, click **Discover**.
2.	Select Data view: **cloud-storage-audit**.
3.	In the query bar, paste the following query, and then press **ENTER**.

```
event.action:"storage.objects.insert"
```

This query searches for **object upload events** to cloud storage.

### Step 2: Correlate Findings

Review:

* object.name
* actor.email
* @timestamp

Look for evidence of suspicious uploads.

Evaluate the following:

* Does the uploaded object **match the archive filename** identified earlier?
* Does the upload occur **after the staging and outbound transfer**?
* Is the **actor account associated with the compromised workload**?

An archive upload to cloud storage shortly after staging and large outbound transfers strongly indicates **successful data exfiltration**.

**Save your investigation step**

Save this query in Kibana using the **exact name**:

```
THL02-Exfiltration-Cloud-Storage
```

Click **Save** and confirm that the saved query appears in your list of saved searches.

**Expected result:**

You confirm data exfiltration through cloud storage upload.

Click **Check my progress** to verify the objective.

<ql-activity-tracking Step=5>
 Validate Cloud Storage Exfiltration
</ql-activity-tracking> 


## Task 7. Reconstruct the attack timeline



In this final task, you reconstruct the **complete attack timeline** using the evidence collected throughout the investigation.

Combine findings from the different data sources to understand how the attack unfolded.

### Step 1: Correlate events across telemetry sources

Use the following data views to reconstruct the attack sequence:

1. **Beaconing activity** — network-flow
2. **DNS resolution** — dns-logs
3. **Tool execution and archive creation** — workload-telemetry
4. **Large outbound transfer** — network-flow
5. **Cloud storage upload** — cloud-storage-audit

### Step 2: Build the attack timeline

Identify the order in which the attacker’s actions occurred.

Your timeline should include events such as:

* Initial **beaconing communication** with the external host
* Repeated **DNS queries** to the C2 domain
* **Tool execution** and **archive creation** on the compromised system
* A **large outbound data transfer**
* The **upload of the archive** to external cloud storage

### Step 3: Map findings to MITRE ATT&CK

Map the observed behavior to the following techniques:

* **T1071 – Application Layer Protocol**
* **T1095 – Non-Application Layer Protocol**
* **T1041 – Exfiltration Over C2 Channel**
* **T1567.002 – Exfiltration to Cloud Storage**

### Step 4: Explain the attack narrative

Write a short explanation describing:

* Why the **beaconing activity is suspicious**
* How **host staging activity aligns with network events**
* How the **data exfiltration was confirmed**
* Why this behavior represents a **coordinated attacker workflow**

**Expected result:**

You produce a **structured, chronological reconstruction of the attack**, demonstrating how multiple telemetry sources reveal the full attack path.


## Congratulations



You investigated covert beaconing and data exfiltration using Kibana and Elasticsearch. You correlated network, DNS, workload, and audit telemetry to reconstruct a complete attack path.
These skills are critical for detecting stealthy cloud-native threats where attackers avoid malware and use legitimate protocols for persistence and exfiltration.



## Continue Your Learning Journey

This lab deepened your investigation skills by detecting covert beaconing and confirming data exfiltration through multi-source correlation.

You learned how to:

- Identify low-volume C2 beaconing patterns
- Correlate DNS, network flow, and workload telemetry
- Detect archive creation and staging behavior
- Confirm exfiltration through cloud storage audit logs
- Build a structured MITRE ATT&CK-aligned timeline

To continue strengthening your cloud threat hunting expertise, explore:

- Behavioral detection of long-term C2 infrastructure
- Detection of DNS tunneling and encrypted beaconing
- Advanced exfiltration detection using entropy and traffic modeling
- Cross-layer correlation between identity, network, and workload telemetry
- Detection engineering practices for low-noise adversaries

Each lab in this series progressively builds real-world SOC capabilities required for mature cloud-native environments.


## Take the Next Lab

Continue building your investigation skills in:

### Lab 3 – Workspace Exfiltration

In this next lab, you shift focus from infrastructure-level compromise to SaaS application abuse and insider-style exfiltration.

Attackers increasingly target collaboration platforms rather than infrastructure.

Instead of beaconing or privilege escalation, they:

- Abuse legitimate OAuth applications
- Overshare sensitive documents
- Generate public sharing links
- Perform bulk downloads
- Create hidden persistence via delegated access

You will investigate suspicious activity across Workspace-style telemetry (Drive, OAuth, sharing, download behavior) and determine whether the activity represents legitimate collaboration or data theft.


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


**Manual Last Updated:** March 2026  
**Lab Last Tested:** March 2026  