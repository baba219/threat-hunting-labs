# Workspace Exfiltration


## Overview



In this lab, you investigate phishing-driven account compromise and data exfiltration in a cloud productivity environment using Kibana and Elasticsearch.

You analyze email delivery logs, OAuth telemetry, sign-in activity, mailbox rule changes, cloud storage file access, and admin audit events. You correlate activity across multiple data views to reconstruct the attacker’s operational timeline. This scenario focuses on identity-based compromise and SaaS abuse, where attackers rely on legitimate collaboration features rather than malware to steal data.

You map your findings to these MITRE ATT&CK techniques:

* T1566 – Phishing
* T1078 – Valid Accounts
* T1550 – Use of Authentication Tokens
* T1114.003 – Email Collection: Email Forwarding Rule
* T1537 – Transfer Data to Cloud Account
* T1567 – Exfiltration Over Web Service

### **What you'll learn**

In this lab, you learn how to:

* Detect phishing delivery using email telemetry.
* Confirm suspicious user interaction through sign-in and OAuth events.
* Identify malicious mailbox rules or forwarding settings used for persistence.
* Correlate SaaS file access, download, and sharing activity.
* Confirm data exfiltration to an external principal or cloud destination.
* Build a structured attack timeline aligned to MITRE ATT&CK.

### **Prerequisites**

Before you start, you should be familiar with:

* SaaS environments and productivity platform activity
* Phishing concepts and common email-based attack patterns
* OAuth consent and token abuse concepts
* Kibana Query Language (KQL)
* Elasticsearch Discover and Lens visualizations


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

![Workspace Attack Diagram](https://raw.githubusercontent.com/baba219/threat-hunting-labs/baba-structure-gps-thr/labs/thl003-workspace-exfiltration/instructions/img/Screenshot%202026-03-03%20072948.png)

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

* email-logs
* oauth-events
* mailbox-rules
* drive-activity
* admin-audit

**Expected result:**

You successfully access Kibana and confirm that all required data views are available for the lab.


## Scenario



A user in a cloud productivity environment receives a phishing email containing a malicious link.  
The attacker:

* Delivers a phishing email to the victim mailbox
* Gains access through credentials or OAuth consent
* Creates a mailbox rule or forwarding configuration
* Searches for and accesses sensitive files in cloud storage
* Downloads or shares files to an external account
* Attempts to blend in with legitimate collaboration activity

Your goal is to detect the phishing activity, pivot into identity and mailbox telemetry, identify suspicious file access and sharing, and confirm exfiltration.

![Workspace Attack Diagram](https://raw.githubusercontent.com/baba219/threat-hunting-labs/baba-structure-gps-thr/labs/thl003-workspace-exfiltration/instructions/img/Screenshot%202026-03-27%20145600.png)


## Task 1. Identify suspicious email activity



In this task, you begin investigating email telemetry to identify potential phishing delivery.  
Attackers often initiate SaaS compromises by sending emails that appear legitimate but contain malicious links, fake login pages, or consent prompts.

Your goal is to identify suspicious emails delivered to internal users.

### Step 1: Review Email Deliveries

1. In the navigation menu, click **Discover**.
2. For **Data view**, select **email-logs**.
3. Set time range: **Last 7 days**
4. In the query bar, paste the following query, and then press **ENTER**.

    ```
    event.type:"email_delivery" and message.subject:*invoice*
    ```

This query filters for email deliveries containing invoice-related subjects, a common phishing lure used to trigger urgency and user interaction.

### Step 2: Analyze Contextual Indicators

Review:

* sender.email
* recipient.email
* message.subject
* message.id
* @timestamp

Look for patterns that may indicate suspicious behavior.

Evaluate:

* Is the sender **external** or unusual?
* Does the email subject suggest **urgency**, payment, or account action?
* Is the message delivered to a **high-value** or targeted user?

**Save your investigation step**

Save this query in Kibana using the **exact name**:

```
THL03-Phishing-Email
```

Click **Save** and confirm that the saved query appears in your list of saved searches.

**Expected result:**

You identify a suspicious phishing email delivered to the victim user.

Click **Check my progress** to verify the objective.

<ql-activity-tracking Step=1>
    Validate Suspicious Email Detection
</ql-activity-tracking>


## Task 2. Confirm suspicious user interaction



In this task, you analyze sign-in and OAuth activity to determine whether the user interacted with the phishing email and whether the attacker gained access.

Attackers may steal credentials through a fake login page or trick the user into granting access to a malicious OAuth application. Either method can provide access to the victim account without deploying malware.

You will investigate suspicious sign-in and OAuth consent activity across two telemetry sources.

### Step 1: Investigate Suspicious Sign-In Activity

1. In the navigation menu, click **Discover**.
2. Select Data view: **admin-audit**.
3. In the query bar, paste the following query, and then press **ENTER**.

    ```
    event.action:"signin"
    ```

This query searches for sign-in activity that may indicate account compromise.

Review:

* user.email
* source.ip
* geo.country_name
* @timestamp

Evaluate the following:

* Does the sign-in occur **shortly after** the phishing email delivery?
* Is the sign-in associated with a **location outside the user’s normal geography**?
* Do most benign sign-ins in the environment originate from the **United States**, while this event originates elsewhere?
* Does the timing align with the beginning of the suspicious activity chain?

### Step 2: Investigate OAuth Grant Activity

1. Change the Data view to **oauth-events**.
2. In the query bar, paste the following query, and then press **ENTER**.

    ```
    event.action:"oauth_grant"
    ```

This query searches for OAuth consent activity that may indicate token abuse or delegated access granted to a malicious application.

Review:

* user.email
* oauth.client_id
* oauth.app_name
* geo.country_name
* @timestamp

Evaluate the following:

* Does the OAuth grant occur **shortly after** phishing delivery?
* Is there a **new or suspicious OAuth client** involved?
* Does the grant appear related to the same user targeted by the phishing email?

Suspicious sign-in or OAuth activity shortly after phishing delivery may indicate **successful user compromise**, especially when the activity deviates from the environment’s usual U.S.-based access patterns.

**Save your investigation step**

Save the OAuth query in Kibana using the **exact name**:

```
THL03-User-Interaction
```

Click **Save** and confirm that the saved query appears in your list of saved searches.

**Expected result:**

You confirm suspicious sign-in and/or OAuth consent activity involving the victim account.

Click **Check my progress** to verify the objective.

<ql-activity-tracking Step=2>
    Validate Suspicious User Interaction
</ql-activity-tracking>


## Task 3. Detect mailbox rule persistence



In this task, you pivot from the suspicious user activity to **mailbox telemetry** to investigate whether the attacker created a malicious mailbox rule or forwarding configuration.

Compromised SaaS accounts are often used to create **mailbox rules** that forward emails externally, hide attacker responses, or maintain persistence without generating obvious alerts.

Your goal is to identify mailbox changes that indicate persistence or silent email exfiltration.

### Step 1: Investigate Mailbox Rule Changes

1. In the navigation menu, click **Discover**.
2. Select Data view: **mailbox-rules**.
3. In the query bar, paste the following query, and then press **ENTER**.

    ```
    event.action:("createForwarding" or "addFilter" or "insertSetting")
    ```

This query searches for mailbox configuration changes related to forwarding, filtering, or persistent email handling.

### Step 2: Analyze Rule Activity

Review:

* user.email
* rule.name
* forwarding.address
* destination.email
* @timestamp

Look for patterns that may indicate suspicious activity.

Evaluate the following:

* Is a **new mailbox rule** created for the victim account?
* Does the rule forward mail to an **external recipient**?
* Does the rule appear **after the suspicious sign-in or OAuth event**?

Mailbox changes that forward or redirect messages externally may indicate **persistence or silent exfiltration**.

**Save your investigation step**

Save this query in Kibana using the **exact name**:

```
THL03-Mailbox-Persistence
```

Click **Save** and confirm that the saved query appears in your list of saved searches.

**Expected result:**

You identify a suspicious mailbox rule or forwarding setting created on the victim account.

Click **Check my progress** to verify the objective.

<ql-activity-tracking Step=3>
    Validate Mailbox Rule Detection
</ql-activity-tracking>


## Task 4. Investigate cloud storage activity and data access



In this task, you investigate **cloud storage telemetry** to identify suspicious access to files in the compromised user’s workspace.

Attackers often search, view, download, or share files after gaining access to an account. This activity is frequently performed using legitimate SaaS interfaces or APIs, making detection dependent on behavioral correlation.

Your goal is to identify suspicious access, download, or sharing behavior associated with the victim account.

### Step 1: Review File Activity

1. In the navigation menu, click **Discover**.
2. Select Data view: **drive-activity**.
3. In the query bar, paste the following query, and then press **ENTER**.

    ```
    event.type:("drive.file_view" or "drive.download" or "drive.share") and user.email:"emily.carter@workspace-lab.com"
    ```

This query helps identify file access, downloads, and sharing activity associated with the compromised user account.

### Step 2: Analyze Workspace Activity

Review the following fields:

* file.name
* event.type
* target.email
* @timestamp
* user.email

Look for suspicious behavior such as:

* **Sensitive file access** by the victim account after compromise
* **File downloads** that may indicate collection
* **External sharing** to attacker-controlled accounts

### Step 3: Correlate with previous findings

Evaluate the following:

* Are files being accessed **after the phishing and sign-in/OAuth activity**?
* Does the victim account access or share **multiple sensitive files**?
* Does file sharing occur **shortly before or during exfiltration activity**?

These behaviors may indicate **data discovery and staging prior to exfiltration**.

**Save your investigation step**

Save this query in Kibana using the **exact name**:

```
THL03-Drive-Activity
```

Click **Save** and confirm that the saved query appears in your list of saved searches.

**Expected result:**

You identify suspicious file access and sharing activity associated with the compromised workspace account.

Click **Check my progress** to verify the objective.

<ql-activity-tracking Step=4>
    Validate Cloud Storage Access Detection
</ql-activity-tracking>


## Task 5. Detect data exfiltration to an external account



In this task, you search for **external sharing or download activity** that may indicate data exfiltration.

After identifying suspicious file access, the next step is to determine whether the attacker transferred data outside the organization using built-in SaaS sharing or export functionality.

Your goal is to identify file-sharing or transfer behavior consistent with external data exfiltration.

### Step 1: Search for External Sharing Activity

1. In the navigation menu, click **Discover**.
2. Select Data view: **drive-activity**.
3. In the query bar, paste the following query, and then press **ENTER**.

    ```
    event.type:"drive.share" and target.email:"alex.morgan@external-mail.net"
    ```

This query filters for file sharing events involving the external attacker-controlled account, which may represent exfiltration through legitimate collaboration features.

### Step 2: Correlate with File Access

Review the following fields:

* file.name
* target.email
* user.email
* @timestamp

Look for evidence of suspicious activity.

Evaluate the following:

* Does the share involve an **external account**?
* Does the activity occur **after the suspicious sign-in or OAuth grant**?
* Are the shared files the same ones previously **viewed or downloaded**?

External sharing of sensitive files after suspicious account activity may indicate **data exfiltration**.

**Save your investigation step**

Save this query in Kibana using the **exact name**:

```
THL03-External-Sharing
```

Click **Save** and confirm that the saved query appears in your list of saved searches.

**Expected result:**

You identify file sharing behavior consistent with data exfiltration to an external account.

Click **Check my progress** to verify the objective.

<ql-activity-tracking Step=5>
    Validate External Sharing Detection
</ql-activity-tracking>


## Task 6. Confirm exfiltration via admin and audit telemetry



In this task, you validate the data exfiltration using **admin and audit telemetry**.

Attackers abusing SaaS platforms may generate additional audit events when files are exported, sharing permissions are modified, or access is delegated to external principals.

Your goal is to confirm that the suspicious file activity resulted in successful exfiltration.

### Step 1: Review Admin Audit Events

1. In the navigation menu, click **Discover**.
2. Select Data view: **admin-audit**.
3. In the query bar, paste the following query, and then press **ENTER**.

    ```
    event.action:("permission_change" or "file_export" or "external_share")
    ```

This query searches for audit events related to file export, permission changes, and external sharing actions.

### Step 2: Correlate Findings

Review:

* event.action
* file.name
* actor.email
* target.email
* @timestamp

Look for evidence of suspicious exfiltration.

Evaluate the following:

* Do the audit events **match the files** identified earlier?
* Do the actions occur **after mailbox persistence and suspicious file access**?
* Is the **actor account associated with the compromised user**?
* Do you observe a **matching external recipient**?

Audit telemetry that confirms file export or permission changes to external users strongly indicates **successful data exfiltration**.

**Expected result:**

You confirm data exfiltration through external sharing, export, or audit-confirmed file transfer activity.


## Task 7. Reconstruct the attack timeline



In this final task, you reconstruct the **complete attack timeline** using the evidence collected throughout the investigation.

Combine findings from the different data sources to understand how the attack unfolded.

### Step 1: Correlate events across telemetry sources

Use the following data views to reconstruct the attack sequence:

1. **Phishing delivery** — email-logs
2. **Suspicious sign-in** — admin-audit
3. **OAuth abuse** — oauth-events
4. **Mailbox persistence** — mailbox-rules
5. **File access and sharing** — drive-activity
6. **Exfiltration confirmation** — admin-audit

### Step 2: Build the attack timeline

Identify the order in which the attacker’s actions occurred.

Your timeline should include events such as:

* Initial **phishing email delivery** to the victim
* Suspicious **sign-in** and/or **OAuth consent** by the victim account
* **Mailbox rule creation** or forwarding configuration
* **Sensitive file access**, **download**, or **sharing**
* **External sharing**, export, or audit-confirmed exfiltration

### Step 3: Map findings to MITRE ATT&CK

Map the observed behavior to the following techniques:

* **T1566 – Phishing**
* **T1078 – Valid Accounts**
* **T1550 – Use of Authentication Tokens**
* **T1114.003 – Email Collection: Email Forwarding Rule**
* **T1537 – Transfer Data to Cloud Account**
* **T1567 – Exfiltration Over Web Service**

### Step 4: Explain the attack narrative

Write a short explanation describing:

* Why the **email activity is suspicious**
* How **identity activity aligns with mailbox and file actions**
* How the **data exfiltration was confirmed**
* Why this behavior represents a **coordinated SaaS attacker workflow**

**Expected result:**

You produce a **structured, chronological reconstruction of the attack**, demonstrating how multiple telemetry sources reveal the full attack path.


## Congratulations



You investigated a SaaS-based phishing, account compromise, and data exfiltration scenario using Kibana and Elasticsearch. You correlated email, identity, mailbox, file activity, and audit telemetry to reconstruct a complete attack path.  
These skills are critical for detecting modern cloud productivity threats where attackers abuse legitimate services, tokens, and collaboration features for persistence and exfiltration.


## Continue Your Learning Journey

This lab deepened your investigation skills by detecting account compromise and confirming data exfiltration through multi-source SaaS telemetry correlation.

You learned how to:

* Identify phishing delivery patterns in email telemetry
* Correlate sign-in, OAuth, and mailbox telemetry
* Detect suspicious file access and external sharing behavior
* Confirm exfiltration using audit events
* Build a structured MITRE ATT&CK-aligned timeline

To continue strengthening your SaaS threat hunting expertise, explore:

* Detection of malicious OAuth applications and delegated access abuse
* Behavioral hunting for bulk download and mass sharing activity
* Detection of mailbox rule abuse and email-based persistence
* Cross-layer correlation between identity, email, and collaboration telemetry
* Detection engineering practices for low-noise SaaS attacks

Each lab in this series progressively builds real-world SOC capabilities required for mature cloud-native and productivity-focused environments.


## Take the Next Lab

Continue building your investigation skills in:

#### Lab 4 – IOC-Driven Hunt

In this next lab, you shift from behavioral investigation to **indicator-driven threat hunting**, where known malicious artifacts are used to identify attacker activity across multiple telemetry sources.

Instead of starting from a user or alert, you begin with **Indicators of Compromise (IOCs)** such as:

* Malicious IP addresses
* Suspicious domains
* Known phishing URLs
* File hashes or artifact identifiers

Attackers often reuse infrastructure, making IOC-based hunting effective for identifying:

* Initial access attempts
* Command-and-control (C2) communication
* Data exfiltration channels
* Lateral movement patterns

You will investigate how these indicators appear across datasets such as:

* Email telemetry (phishing links and sender domains)
* Authentication logs (suspicious IP activity)
* Network or SaaS activity (external connections and sharing)
* File and audit logs (artifact access and transfer)

Your goal is to pivot across data sources using IOCs to uncover **hidden attacker activity, scope the intrusion, and identify affected assets**.


## Next Steps / Learn More

To expand your knowledge beyond this lab:

* Review MITRE ATT&CK techniques related to SaaS compromise, persistence, and exfiltration.
* Practice writing advanced detection queries using Kibana Query Language (KQL).
* Study token abuse, delegated access, and mailbox rule attack patterns.
* Explore detection engineering principles used by mature SOC teams.

Continuous practice in structured hunting improves investigative confidence and reduces false positives in production environments.


## End Your Lab

Congratulations! You’ve completed **Workspace Exfiltration**.

Now that you’re finished:

1. Click the **End Lab** button.
2. Click **Submit** to close your session.

Please take a moment to rate the lab. Your feedback helps improve future training content and detection-focused exercises.

### Rating Scale

* ⭐ 1 star = Very dissatisfied
* ⭐⭐ 2 stars = Dissatisfied
* ⭐⭐⭐ 3 stars = Neutral
* ⭐⭐⭐⭐ 4 stars = Satisfied
* ⭐⭐⭐⭐⭐ 5 stars = Very satisfied

Ending the lab removes access to the investigation environment and associated resources.

If you return to the environment after ending the lab, you will be automatically signed out.


**Manual Last Updated:** March 2026  
**Lab Last Tested:** March 2026



