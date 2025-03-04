# 🔥 SOAR & EDR Project  

## 📌 Overview  

This project aims to provide **hands-on experience** with **Endpoint Detection and Response (EDR)** and **Security Orchestration, Automation, and Response (SOAR)**. We will use **LimaCharlie** (EDR) and **Tines** (SOAR) to create automated detection and response rules via a playbook.  

LimaCharlie will serve as our **EDR tool**, providing real-time threat detection and monitoring for endpoints, while Tines will act as our **SOAR platform**, automating and orchestrating responses to those detections.  

### 🎯 Key Objectives  

- **Create Detection Rules:** Configure LimaCharlie to detect threats like HackTools, suspicious processes, or abnormal system behaviour. 🔍  
- **Automate Responses:** Use Tines to build playbooks that automatically respond to detections, such as sending alerts, isolating affected machines, or triggering remediation actions. ⚡  
- **Integrate LimaCharlie & Tines:** Establish seamless integration for an automated security operations workflow. 🔗  
- **Simulate Real-World Scenarios:** Improve incident response efficiency by detecting and mitigating threats quickly. 🌍  

By combining EDR with SOAR, this project will **reduce manual tasks, minimise response times, and enhance security operations** — crucial for modern cybersecurity teams. 🚀  

---

## 📊 Playbook Diagram  

![Playbook Diagram drawio](https://github.com/user-attachments/assets/402a0c1d-19da-44e5-b7d5-e32ac8b974de)  
**Ref 1: A diagram illustrating the playbook flow**  

---

## ⚙️ Playbook Workflow  

### 1️⃣ **Detection in LimaCharlie**  
LimaCharlie will detect **HackTool** activity, triggering an alert for Tines to process. 🕵️‍♂️  

### 2️⃣ **Send Alerts**  
Tines will automatically notify relevant stakeholders via **Slack** and **Email** with details:  

- **Time** of detection ⏰  
- **Computer Name** affected 💻  
- **Source IP** address 🌐  
- **Process** involved 🧑‍💻  
- **Command Line** executed 🔐  
- **File Path** (if applicable) 📂  
- **Sensor ID** 🛡️  
- **Link to Detection** (if applicable) 🔗  

### 3️⃣ **User Prompt**  
Tines will then prompt the user:  

> **Would you like to isolate the machine?**  
> (Yes / No) 🤔  

### 4️⃣ **Action Based on User Response**  

- **If "Yes" is selected**:  
  - LimaCharlie isolates the machine.  
  - Slack message:  
    > "The computer `<computer_name>` has been isolated." 🚨  

- **If "No" is selected**:  
  - No isolation occurs.  
  - Slack message:  
    > "The computer `<computer_name>` was not isolated. Please investigate further." 🧐  

---

# 🛠️ Setting Up LimaCharlie (EDR)  

## 🔹 Overview  

We will install and configure **LimaCharlie (EDR)** on a **Windows Server VM** running in **VirtualBox**. The goal is to ensure the endpoint successfully connects and reports security events in real time.  

Once installed, we will explore LimaCharlie’s core features, including **threat detection, monitoring, and response**.  

---

## 🔹 Setting Up Your Windows VM  

1. Ensure your **Windows Server VM** is running in **VirtualBox**.  
2. Proceed with enrolling the machine into LimaCharlie.  

---

## 🔹 Generate an Installation Key  

1. Log in to **LimaCharlie** and open your **organisation**.  
2. Navigate to **Installation Keys** → Click **Create Installation Key**.  
3. Name your key (e.g., `AJSOC-SOAR-EDR-PROJECT`).   

---

## 🔹 Download & Install LimaCharlie on Windows  

1. Scroll to **Sensor Downloads**.  
2. Download the **Windows 64-bit** EDR agent.  
3. Copy your **Installation Key** for the PowerShell installation.  

---

## 🔹 Install LimaCharlie via PowerShell  

1. Open **PowerShell as Administrator**.  
2. Navigate to your **Downloads** folder.  
3. Run:
   ```powershell
   .\LimaCharlieInstaller.exe -i <YOUR_INSTALLATION_KEY>
   ```
4. Installation completes within seconds.
5. Check LimaCharlie → Sensors List — your VM should appear as an active sensor.

---

## 🔍 Exploring LimaCharlie Features  

Once connected, explore LimaCharlie’s security tools for **monitoring and investigating threats**.  

### 🔑 Key Features  

- 📌 **Overview** – Displays hostname, status, and metadata.  
- 📊 **Analytics** – Insights from security events for anomaly detection.  
- 📦 **Artifacts** – Collects forensic data (logs, memory dumps, etc.).  
- ⚙️ **Autoruns** – Lists applications/scripts that start automatically.  
- 💻 **Console** – CLI for remote command execution on endpoints.  
- 🚨 **Detections** – Alerts triggered by security rules.  
- 🖥️ **Drivers** – Identifies outdated or potentially malicious drivers.  
- 📡 **Event Collection** – Tracks system events (process creation, registry changes, network activity).  
- 📂 **File System** – Enables remote file browsing.  
- 🔎 **Integrity Monitoring** – Detects unauthorised system file changes.  
- ⚡ **Live Feed** – Streams real-time security events.  
- 🌐 **Network** – Monitors network connections for suspicious activity.  
- 🔗 **Packages** – Manages installed tools/scripts.  
- 🏃 **Processes** – Displays active processes to detect anomalies.  
- 🔄 **Services** – Lists running services and their statuses.  
- 📅 **Timeline** – Historical view of events for forensic analysis.  
- 👥 **Users** – Lists system accounts to detect unauthorised access.  

# 🔐 Detecting LaZagne with LimaCharlie  

## 📥 Download & Install LaZagne  

1. Download **LaZagne** from GitHub:  
   👉 [LaZagne v2.4.6](https://github.com/AlessandroZ/LaZagne/releases/tag/v2.4.6)  

2. Install it on the **Windows Server** using **PowerShell**.  

---

## ℹ️ What is LaZagne?  

LaZagne is an open-source **credential recovery tool** that extracts stored passwords from various applications, including browsers, databases, and system credentials.  

Since we ran this tool on the server, **LimaCharlie** would have picked it up via the **Timeline** as a running process.  

---

## ⚙️ Creating a Detection Rule in LimaCharlie  

1. Navigate to **Organisation** → **Automation** → **D&R Rules**.  
2. Click **New Rule**.  
3. Use the following **process creation rule** from LimaCharlie’s GitHub:  

**Detect:**
```yaml
  events:
    - NEW_PROCESS
    - EXISTING_PROCESS
  op: and
  rules:
    - op: is
      value: windows
    - op: or
      rules:
        - case sensitive: false
          op: ends with
          path: event/FILE_PATH
          value: LaZagne.exe
        - case sensitive: false
          op: contains
          path: event/COMMAND_LINE
          value: LaZagne
        - case sensitive: false
          op: is
          path: event/HASH
          value: 467e49f1f795c1b08245ae621c59cdf06df630fc1631dc0059da9a032858a486
```
**Respond:**
```yaml
  - action: report
    metadata:
      author: AJSOC
      description: TEST - Detects LaZagne Usage
      falsepositives:
        - ToTheMoon
      level: high
      tags:
        - attack.credential_access
  name: AJSOC - HackTool - LaZagne - SOAR - EDR
```
## 📝 Rule Breakdown  

#### **Detect Section**  
- **events:**  
  - `NEW_PROCESS` – Triggers when a new process starts.  
  - `EXISTING_PROCESS` – Monitors already running processes.  
- **op: and** – All conditions must be met.  
- **rules:**  
  - **op: is → value: windows** – Ensures the rule applies only to Windows systems.  
  - **op: or** – At least one of the conditions must match:  
    - **case sensitive: false, op: ends with, path: event/FILE_PATH, value: LaZagne.exe**  
      - Detects if the process file path ends with `LaZagne.exe`.  
    - **case sensitive: false, op: contains, path: event/COMMAND_LINE, value: LaZagne**  
      - Flags command-line executions containing "LaZagne".  
    - **op: is, path: event/HASH, value: 467e49f1f795c1b08245ae621c59cdf06df630fc1631dc0059da9a032858a486**  
      - Matches the exact hash of a known `LaZagne` binary.  

#### **Respond Section**  
- **action: report** – Generates an alert when the rule is triggered.  
- **metadata:**  
  - **author: AJSOC** – Identifies the rule creator.  
  - **description:** Detects `LaZagne` execution.  
  - **falsepositives:** Allows exceptions (`ToTheMoon`).  
  - **level: high** – Sets severity to high.  
  - **tags:** Categorises detection as a **credential access attack**.  

---

## 🛠️ **Testing the Rule**  

1. **Go to LimaCharlie** → **Detections** and clear any existing detections.  
2. Open **PowerShell** and run:

   ```powershell
   .\LaZagne.exe all

3. Go back to LimaCharlie → Detections.
4. You should now see an alert for LaZagne execution triggered by the rule.

## 🔗 Connecting Tines with LimaCharlie using Webhooks  

---

## 🛠 Step 1: Create a Webhook in Tines  
1. **Log in** to your Tines account.  
2. **Click "New Story"** and create a new story.  
3. **Click "Add Agent"** and select **"Webhook"** as the agent type.  
4. **Rename the webhook** to `Retrieve Detections`.  
5. **Add a description**: `Retrieve LimaCharlie Detections`.  
6. **Copy the Webhook URL** generated by Tines.  

---

## ⚙️ Step 2: Configure LimaCharlie to Send Events  
1. **Log in** to your LimaCharlie dashboard.  
2. **Go to "Outputs"** in the left-hand menu.  
3. **Click "Add Output"**, then select **Detections**.  
4. **Choose "Tines"** as the output type.  
5. **Enter the name**: `AJSOC-SOAR-EDR`.  
6. **Paste the Tines Webhook URL** copied earlier.  
7. Click **"Save"** to activate the webhook.  

---

## 📡 Step 3: Test the Integration  
1. **Trigger an event** in LimaCharlie (e.g., execute a process that should be detected).  
2. **Check Tines** to see if the event has been received.  

LimaCharlie instance is now successfully integrated with Tines via a webhook! This setup allows real-time event 
forwarding to automate responses and enhance security operations.  

# 📖 Automated Security Response: LimaCharlie & Tines Playbook  

---


## 🛠️ Playbook Overview  
I have successfully built an **automated security response playbook** in **Tines**, following the previously designed playbook diagram.  

### 🔄 Workflow Overview  
When **a detection is received**, the playbook will:  

![image](https://github.com/user-attachments/assets/a4ab26e3-5657-42e5-95d4-8207c05aa823)
1️⃣ **Send an email alert**.  

![image](https://github.com/user-attachments/assets/859e3856-e649-4f07-b675-68f33959c45b)
2️⃣ **Post a notification to the `#alerts` channel** in Slack.  


![image](https://github.com/user-attachments/assets/f72e3789-c526-4828-89e7-6a10d74d5669) 

3️⃣ **Prompt the user** to decide if the affected machine should be isolated. 

4️⃣ If the user selects **"Yes"**, the machine is **automatically isolated** from the network. 


![image](https://github.com/user-attachments/assets/2e5e2583-3196-43bb-8167-22062da645df)

5️⃣ A **confirmation message** with machine details is sent to **Slack**.  

![image](https://github.com/user-attachments/assets/41a46a5f-6210-4f5c-8b17-b64151a9c968)
6️⃣ The isolation status can be verified in **LimaCharlie**.  

---

## Tools Used 🛠️  
- **LimaCharlie** (EDR for real-time detection & response)  
- **Tines** (Security automation & orchestration)  
- **Slack** (Instant alerting in the `#alerts` channel)  
- **Email (SMTP)** (Automated email notifications)  

---

## Skills Gained 🚀  
✅ Configuring **EDR detections** in LimaCharlie  
✅ Automating security responses using **Tines**  
✅ Sending **automated alerts** via Slack and email  
✅ Implementing **user-driven machine isolation**  
✅ Enhancing **incident response efficiency**  

---

## Conclusion 🎯  
This playbook enables **real-time threat detection and response** by integrating LimaCharlie with Tines and Slack. The automation reduces manual workload, speeds up incident handling, and ensures **fast machine isolation** when necessary.  

---

## Future Enhancements 🔮  
- **Threat Intelligence Integration** for enriched detections  
- **Granular Isolation Controls** (e.g., process-level quarantine)  
- **Multi-Channel Alerts** (MS Teams, SMS, or webhooks)  
- **Automated Reporting** for security audits  
- **Machine Learning-based Anomaly Detection**  





