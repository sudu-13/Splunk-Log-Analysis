# Log Analysis using Splunk

# Project Overview
This project demonstrates SSH authentication log analysis using Splunk SIEM to detect malicious activity such as brute-force attacks, unauthorized access attempts, and suspicious SSH behavior.

It simulates real-world SOC analyst workflows, including log ingestion, SPL queries, dashboards, and alerting.

# Objectives
The project aims to detect and analyze:

* ✅ Successful SSH logins (source and destination analysis)
* ❌ Failed login attempts (password guessing & spraying)
* 🚨 Multiple failed authentication attempts (brute-force indicators)
* 🔍 Connections without authentication (SSH probing or scanning)

#   Lab Setup & Prerequisites
# Prerequisites
* Splunk Enterprise / Splunk Free
* Basic understanding of SPL
# Dataset
* ssh_log.json (JSON-formatted SSH authentication logs)

### ⚙️ Environment Setup

1. **Log in to Splunk Web:** Access your Splunk instance via the browser.
2. **Navigate to :**
   
   **Apps** → **Search & Reporting**.

   ![Splunk Dashboard / Search](./image/1.png)

   ![Splunk Step 2](./image/2.png)

3. **Click:**  
  **Add Data** → **Upload**

![Splunk Step 3](./image/3.png)

![Splunk Step 4](./image/4.png)

![Splunk Step 5](./image/5.png)

4. **Upload:** 
   `ssh_log.json`.
   ![Splunk Step 6](./image/6.png)
   ![Splunk Step 7](./image/7.png)

5. **Configure Input Settings:**
   * **Source type:** `_json`
   * **Index:** `ssh_logs`
  
   ![Splunk Step 8](./image/8.png)
   ![Splunk Step 9](./image/9.png)
   ![Splunk Step 10](./image/10.png)
   ![Splunk Step 11](./image/11.png)
   ![Splunk Step 12](./image/12.png)
   ![Splunk Step 13](./image/13.png)
   ![Splunk Step 14](./image/14.png)

6. **Click Start Searching**
    ![Splunk Step 15](./image/15.png)

## 🛠️ Step-by-Step Implementation

### 🔹 Task 1: Log Ingestion & Parsing

**Extracted Fields:**
* `event_type`
* `auth_success`
* `auth_attempts`
* `id.orig_h` (Source IP)
* `id.resp_h` (Destination Host)

**Validation Query:**
```spl
index=ssh_logs
| stats count by event_type
```
 Confirms successful ingestion and parsing.

  ![Splunk Step 16](./image/16.png)

### 🔹 Task 2: Failed Login Analysis

**SPL Query:**
```spl
index=ssh_logs event_type="Failed SSH Login"
| stats count by id.orig_h
| sort - count
| head 10
```
 ![Splunk Step 17](./image/17.png)
![Splunk Step 18](./image/18.png)

### 🔹 Task 3: Brute-Force Detection

**Multiple Failed Attempts Query:**
```spl
index=ssh_logs event_type="Multiple Failed Authentication Attempts"
| stats count by id.orig_h, id.resp_h
| where count > 5
```
![Splunk Step 19](./image/19.png)

#### 🚨 Alert Configuration

| Setting | Configuration |
| :--- | :--- |
| **Trigger Condition** | `> 5 failed attempts` |
| **Time Window** | `10 minutes` |
| **Alert Type** | `Scheduled / Real-Time` |
| **Trigger Action** | `SOC notification or email` |

> 📌 **Purpose:** Early detection of brute-force attacks.

![Splunk Step 20](./image/20.png)
![Splunk Step 21](./image/21.png)
![Splunk Step 22](./image/22.png)
![Splunk Step 23](./image/23.png)
![Splunk Step 24](./image/24.png)
![Splunk Step 25](./image/25.png)
![Splunk Step 26](./image/26.png)

### 🔹 Task 4: Successful SSH Login Tracking

**SPL Query:**
```spl
index=ssh_logs event_type="Successful SSH Login"
| stats count by id.orig_h, id.resp_h
```
![Splunk Step 27](./image/27.png)

### 🔍 Security Correlation

* **Failed vs. Successful Analysis:** Compare source IPs performing successful logins against prior failed attempts.
* **Threat Detection:** Identify possible compromised credentials or successful brute-force intrusions.

> 📊 **Dashboard Panel:**
* Top source IPs with successful SSH access.

![Splunk Step 28](./image/28.png)
![Splunk Step 29](./image/29.png)
![Splunk Step 30](./image/30.png)
![Splunk Step 31](./image/31.png)
![Splunk Step 32](./image/32.png)

