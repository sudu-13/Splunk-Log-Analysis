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
2. **Navigate to App:**
   **Apps** → **Search & Reporting**.
