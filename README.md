# Azure Sentinel Brute Force Detection and Incident Response Lab

This lab walks through the detection, investigation, and response of brute force login attempts against an Azure VM using Microsoft Sentinel, Microsoft Defender for Endpoint, and NSG configuration.

## 🧠 Scenario Overview

Entities (local or remote users) attempting to log into an Azure VM generate entries in the `DeviceLogonEvents` table. These logs are ingested by Microsoft Defender for Endpoint and forwarded to Microsoft Sentinel for correlation and alerting. We designed a scheduled query alert that detects when the same IP address attempts to log in and fails ≥10 times within a set time frame.

---

## 📍 Objective

- Create an **Analytics Rule** in Microsoft Sentinel to detect brute-force login attempts.
- Trigger the alert and generate an incident.
- Investigate and respond to the incident using the NIST 800-61 Incident Response Lifecycle.
- Lock down the NSG to prevent unauthorized RDP access.
- Document and close the incident.

---

## 🛠️ Part 1: Create Brute Force Alert Rule

### 🔎 Query Used

```kql
DeviceLogonEvents
| where TimeGenerated > ago(10d)
| where DeviceName == "rich-mde-test"
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize FailedAttempts = count() by RemoteIP, DeviceName
| where FailedAttempts >= 10
| extend TimeWindow = "10d"
| project RemoteIP, DeviceName, FailedAttempts, TimeWindow
| order by FailedAttempts
```

## 🧠 Rule Configuration Highlights

- **Query Frequency:** Every 5 hours  
- **Lookup Period:** 10 days  
- **Stop query if alert is generated:** ✅  
- **MITRE ATT&CK:** Credential Access  
- **Entity Mapping:**
  - Host → `DeviceName`
  - IP → `RemoteIP`

![image](https://github.com/user-attachments/assets/0e2f6c40-3950-4438-b5d5-8eda0c561b36)

---

## ⚠️ Part 2: Trigger and Generate an Incident

- Manual brute-force login attempts were initiated using known external IPs.
- The alert was successfully triggered and an incident was automatically created.
- Incident was assigned and marked as **Active** in Microsoft Sentinel.

![image](https://github.com/user-attachments/assets/fc51721a-76ed-402e-ba9a-cb5c99187a24)

![image](https://github.com/user-attachments/assets/93b10827-fee1-47cc-b2d5-d7ac011bddcb)

![image](https://github.com/user-attachments/assets/f27c4b21-1df2-44b0-85cb-fa16d4b30cf8)

---

## 🧪 Part 3: Investigate & Respond (NIST Lifecycle)

### 1. **Preparation**
- Microsoft Sentinel and Defender for Endpoint already deployed and integrated.
- Alert rule created using KQL to detect brute-force login attempts.

  ![image](https://github.com/user-attachments/assets/d0afc33c-f161-4ee8-b212-1ce50be34d11)

---

### 2. **Detection & Analysis**

- **Incident Title:** Rich H. - Brute Force Attempt Detection  
- **Affected VM:** `rich-mde-test`  
- **IP Addresses Detected:**
  - `103.51.56.169`
  - `85.215.240.231`
  - `185.7.214.7`
  - `79.72.9.168`
 
  ![image](https://github.com/user-attachments/assets/14e22b8b-9160-4012-8832-6b11c5739fb1)

> ✅ **Only successful login:** My public IP was intentionally used to validate alert logic.

#### ✅ Query Used to Confirm Successful Logins

```kql
DeviceLogonEvents
| where TimeGenerated > ago(10d)
| where DeviceName == "rich-mde-test"
| where ActionType == "LogonSuccess"
| where isnotempty(RemoteIP)
| summarize SuccessfulAttempts = count() by RemoteIP, DeviceName
| extend TimeWindow = "10d"
| project RemoteIP, DeviceName, SuccessfulAttempts, TimeWindow
| order by SuccessfulAttempts desc
```

## 🛡️ 3. Containment, Eradication, and Recovery

- ✅ **Device Isolation:** Executed via Microsoft Defender for Endpoint  
- ✅ **Malware Scan:** Completed — no threats found  
- ✅ **NSG Update:** VM NSG modified to only allow RDP access from my public IP  
- ✅ **Policy Proposed:** All corporate VMs should restrict RDP to trusted IPs via Azure Policy

  ![image](https://github.com/user-attachments/assets/60cee706-8b53-48b2-8a28-98a338dc447e)

---

## 🧾 4. Post-Incident Activity

- 📝 **Incident response notes** were documented in Sentinel’s activity log.  
- 📌 **Incident labeled:** `True Positive - Suspicious Activity`  
- ✅ **Case closed** after confirming full containment and mitigation steps.

![image](https://github.com/user-attachments/assets/a773a487-71c8-4681-9a14-99c84164dd30)

![image](https://github.com/user-attachments/assets/d7c4dc14-b2e7-4ba4-802a-7541f81f0920)

---

## 📘 Final Summary

| **Category**         | **Details**                                          |
|----------------------|------------------------------------------------------|
| **Affected VM**      | `rich-mde-test`                                      |
| **Detection Source** | Microsoft Sentinel                                   |
| **Alert Trigger**    | ≥5 failed logins from same RemoteIP                  |
| **True Positive?**   | ✅ Yes                                                |
| **Action Taken**     | NSG hardened, AV scan, device isolation              |
| **Final Status**     | Closed (`True Positive`)                             |
| **MITRE ATT&CK**     | Credential Access                                    |
| **Analyst Notes**    | See screenshots and Sentinel activity log for detail |

---

## 📸 Appendix: Screenshots

Screenshots captured from:

- Microsoft Sentinel (Alerts, Incidents, Investigation Timeline)  
- Microsoft Defender for Endpoint (Isolation, AV scan results)  
- Azure Log Analytics (KQL queries for detection and verification)

---

## 💡 Lessons Learned

- Confirm KQL queries include projectable fields — avoid referencing columns (like `TimeGenerated`) post-`summarize()` unless rejoined.
- Avoid wide-open NSGs — restrict RDP access to known IPs only.
- Efficient response depends on visibility across **SIEM**, **EDR**, and **cloud networking** controls.

---

## ✅ Status

> **Incident Resolved and Closed**  
> **Classification:** ✅ `True Positive – Suspicious Activity`
```
