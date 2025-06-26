# 🚨 Microsoft Sentinel Impossible Travel Alert Project🕵️‍♂️ 

![bigstock-Startup-And-Research-Concept-274237045-e1608263336866](https://github.com/user-attachments/assets/736a03f1-e933-4185-bef6-c570629f08c7)

## 🧠 Purpose

This project demonstrates how to detect "impossible travel" scenarios using Microsoft Sentinel, Log Analytics, and KQL (Kusto Query Language). This kind of detection is useful for spotting suspicious login patterns where a user logs into Azure from geographically distant locations within a short time period — potentially indicating account compromise.

**Scenario:**  
An alert is triggered if a user logs into more than two distinct geographic regions (e.g., Boston and Arlington, TX) within a 7-day time frame.

---

## 🛠️ Technologies Used

- Azure Log Analytics Workspace
- Microsoft Sentinel
- KQL (Kusto Query Language)
- MITRE ATT&CK Mapping
- NIST 800-61 Incident Response Lifecycle
  
---

## 🔎 Part 1: Create the Analytics Rule

![Screenshot 2025-06-25 223606](https://github.com/user-attachments/assets/51e6f350-436e-454a-8240-07deba174cbb)

**Step 1: Query Used for the Possibility of Impossible Travel**
```kql
let TimePeriodThreshold = timespan(7d); 
let NumberOfDifferentLocationsAllowed = 2;
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| summarize Count = count() by UserPrincipalName, UserId, 
    City = tostring(parse_json(LocationDetails).city), 
    State = tostring(parse_json(LocationDetails).state), 
    Country = tostring(parse_json(LocationDetails).countryOrRegion)
| project UserPrincipalName, UserId, City, State, Country
| summarize PotentialImpossibleTravelInstances = count() by UserPrincipalName, UserId
| where PotentialImpossibleTravelInstances > NumberOfDifferentLocationsAllowed
```
![Screenshot 2025-06-25 223506](https://github.com/user-attachments/assets/9d31c2da-411e-47c2-8af1-810f11027c0a)

### 🔨 Step 2: Configure the Rule

- **Name**: `Felipe Restrepo – Potential Impossible Travel`
- **Description**: Trigger alert if a user logs in from more than 2 locations in a 7-day period
- **Severity**: Medium
- **MITRE ATT&CK Mapping**: `T1078.004 - Cloud Accounts`

![Screenshot 2025-06-25 223704](https://github.com/user-attachments/assets/ede17d68-5b02-4edb-bdfa-faa399a5ee93)

---

### 🧬 Step 3: Entity Mapping

- **Account ➝** `UserId` *(AadUserId)*
- **DisplayName ➝** `UserPrincipalName`

![Screenshot 2025-06-25 223953](https://github.com/user-attachments/assets/08aa8ea1-347c-4164-bc9a-d38251d7c186)

---

### ⏱️ Step 4: Query Scheduling

- Run every **5 hours**
- Lookup data from the last **7 days**

![Screenshot 2025-06-25 224010](https://github.com/user-attachments/assets/ec86dd11-575b-4379-87e3-879a0ef4c7d7)

- Generate alert if **results > 0**

![Screenshot 2025-06-25 224019](https://github.com/user-attachments/assets/b2d3d949-4c93-4170-bb16-4f2de34c67f7)

- **Group all events** into a single alert
- **Suppress alerts** for 24 hours

![Screenshot 2025-06-25 224033](https://github.com/user-attachments/assets/541fc202-7d9e-46c5-87a9-69d97326d489)

- **Alert Grouping**

![Screenshot 2025-06-25 224043](https://github.com/user-attachments/assets/bc3b7fae-b43f-48f9-ab5b-7af06691d87d)

- **Alert Rule Created**

![Screenshot 2025-06-25 224135](https://github.com/user-attachments/assets/e5425aa4-3752-4e9f-8c8a-b32858a994ef)

- **Alert Assigned to Me and Activated**

![Screenshot 2025-06-25 224236](https://github.com/user-attachments/assets/8ef07c0e-af24-4d70-8459-cf4c1cdc0da9)

---

## 🧪 Part 2: Work the Incident (NIST IR Lifecycle)

### 1️⃣ Preparation📋
- Before deploying any detection logic, I started by outlining clear roles and procedures for handling potential account anomalies like impossible travel events. This included documenting how alerts would be investigated, who would own the incident, and what steps would be taken at each stage of the response.

- I also made sure that the necessary tools and services were properly configured

---

### 2️⃣ Detection and Analysis🕵️‍♂️ 
- In this phase, we used a targeted KQL query to analyze a specific user's login behavior across geographic locations. The analysis revealed that the user logged in from Boston, MA on June 23 and then from Arlington, TX on June 24 at 2:37 PM. The estimated flight time between these cities is approximately 6 hours, making the travel technically possible.

- However, the logins occurred during a timeframe that did not align with the user’s normal working schedule, raising additional concerns. The timing of access, combined with the geographic shift, flagged the activity as suspicious, even though it could be legitimate. This anomaly warranted further investigation to rule out credential misuse or account compromise.

**Key Finding:**
- Login from **Boston** on 6/23 and **Arlington, TX** on 6/24 at 2:37 PM

![Screenshot 2025-06-25 230145](https://github.com/user-attachments/assets/30b357a4-3ea6-4974-b3e1-5651c2dcc6f7)

- Total flight time: ~6 hours

 ![Screenshot 2025-06-25 225754](https://github.com/user-attachments/assets/580b370d-50b8-4a83-a1ce-abcba2ec69fd)

- Behavior is **suspicious** because of the working schedule, though **possibly legitimate**
- I contacted the user to verify the activity more in depth. They confirmed it was them, but said they didn't want to explain further. Because of that, I considered it a benign positive, but still flagged it as suspicious behavior worth noting in case similar activity happens again.
---

### 3️⃣ Containment, Eradication, and Recovery🔒

- **Contacted the user for verification** 
- I still decided to temporarily contain the account by disabling it in **Azure AAD** as a precaution. It was re-enabled after confirming there were no additional signs of compromise. I documented it as a benign positive, but kept it flagged due to the unusual behavior and limited user cooperation.
  
- Disabled the Account in Azure AAD

![Screenshot 2025-06-25 230735](https://github.com/user-attachments/assets/2c2ff5cd-d391-41ad-8ed9-45020b87e1d4)

**Marked the Incident as a Benign Positive and left a comment about the situation**

![Screenshot 2025-06-25 232818](https://github.com/user-attachments/assets/ef7330bd-9159-4327-90f2-958b0a2a8000)

To finalize the incident, I added a detailed comment directly in the Sentinel alert, explaining the user’s response, the containment action taken, and the reasoning behind the decision. This ensures the case is properly documented and can be reviewed later if needed.

![Screenshot 2025-06-25 232644](https://github.com/user-attachments/assets/7f55c518-e144-4973-af63-282b2681b48a)

---

### 4️⃣ Post-Incident Activities🧾

After finishing the investigation, I closed the incident as:  
> ✅ **Benign Positive – Suspicious but Expected**

Even though the sign-ins came from different locations in a short time frame and didn’t match the user’s usual working hours, the user did confirm the activity. They didn’t want to explain the details, which was a little unusual, but based on their confirmation and no further signs of compromise, I didn’t see enough evidence to consider it a real threat. Still, the behavior was worth flagging just in case it happens again.

This case brought up a couple of things we could improve to catch this type of activity more accurately in the future:

---

#### 📍 Geo-Fencing Login Policies  
We could add geo-fencing rules in Azure to block or alert on logins from outside approved regions — like only allowing sign-ins from within the U.S. This would help reduce the number of "gray area" alerts like this one and give us clearer indicators when something’s really off.

---

#### 🧠 Smarter Detection Based on User Behavior  
Right now, alerts are mostly based on location and timing, but they don’t consider what's normal for each specific user. If we had a way to track behavior over time — like usual work hours, travel patterns, and devices — we’d be able to tell the difference between a real threat and something expected much faster. In this case, the system couldn’t tell that this user normally doesn’t log in late or from different states, which is why it triggered an alert.

---

Overall, while this incident didn’t lead to any action beyond temporarily disabling the account, it was still helpful in showing where we can make improvements to reduce false positives and respond faster to anything truly suspicious.

