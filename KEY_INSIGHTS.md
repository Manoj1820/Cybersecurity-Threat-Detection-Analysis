# Cybersecurity Threat Detection & Analysis Using Python
### Key Insights & Project Documentation

---

## 1. Project Overview

**Project Title:** Cybersecurity Threat Detection & Analysis Using Python

### Objective
To analyse a network security event log and identify the patterns that separate genuine cybersecurity threats from normal network activity. The project aims to:

- Measure how frequently threats occur in the monitored environment
- Identify the most common threat types, attack types and attack vectors
- Determine which security indicators are the strongest signals of an actual threat
- Use Risk Score and Anomaly Score to prioritise high-risk events
- Provide a data-backed basis for threat monitoring and alert triage

### Dataset Overview

| Attribute | Value |
|---|---|
| File | `cybersecurity_threat_dataset.csv` |
| Rows (raw) | 5,255 |
| Columns | 42 |
| Rows after cleaning | **5,200** |
| Time period covered | 01 Jan 2025 – 31 Mar 2025 |
| Target column | `Is_Threat` (1 = threat, 0 = non-threat) |

**Column groups in the dataset:**

| Group | Columns |
|---|---|
| Event identity | Event_ID, Timestamp, Source_IP, Destination_IP, Source_Port, Destination_Port, Protocol |
| Network traffic | Packet_Count, Bytes_Sent, Bytes_Received, Connection_Duration, Request_Count, Response_Time |
| Login activity | Login_Attempts, Failed_Login_Count, Successful_Login_Count, Session_Duration, Authentication_Method |
| Security controls | Malware_Detected, Firewall_Status, Antivirus_Status, Encryption_Used |
| Threat indicators | Suspicious_URL, Unusual_Port, Multiple_Failed_Logins |
| Scores | Anomaly_Score, Risk_Score |
| Threat labels | Threat_Type, Attack_Type, Attack_Vector, Severity, Threat_Status, Detection_Method, Is_Threat, Is_Malicious, Incident_Status |
| Context | Device_Type, Operating_System, Browser, Country, Region, Network_Type |

### Technologies Used

| Technology | Role in the project |
|---|---|
| **Python** | Core programming language for the entire analysis |
| **Pandas** | Data loading, cleaning, missing-value handling, grouping, aggregation, cross-tabulation |
| **NumPy** | Statistical calculations, percentiles, correlation, array-based filtering of high-risk events |
| **Matplotlib** | Base plotting for distribution and comparison charts |
| **Seaborn** | Statistical visualisations — count plots, box plots, histograms, heatmaps |

---

## 2. Data Preparation & Cleaning

### 2.1 Initial Dataset Inspection

The raw file was loaded with `pd.read_csv()` and inspected using `.shape`, `.head()`, `.info()`, `.dtypes`, `.describe()` and `.isnull().sum()`.

| Check | Result |
|---|---|
| Shape | 5,255 rows × 42 columns |
| Numeric columns | 18 |
| Text / categorical columns | 24 |
| Columns with missing values | 11 |
| Fully duplicated rows | 55 |

### 2.2 Missing Value Analysis

| Column | Missing Count | Missing % (of 5,200 cleaned rows) | Nature of missingness |
|---|---|---|---|
| Threat_Type | 4,370 | 84.04% | Structural — no threat occurred |
| Attack_Type | 4,370 | 84.04% | Structural — no threat occurred |
| Attack_Vector | 4,370 | 84.04% | Structural — no threat occurred |
| Threat_Status | 4,370 | 84.04% | Structural — no threat occurred |
| Response_Time | 208 | 4.00% | Genuine data gap |
| Antivirus_Status | 156 | 3.00% | Genuine data gap |
| Bytes_Received | 130 | 2.50% | Genuine data gap |
| Authentication_Method | 104 | 2.00% | Genuine data gap |
| Browser | 104 | 2.00% | Genuine data gap |
| Country | 104 | 2.00% | Genuine data gap |
| Session_Duration | 78 | 1.50% | Genuine data gap |

> **Important finding:** The 4,370 missing values in the four threat-description columns are **not** a data quality problem. Cross-checking against `Is_Threat` showed that **every one of those 4,370 rows is a non-threat event**, and **zero threat events have a missing Threat_Type**. These fields are blank simply because there is no threat to describe. Dropping these rows would have deleted the entire non-threat population.

### 2.3 Categorical Missing-Value Handling

Two different rules were applied, based on *why* the value was missing:

| Columns | Fill value | Reasoning |
|---|---|---|
| Threat_Type, Attack_Type, Attack_Vector, Threat_Status | `"None"` | The event genuinely had no threat — "None" is the correct, meaningful value |
| Authentication_Method, Antivirus_Status, Browser, Country | `"Unknown"` | The information was not captured — "Unknown" preserves the row without inventing a value |

After filling, `Browser` shows 967 "Unknown" entries (863 already recorded as "Unknown" in the source plus 104 filled), and `Antivirus_Status` shows 156 "Unknown" entries.

### 2.4 Numerical Missing-Value Handling Using Group-Wise Median

A single overall median would have been misleading, because threat events and normal events have very different traffic profiles. Instead, missing numeric values were filled with the **median of their own `Is_Threat` group**:

```python
for col in ['Bytes_Received', 'Response_Time', 'Session_Duration']:
    df[col] = df.groupby('Is_Threat')[col].transform(lambda s: s.fillna(s.median()))
```

| Column | Median (Non-Threat) | Median (Threat) | Difference |
|---|---|---|---|
| Bytes_Received | 5,993.00 | 20,823.00 | Threat events receive ~3.5× more data |
| Response_Time | 0.82 | 3.41 | Threat events respond ~4× slower |
| Session_Duration | 25.20 | 12.45 | Threat sessions are about half as long |

> Using a single global median would have inflated non-threat values and deflated threat values, weakening the very difference the project is trying to detect. The median was chosen over the mean because these columns are right-skewed and the median is not distorted by extreme values.

### 2.5 Duplicate Removal

| Step | Rows |
|---|---|
| Before removal | 5,255 |
| Exact duplicate rows removed | **55** |
| After removal | **5,200** |

All 55 duplicates were confirmed as repeated `Event_ID` values, meaning the same security event had been logged twice. Retaining them would have double-counted those events in every subsequent percentage.

### 2.6 Data Type and Consistency Checks

| Check | Finding | Action |
|---|---|---|
| `Timestamp` stored as text | Yes | Converted with `pd.to_datetime()` |
| `Protocol` inconsistent casing | **16 unique values** found instead of 8 — e.g. `HTTP`, `http`, `Http`; `TCP`, `tcp`, `Tcp`; `UDP`, `udp`, `Udp`; `HTTPS`, `https` | Standardised with `.str.strip().str.upper()` → reduced to **8 clean protocol values** |
| Binary flag columns | Malware_Detected, Suspicious_URL, Unusual_Port, Multiple_Failed_Logins, Encryption_Used, Is_Threat, Is_Malicious all contain only 0/1 | Confirmed valid |
| Score ranges | Risk_Score and Anomaly_Score both fall within 0–100 | No out-of-range values |
| Negative values | None in Packet_Count, Bytes_Sent, Bytes_Received, Login counts | No action needed |
| Remaining nulls after cleaning | **0** | Dataset ready for analysis |

---

## 3. Exploratory Data Analysis

### 3.1 Threat vs Non-Threat Distribution

| Category | Count | Percentage |
|---|---|---|
| Non-Threat (`Is_Threat = 0`) | 4,370 | 84.04% |
| **Threat (`Is_Threat = 1`)** | **830** | **15.96%** |
| **Total** | **5,200** | **100%** |

The dataset is **imbalanced** — roughly 1 in every 6 logged events is an actual threat.

### 3.2 Threat Type Distribution

All 830 threat events fall into nine categories, and the distribution is remarkably even (no single dominant threat):

| Threat Type | Count | % of Threats |
|---|---|---|
| Port Scanning | 101 | 12.17% |
| Man-in-the-Middle | 96 | 11.57% |
| Ransomware | 94 | 11.33% |
| DDoS | 93 | 11.20% |
| Malware | 91 | 10.96% |
| Brute Force | 90 | 10.84% |
| Phishing | 89 | 10.72% |
| Insider Threat | 89 | 10.72% |
| SQL Injection | 87 | 10.48% |
| **Total** | **830** | **100%** |

### 3.3 Attack Type Distribution

A column-by-column comparison confirmed that **`Attack_Type` is identical to `Threat_Type` for every row in the dataset**. The two columns are duplicates of each other, so the counts in Section 3.2 apply equally to Attack_Type. This is a useful redundancy finding — only one of the two columns is needed for modelling.

### 3.4 Severity Distribution

| Severity | Count | % of All Events |
|---|---|---|
| Low | 4,484 | 86.23% |
| High | 317 | 6.10% |
| Medium | 302 | 5.81% |
| Critical | 97 | 1.87% |

Cross-tabulating Severity against Is_Threat revealed a strict pattern:

| Severity | Non-Threat | Threat |
|---|---|---|
| Low | 4,370 | 114 |
| Medium | 0 | 302 |
| High | 0 | 317 |
| Critical | 0 | 97 |

> **Every single Medium, High and Critical event is a confirmed threat.** All 4,370 non-threat events are labelled Low severity. Within the 830 threats, 716 (86.27%) are Medium or above, while 114 are still rated Low.

### 3.5 Risk Score Analysis

| Statistic | Value |
|---|---|
| Mean | 27.67 |
| Median | 20.07 |
| Standard Deviation | 24.61 |
| Minimum | 0.00 |
| Maximum | 100.00 |
| 25th percentile | 12.50 |
| 75th percentile | 30.37 |
| 90th percentile | 75.07 |
| 95th percentile | 86.12 |

The distribution is strongly **right-skewed** (mean 27.67 > median 20.07). Most events cluster at low risk, with a long tail of high-risk events. The jump from the 75th percentile (30.37) to the 90th (75.07) shows the high-risk group is a small, clearly separated cluster.

### 3.6 Anomaly Score Analysis

| Statistic | Value |
|---|---|
| Mean | 28.96 |
| Median | 22.80 |
| Standard Deviation | 23.35 |
| Minimum | 0.00 |
| Maximum | 100.00 |
| 25th percentile | 13.71 |
| 75th percentile | 34.41 |
| 90th percentile | 70.68 |
| 95th percentile | 82.50 |

Anomaly Score follows the same right-skewed shape as Risk Score, which is expected since the two are strongly correlated (r = 0.786).

### 3.7 Security Indicator Analysis

| Indicator | Flagged (=1) | % of All Events |
|---|---|---|
| Malware_Detected | 541 | 10.40% |
| Suspicious_URL | 538 | 10.35% |
| Unusual_Port | 466 | 8.96% |
| Multiple_Failed_Logins | 443 | 8.52% |
| Encryption_Used | 3,809 | 73.25% |

**Security control status across all 5,200 events:**

| Firewall_Status | Count | | Antivirus_Status | Count |
|---|---|---|---|---|
| Active | 3,967 | | Updated | 3,635 |
| Inactive | 779 | | Outdated | 991 |
| Misconfigured | 454 | | Disabled | 418 |
| | | | Unknown | 156 |

Roughly **23.7% of events occurred on systems with an inactive or misconfigured firewall**, and **27.1% on systems with outdated or disabled antivirus**.

---

## 4. Cybersecurity Threat Analysis

### 4.1 Threat Prevalence
**830 of 5,200 events (15.96%)** are confirmed threats. A security team monitoring this environment would need to separate these 830 real incidents from 4,370 items of normal noise.

### 4.2 Threat Types
Nine threat categories, evenly spread between 87 and 101 events each. **Port Scanning is the most frequent (101)** and **SQL Injection the least frequent (87)** — a range of only 14 events. This means the environment is not facing one dominant attack campaign but broad, varied attack activity.

### 4.3 Attack Types
Identical to Threat Type (confirmed for all rows). Port Scanning leads with 101 events.

### 4.4 Attack Vectors

| Attack Vector | Count | % of Threats |
|---|---|---|
| Web Application | 134 | 16.14% |
| Remote Desktop | 126 | 15.18% |
| Email | 126 | 15.18% |
| Network | 112 | 13.49% |
| USB Device | 112 | 13.49% |
| API | 112 | 13.49% |
| Social Engineering | 108 | 13.01% |
| **Total** | **830** | **100%** |

**Web Application is the single largest entry point (134 threats)**. Web Application, Remote Desktop and Email together account for 386 threats — **46.5% of all threats** enter through these three channels.

### 4.5 Severity
Of the 830 threats: **High 317, Medium 302, Low 114, Critical 97**. Critical events (97) represent the highest-priority queue — only 1.87% of total traffic but demanding immediate response.

### 4.6 Malware Detection

| Group | Malware Detected | Rate |
|---|---|---|
| Threat events | 467 of 830 | **56.27%** |
| Non-threat events | 74 of 4,370 | 1.69% |

Malware detection is roughly **33× more likely** in a threat event. However, 74 non-threat events also triggered malware detection, and 363 threats did **not** — so this flag alone cannot be used as the sole detection rule.

### 4.7 Suspicious URLs

| Group | Suspicious URL | Rate |
|---|---|---|
| Threat events | 411 of 830 | **49.52%** |
| Non-threat events | 127 of 4,370 | 2.91% |

About half of all threats involve a suspicious URL, versus under 3% of normal traffic.

### 4.8 Unusual Ports

| Group | Unusual Port | Rate |
|---|---|---|
| Threat events | 466 of 830 | **56.14%** |
| Non-threat events | **0 of 4,370** | **0.00%** |

> **Strongest single indicator in the dataset.** Not one non-threat event used an unusual port. Every one of the 466 unusual-port events is a confirmed threat — a **100% precision** signal. It detects 56% of threats, so it cannot catch everything, but when it fires it is never wrong in this dataset.

### 4.9 Multiple Failed Logins

| Group | Multiple Failed Logins | Rate |
|---|---|---|
| Threat events | 429 of 830 | **51.69%** |
| Non-threat events | 14 of 4,370 | 0.32% |

Over half of threats show repeated failed logins, against almost none in normal traffic — a very high-precision indicator with only 14 false positives.

### 4.10 Threat / Incident Status

**Threat_Status (830 threat events only):**

| Status | Count |
|---|---|
| Contained | 329 |
| Investigating | 264 |
| Active | 237 |

**237 threats remain Active** — still live and unresolved.

**Incident_Status (all 5,200 events):**

| Incident Status | Non-Threat | Threat | Total |
|---|---|---|---|
| Resolved | 3,053 | 289 | 3,342 |
| False Positive | 1,317 | 104 | 1,421 |
| Under Investigation | 0 | 235 | 235 |
| Escalated | 0 | 126 | 126 |
| Open | 0 | 76 | 76 |

Escalated, Open and Under Investigation statuses are used **exclusively for real threats** (437 events in total). Notably, **104 confirmed threats were closed as "False Positive"** — a potential mis-triage worth flagging to the security team.

**Is_Malicious vs Is_Threat:** 628 of the 830 threats are also flagged malicious; **202 threats are not flagged as malicious**. No non-threat event is flagged malicious. This shows `Is_Malicious` is a narrower label than `Is_Threat`.

### 4.11 Detection Methods

| Detection Method | Total Events | Threats Detected | Non-Threats |
|---|---|---|---|
| Firewall | 1,458 | 119 | 1,339 |
| Antivirus | 1,017 | 125 | 892 |
| No_Detection | 804 | **0** | 804 |
| SIEM | 612 | 154 | 458 |
| IDS/IPS | 579 | 152 | 427 |
| Manual Review | 381 | 142 | 239 |
| EDR | 349 | 138 | 211 |

> **Key observation:** All 804 "No_Detection" events are non-threats — nothing slipped through undetected. **SIEM catches the most threats (154)**, but **Manual Review has the highest hit rate (142 of 381 = 37.3%)**, followed by EDR (138 of 349 = 39.5%) and IDS/IPS (152 of 579 = 26.3%). Firewall processes the most traffic (1,458 events) but has the lowest hit rate (8.2%) — it acts as a high-volume, low-specificity first filter.

### 4.12 Login Behaviour

| Metric (average) | Non-Threat | Threat | Ratio |
|---|---|---|---|
| Login Attempts | 1.73 | **5.51** | 3.2× |
| Failed Login Count | 0.98 | **5.02** | 5.1× |
| Successful Login Count | 0.75 | 0.49 | 0.65× |
| Session Duration | 25.78 | 14.63 | 0.57× |

Median failed logins: **1 for non-threats, 5 for threats** (maximum observed: 18).

> **Behavioural signature of an attack:** many attempts, many failures, few successes, short sessions. Attackers try repeatedly, fail often, and do not stay long — the opposite of a legitimate user, who logs in once or twice and stays connected.

**Supporting traffic behaviour:**

| Metric (average) | Non-Threat | Threat | Ratio |
|---|---|---|---|
| Packet Count | 154.87 | 850.08 | 5.5× |
| Bytes Sent | 5,671.23 | 60,128.16 | 10.6× |
| Request Count | 19.75 | 150.47 | 7.6× |
| Connection Duration | 31.43 | 140.37 | 4.5× |
| Response Time | 0.81 | 3.55 | 4.4× |

**Encryption behaviour is inverted:** 80.66% of non-threat events use encryption, but only 34.22% of threat events do. Absence of encryption is itself a warning sign.

---

## 5. NumPy Numerical Analysis

NumPy was used for all statistical computation and for array-based filtering of high-risk events.

```python
risk = df['Risk_Score'].to_numpy()
anomaly = df['Anomaly_Score'].to_numpy()

np.mean(risk), np.median(risk), np.std(risk)
np.percentile(risk, [25, 50, 75, 90, 95])
np.corrcoef(risk, anomaly)[0, 1]
high_risk = df[np.logical_and(risk > 70, anomaly > 70)]
```

### 5.1 Risk Score Statistical Analysis

| Statistic | All Events | Non-Threat | Threat |
|---|---|---|---|
| Mean | 27.67 | 17.95 | **78.87** |
| Median | 20.07 | 17.66 | **78.85** |
| Std Deviation | 24.61 | 9.74 | 13.21 |
| Minimum | 0.00 | 0.00 | 31.56 |
| Maximum | 100.00 | 54.64 | 100.00 |

### 5.2 Anomaly Score Statistical Analysis

| Statistic | All Events | Non-Threat | Threat |
|---|---|---|---|
| Mean | 28.96 | 20.18 | **75.19** |
| Median | 22.80 | 20.29 | **75.17** |
| Std Deviation | 23.35 | 11.39 | 13.82 |
| Minimum | 0.00 | 0.00 | 32.43 |
| Maximum | 100.00 | 65.33 | 100.00 |

### 5.3 Threat vs Non-Threat Comparison

| Comparison | Result |
|---|---|
| Risk Score gap (mean) | 78.87 vs 17.95 → **4.4× higher** for threats |
| Anomaly Score gap (mean) | 75.19 vs 20.18 → **3.7× higher** for threats |
| Non-threat maximum Risk Score | 54.64 |
| Threat minimum Risk Score | 31.56 |
| Overlap zone | Risk Score 31.56 – 54.64 |

Outside the narrow overlap band, the two populations separate cleanly: **no non-threat event scores above 54.64 on risk**, and **no non-threat event scores above 65.33 on anomaly**.

**Correlations (NumPy `np.corrcoef`):**

| Pair | Correlation |
|---|---|
| Risk Score ↔ Is_Threat | **0.907** |
| Anomaly Score ↔ Is_Threat | **0.863** |
| Risk Score ↔ Anomaly Score | 0.786 |

Risk Score is the strongest numerical predictor of whether an event is a threat.

### 5.4 High-Risk Event Identification

| Filter | Events | % of Dataset | Threats Inside | Precision |
|---|---|---|---|---|
| Risk_Score > 70 | 625 | 12.02% | 625 | **100%** |
| Risk_Score > 80 | 388 | 7.46% | 388 | **100%** |
| Risk_Score > 90 | 190 | 3.65% | 190 | **100%** |
| Anomaly_Score > 70 | 531 | 10.21% | 531 | **100%** |
| Anomaly_Score > 80 | 320 | 6.15% | 320 | **100%** |
| Anomaly_Score > 90 | 131 | 2.52% | 131 | **100%** |
| Risk > 70 **AND** Anomaly > 70 | 411 | 7.90% | 411 | **100%** |

> **Most actionable result in the project.** A simple rule — Risk Score above 70 — isolates 625 events, and **every one of them is a genuine threat**. This narrows the analyst's queue from 5,200 events to 625 (a 88% reduction in review volume) with zero false positives in this dataset. Those 625 events cover **75.3% of all 830 threats**; the remaining 205 threats score 70 or below and need the indicator-based rules from Section 4 to catch them.

---

## 6. Key Cybersecurity Insights

### 6.1 Headline Numbers

| Metric | Value |
|---|---|
| **Total events analysed** | **5,200** |
| **Threat events** | **830** |
| **Non-threat events** | **4,370** |
| **Threat percentage** | **≈ 15.96%** |
| Duplicate records removed | 55 |
| Columns analysed | 42 |

### 6.2 Most Common Threat and Attack Categories
- **Port Scanning is the most common threat and attack type (101 events, 12.17% of threats)**, followed by Man-in-the-Middle (96) and Ransomware (94).
- Threat types are evenly distributed — the spread from most to least common is only 101 down to 87, indicating broad rather than concentrated attack activity.
- **Web Application is the leading attack vector (134 threats, 16.14%)**, followed by Remote Desktop and Email (126 each).
- Attack_Type duplicates Threat_Type exactly across all 5,200 rows.

### 6.3 Severity Findings
- **All 716 Medium, High and Critical events are confirmed threats; not one is a false alarm.**
- All 4,370 non-threat events are Low severity.
- 114 threats are rated Low severity — meaning severity alone would miss 13.7% of real threats.
- 97 Critical events (1.87% of all traffic) form the top-priority response queue.

### 6.4 Security Indicator Findings

| Indicator | Threat Rate | Non-Threat Rate | Precision when flagged |
|---|---|---|---|
| **Unusual Port** | 56.14% | **0.00%** | **466/466 = 100%** |
| Multiple Failed Logins | 51.69% | 0.32% | 429/443 = 96.8% |
| Malware Detected | 56.27% | 1.69% | 467/541 = 86.3% |
| Suspicious URL | 49.52% | 2.91% | 411/538 = 76.4% |
| Encryption Used | 34.22% | 80.66% | *(inverse indicator)* |

- **Unusual Port is a perfect indicator in this dataset** — zero non-threat events used one.
- Encryption works in reverse: threats are **less** likely to be encrypted (34.22% vs 80.66%).
- No single indicator catches more than 57% of threats, so **layered rules are necessary** — combining indicators is far more effective than relying on any one.

### 6.5 Risk and Anomaly Findings
- Threat events average a Risk Score of **78.87** versus **17.95** for non-threats.
- Threat events average an Anomaly Score of **75.19** versus **20.18** for non-threats.
- Risk Score correlates with threat status at **r = 0.907** — the strongest numerical signal in the dataset.
- No non-threat event exceeds a Risk Score of **54.64** or an Anomaly Score of **65.33**.

### 6.6 High-Risk Event Findings
- **625 events (12.02%) have a Risk Score above 70, and 100% of them are real threats.**
- 411 events breach both the Risk > 70 and Anomaly > 70 thresholds — all confirmed threats.
- A Risk > 70 rule reduces the analyst review queue by 88% while capturing 75.3% of all threats.

### 6.7 Login Behaviour Findings
- Threat events average **5.51 login attempts and 5.02 failures**, versus 1.73 attempts and 0.98 failures for normal events.
- Threat events have **fewer successful logins (0.49 vs 0.75)** and **shorter sessions (14.63 vs 25.78)**.
- Threat traffic is far heavier: **10.6× more bytes sent, 7.6× more requests, 5.5× more packets**.
- The signature of a malicious login is: *high attempts, high failures, low success, short session*.

### 6.8 Detection and Response Findings
- All 804 "No_Detection" events are non-threats — no threat went completely undetected.
- **SIEM detected the most threats (154)**; **EDR and Manual Review had the best hit rates (39.5% and 37.3%)**.
- **237 threats are still Active** and 126 have been Escalated.
- **104 confirmed threats were closed as "False Positive"** — a triage gap worth investigating.
- 202 threat events are not flagged as `Is_Malicious`, showing the two labels measure different things.

---

## 7. Data Visualizations

| # | Visualization | Type | Purpose |
|---|---|---|---|
| 1 | Threat vs Non-Threat count plot | Seaborn `countplot` | Shows the 830 / 4,370 class imbalance at a glance — establishes that threats are the minority case |
| 2 | Threat Type distribution | Horizontal bar chart | Ranks the nine threat categories and demonstrates how evenly spread they are |
| 3 | Attack Vector distribution | Bar chart | Identifies Web Application, Remote Desktop and Email as the main entry points to defend |
| 4 | Severity distribution | Count plot | Shows how few events are Critical/High relative to the Low-severity bulk |
| 5 | Severity vs Is_Threat | Stacked bar / crosstab heatmap | Reveals that all Medium+ events are threats — the clearest visual rule in the project |
| 6 | Risk Score histogram | Histogram with KDE | Exposes the right-skewed, two-cluster shape of the risk distribution |
| 7 | Anomaly Score histogram | Histogram with KDE | Same purpose for anomaly, confirming the pattern repeats |
| 8 | Risk Score by Threat Status | Box plot | Visualises the 78.87 vs 17.95 separation and how little the two boxes overlap |
| 9 | Anomaly Score by Threat Status | Box plot | Confirms the same separation on the second score |
| 10 | Risk vs Anomaly scatter plot | Scatter, coloured by Is_Threat | Shows threats clustering in the top-right quadrant — the visual basis for the dual-threshold rule |
| 11 | Security indicator comparison | Grouped bar chart | Compares indicator rates across threat and non-threat groups, making the Unusual Port result obvious |
| 12 | Correlation heatmap | Seaborn `heatmap` | Displays relationships among numeric features, highlighting Risk_Score ↔ Is_Threat at 0.907 |
| 13 | Detection Method vs Threat | Grouped bar chart | Compares how many threats each detection tool catches versus its total volume |
| 14 | Login behaviour comparison | Bar chart of group means | Contrasts login attempts, failures and successes between threat and non-threat events |

---

## 8. Project Conclusion

This analysis converts a raw log of 5,200 security events into a clear, evidence-based picture of the threat landscape.

**Understanding cybersecurity threats.** The project quantifies exactly how much of the monitored traffic is dangerous — **15.96%** — and breaks that down into nine threat types and seven attack vectors. Instead of a vague sense that "attacks happen", the security team gets specific numbers: Port Scanning leads at 101 events, Web Application is the biggest entry point at 134 threats, and 237 threats are still live.

**Identifying suspicious events.** The indicator analysis shows precisely which signals are trustworthy. **Unusual Port is a perfect indicator (466 flags, 466 threats, zero false positives)**, Multiple Failed Logins is 96.8% precise, and the behavioural signature of attacks — many login attempts, many failures, few successes, short sessions, heavy traffic, no encryption — is measurable and repeatable. These findings can be written directly into detection rules.

**Prioritising high-risk events.** The most practical outcome is the threshold rule. Filtering to **Risk Score > 70 returns 625 events, all of which are genuine threats**. An analyst who reviews only those 625 events covers three-quarters of all threats while ignoring 88% of the log. Adding the Anomaly > 70 condition tightens the queue to 411 events for the most urgent review. Severity offers a second prioritisation lane: every Medium, High and Critical event is real, with the 97 Critical events at the top.

**Supporting threat monitoring.** The cleaned dataset and the rules derived from it give a monitoring team three layers of defence: a score threshold for high-confidence alerts, indicator flags for events that score lower but still show attack behaviour, and detection-method performance data showing where tooling investment pays off (SIEM and EDR outperform the firewall on hit rate). The analysis also surfaces operational gaps worth fixing — **104 real threats closed as false positives**, 237 threats still active, and 27.1% of events occurring on systems with outdated or disabled antivirus.

The analysis is descriptive rather than predictive. It does not build a machine learning classifier, and the conclusions apply to this three-month dataset. A natural next step is to use these features to train a supervised model and validate the thresholds on fresh data.

---

## 9. Interview Talking Points

### What problem does this project solve?
Security teams receive far more alerts than they can investigate. In this dataset, 5,200 events were logged but only 830 were real threats — about 84% of the queue is noise. This project answers two questions with data: *which events actually matter*, and *which ones should be looked at first*. The outcome is a filter that cuts the review queue from 5,200 events to 625, with every one of those 625 confirmed as a genuine threat.

### What did I do in the project?
> "I took a raw security log of 5,255 rows and 42 columns and worked through it end to end. First I cleaned it — removed 55 duplicate events, handled missing values in 11 columns, and fixed inconsistent protocol names where HTTP appeared in four different cases. Then I explored the data to find out what fraction were real threats and what kinds of attacks were occurring. After that I analysed which security indicators and numerical scores actually separate threats from normal traffic, and finally I visualised the results. The main finding was that a Risk Score above 70 identifies 625 events that are all genuine threats."

### Why was Pandas used?
Pandas handles everything involving the table itself:
- `read_csv()` to load 5,255 rows and 42 columns
- `isnull().sum()` to find the 11 columns with missing values
- `drop_duplicates()` to remove the 55 repeated events
- `groupby().transform()` for the group-wise median imputation
- `value_counts()` for every distribution in Sections 3 and 4
- `crosstab()` to prove that all Medium+ severity events are threats
- `.str.upper()` to standardise 16 protocol spellings into 8

> "Pandas is for anything shaped like a table — filtering, grouping and summarising. Without it I'd be writing loops for every count."

### Why was NumPy used?
NumPy handles the numbers underneath the table:
- `np.mean`, `np.median`, `np.std` for the Risk and Anomaly score statistics
- `np.percentile` to find the 90th percentile (75.07) and see where the high-risk cluster begins
- `np.corrcoef` to measure Risk Score against Is_Threat at 0.907
- Boolean array filtering (`np.logical_and`) to isolate the 411 events above both thresholds

> "NumPy works on arrays of numbers and is much faster than Python loops. When I needed percentiles, standard deviation or correlation, that's NumPy. Pandas is actually built on top of it."

### Why were Seaborn and Matplotlib used?
Matplotlib is the underlying plotting engine; Seaborn sits on top and makes statistical charts quick to produce.

> "The box plot of Risk Score by threat status makes the point faster than any table — you can see immediately that the two boxes barely overlap. The correlation heatmap and the scatter plot of Risk against Anomaly showed the threat cluster in the top-right corner, which is what led me to the dual-threshold rule. Seaborn gave me count plots, box plots and heatmaps in one line each; Matplotlib handled the titles, labels and figure sizing."

### What were the major findings?
Five findings worth memorising:

1. **15.96% of events are threats** — 830 out of 5,200.
2. **Risk Score above 70 gives 625 events and 100% of them are real threats** — an 88% reduction in review volume.
3. **Unusual Port is a perfect indicator** — 466 flags, zero false positives, not one non-threat event used an unusual port.
4. **Every Medium, High and Critical event is a genuine threat** — all 716 of them; non-threats are always Low severity.
5. **Attack logins look different** — 5.02 failed attempts on average versus 0.98, with shorter sessions and 10.6× more data sent.

### What did I learn from the project?
- **Missing data needs a reason, not a default.** The 4,370 blanks in Threat_Type looked like a huge data quality problem, but they were blank because those events had no threat. Dropping or filling them blindly would have destroyed the analysis.
- **Group-wise imputation beats a global median** when the groups genuinely differ — non-threat sessions had a median Bytes_Received of 5,993 against 20,823 for threats, so one shared median would have blurred the exact signal I was looking for.
- **Data consistency checks catch things counts don't.** The protocol column looked fine until I checked unique values and found 16 instead of 8.
- **Precision and coverage are different things.** Unusual Port is 100% precise but only catches 56% of threats. No single rule is enough — layering them is what works.
- **Always check for redundant columns.** Attack_Type turned out to be an exact copy of Threat_Type across all 5,200 rows.
- **The business value is in the prioritisation, not the statistics.** The mean Risk Score of 27.67 is just a number; "review these 625 events and you'll find 625 real threats" is something a security team can act on tomorrow.

---

*Documentation generated from the analysis of `cybersecurity_threat_dataset.csv` (5,200 cleaned records, 42 features, January–March 2025). All figures in this document are computed directly from the dataset.*
