# Cybersecurity-Threat-Detection-Analysis
Python-based cybersecurity threat detection, data cleaning, analysis, and visualization project.
# Cybersecurity Threat Detection & Analysis Using Python

## 📌 Project Overview

This project focuses on analyzing cybersecurity event data to identify potential threats, attack patterns, security indicators, risk levels, and suspicious user behavior.

The project demonstrates the use of Python for **data cleaning, exploratory data analysis, numerical analysis, and data visualization** in a cybersecurity context.

## 🎯 Objectives

* Clean and prepare cybersecurity event data
* Handle missing and duplicate data
* Perform Exploratory Data Analysis (EDA)
* Analyze threat and attack patterns
* Analyze security indicators
* Compare Risk Score and Anomaly Score
* Identify high-risk cybersecurity events
* Analyze suspicious login and network behavior
* Create meaningful cybersecurity visualizations

## 📊 Dataset

* **Original Records:** 5,255
* **Original Columns:** 42
* **Cleaned Records:** 5,200
* **Duplicate Records Removed:** 55
* **Threat Events:** 830
* **Non-Threat Events:** 4,370
* **Threat Percentage:** 15.96%
* **Dataset Period:** January 1, 2025 – March 31, 2025

The primary target variable used for threat analysis is `Is_Threat`.

## 🛠️ Technologies Used

* Python
* Pandas
* NumPy
* Matplotlib
* Seaborn
* Jupyter Notebook

## 🧹 Data Cleaning

The project includes:

* Data structure and data type validation
* Missing value analysis
* Categorical missing value handling
* Numerical missing value handling using median imputation
* Duplicate record removal
* Timestamp conversion
* Categorical data consistency checks
* Final dataset validation

## 🔍 Analysis Performed

### Exploratory Data Analysis

* Threat vs Non-Threat distribution
* Threat Type analysis
* Attack Type analysis
* Attack Vector analysis
* Severity analysis
* Risk Score analysis
* Anomaly Score analysis
* Malware detection analysis
* Suspicious URL analysis
* Unusual Port analysis
* Multiple Failed Login analysis

### Cybersecurity Threat Analysis

The project analyzes:

* Threat Types
* Attack Types
* Attack Vectors
* Severity Levels
* Detection Methods
* Incident Status
* Security Indicators
* Login Behavior
* Network and Traffic Behavior

### Numerical Analysis

NumPy was used for:

* Mean
* Median
* Minimum
* Maximum
* Standard Deviation
* Threat vs Non-Threat comparisons
* High-risk event identification
* Correlation analysis

## 📈 Visualizations

The project includes:

* Threat vs Non-Threat Count Plot
* Threat Type Distribution
* Attack Type Distribution
* Attack Vector Pie Chart
* Severity Distribution
* Security Indicator Heatmap
* Detection Method Distribution
* Risk Score Distribution
* Anomaly Score Distribution
* Risk Score vs Anomaly Score Scatter Plot

## 💡 Key Findings

* The cleaned dataset contains **5,200 cybersecurity events**.
* **830 events (15.96%)** were identified as threats.
* Threat events showed higher average Risk Scores and Anomaly Scores compared with non-threat events.
* High-risk events were identified using **Risk Score > 70**.
* Security indicators such as unusual ports, multiple failed logins, malware detection, and suspicious URLs were analyzed.
* Login and network behavior were compared between threat and non-threat events.

## 📁 Project Files

```text
Cybersecurity-Threat-Detection-Analysis/
│
├── Cybersecurity.ipynb
├── cybersecurity_threat_dataset.csv
├── README.md
├── KEY_INSIGHTS.md
├── Project_Presentation.pptx
│
├── visualizations/
│
└── screenshots/
```

## 🏁 Conclusion

This project demonstrates how **Python, Pandas, NumPy, Matplotlib, and Seaborn** can be used for cybersecurity data analysis.

The project combines data cleaning, EDA, statistical analysis, threat analysis, risk analysis, and visualization to understand cybersecurity events and identify potentially high-risk activities.

> **Note:** This project is descriptive in nature and does not implement a machine-learning classification model.

## 🚀 Future Scope

* Machine-learning based threat classification
* Advanced anomaly detection
* Real-time cybersecurity monitoring
* Interactive cybersecurity dashboards
* Integration of additional cybersecurity datasets
* Deployment as a cybersecurity monitoring application

## 👤 Author

**Manoj**

Data Analytics | Python | Power BI | SQL
