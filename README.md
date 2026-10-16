# 🛡️ LabSentinel
### Rule-Based Security Monitoring for Shared Computer Labs

LabSentinel is a cybersecurity monitoring project designed to analyze shared computer lab login logs, detect suspicious authentication patterns, and generate explainable security alerts to support incident investigation.

The system helps lab administrators identify potentially compromised accounts, repeated authentication failures, unusual login times, and suspicious access patterns through a centralized dashboard.

> **Project focus:** Security monitoring · Authentication log analysis · Incident response · Explainable detection · SOAR-inspired workflows

## 📌 Problem Statement

Shared computer laboratories often have multiple users accessing systems from common devices and networks. Monitoring login activity manually can make it difficult to identify suspicious behavior in time.

LabSentinel addresses this challenge by analyzing authentication logs using configurable, rule-based detection logic and presenting potentially suspicious activity in a structured dashboard for human review.

## ✨ Key Features

- **Multi-CSV Log Analysis:** Upload and analyze multiple authentication log files.
- **Repeated Failures Followed by Success:** Detect repeated failed login attempts followed by a successful login.
- **After-Hours Login Detection:** Flag successful logins occurring outside configured lab hours.
- **Shared IP Detection:** Identify multiple accounts accessing a lab from the same IP address within a defined time window.
- **Repeated Failed Attempts:** Flag repeated login attempts that end in failure.
- **Explainable Alerts:** Present incident evidence and relevant login events to support investigation.
- **Incident Review:** Classify alerts as Needs Review, Confirmed Suspicious, or False Positive, with review notes where supported.
- **Risk Classification:** Categorize alerts by severity to help prioritize investigations.
- **Containment Workflow:** Support controlled, temporary account-blocking workflows for eligible high-risk incidents, where configured.
- **Audit Trail:** Record relevant review and response actions.
- **Incident Reporting:** Export incident reports, including PDF reports where supported by the installed version.
- **Persistent Review History:** Use SQLite to preserve incident review information between sessions.

*Detection thresholds, lab hours, and response behavior depend on the configured implementation. Alerts indicate suspicious patterns, not proof of malicious activity.*

## 🧰 Technology Stack

| Technology | Purpose |
|---|---|
| Python | Detection logic and application processing |
| Streamlit | Interactive web dashboard |
| Pandas | CSV parsing and log analysis |
| SQLite | Local incident review and history storage |
| CSV | Authentication log input |
| Git & GitHub | Version control and source code hosting |

## 🏗️ System Workflow

1. Import authentication logs from CSV files.
2. Validate and process the login events.
3. Apply detection rules to identify suspicious patterns.
4. Generate alerts with supporting evidence and severity.
5. Review and classify incidents through the dashboard.
6. Record relevant response actions and audit information.
7. Export incident reports for further investigation.

## 🔍 Detection Rules

| Rule | Detection logic | Purpose |
|---|---|---|
| Rule 1 | Repeated failures followed by a successful login | Identify possible account compromise |
| Rule 2 | Successful login outside configured lab hours | Identify unusual access timing |
| Rule 3 | Multiple accounts using the same IP within a configured time window | Identify potentially suspicious shared access |
| Rule 4 | Repeated login attempts ending in failure | Identify persistent authentication failures |

Risk levels and thresholds are determined by the implemented detection rules. Legitimate shared-lab activity can also trigger alerts, so administrator review is important.

## 📂 Expected Log Format

LabSentinel uses authentication logs with fields such as:

| Column | Description |
|---|---|
| `event_id` | Unique login event identifier |
| `username` | Account associated with the event |
| `timestamp` | Date and time of the event |
| `ip_address` | Source IP address |
| `login_status` | Login success or failure |
| `lab_id` | Identifier of the computer lab |

Example CSV:

```csv
event_id,username,timestamp,ip_address,login_status,lab_id
E001,student01,2026-10-15 09:00:00,192.168.1.10,FAILURE,LAB01
E002,student01,2026-10-15 09:01:00,192.168.1.10,FAILURE,LAB01
E003,student01,2026-10-15 09:02:00,192.168.1.10,SUCCESS,LAB01
```

Use synthetic or anonymized data when testing and sharing the project.

## 🚀 Getting Started

### Prerequisites

- Python 3.10 or a compatible version
- pip
- Git
- A Windows, Linux, or macOS environment

### 1. Clone the repository

```bash
git clone https://github.com/Christy-29/LabSentinel.git
cd LabSentinel
```

### 2. Create a virtual environment

**Windows Command Prompt:**

```cmd
python -m venv .venv
.venv\Scripts\activate
```

### 3. Install dependencies

If the repository contains `requirements.txt`:

```cmd
python -m pip install -r requirements.txt
```

If it does not, install the packages required by the application. For the basic Streamlit prototype:

```cmd
python -m pip install streamlit pandas
```

Install any additional dependencies required by the report-generation or other enabled features.

### 4. Run the application

```cmd
python -m streamlit run app.py
```

Open the local URL displayed in the terminal, typically:

`http://localhost:8501`

The dashboard runs locally on your machine. Other users can clone the repository and follow these steps to run their own instance.

## 🧪 Testing

To evaluate the detection rules:

1. Prepare synthetic CSV files containing successful and failed login events.
2. Include normal lab activity and suspicious authentication patterns.
3. Upload the files through the dashboard.
4. Review the generated alerts and supporting evidence.
5. Test incident review, reporting, and configured response workflows.
6. Verify that legitimate shared-lab usage is not automatically treated as confirmed malicious activity.

## 🔐 Security Considerations

- Do not commit passwords, API keys, database credentials, or private configuration files.
- Avoid publishing real student login records, personal information, or sensitive network data.
- Use least privilege when implementing containment actions.
- Require appropriate authorization before blocking accounts.
- Keep audit records for response actions.
- Treat automated detections as investigation leads rather than definitive proof of an attack.

## 🛣️ Future Enhancements

- Integration with centralized authentication and SIEM platforms.
- Configurable detection thresholds and lab schedules.
- Improved role-based access control.
- Integration with approved alerting channels.
- Expanded automated response playbooks.
- Deployment for controlled remote access.
- Enhanced testing with larger and more diverse datasets.

## 🎯 Learning Outcomes

This project explores practical cybersecurity concepts, including authentication log analysis, detection engineering, incident triage, alert prioritization, audit logging, and security automation.

## 👨‍💻 Author

**Christy Grace V**

CSE – Cyber Security Student

GitHub: [@Christy-29](https://github.com/Christy-29)

## ⚠️ Disclaimer

LabSentinel is an educational cybersecurity project intended for authorized monitoring, testing, and research. It should be validated and secured before use in a production environment.

## 👨‍💻 Author & Copyright

**Developed by Christy Grace V**  
CSE – Cyber Security Student

GitHub: [@Christy-29](https://github.com/Christy-29)

**Copyright © 2026 Christy Grace V. All rights reserved.**

LabSentinel is an educational cybersecurity project developed for portfolio demonstration and evaluation. Please refer to the repository's `LICENSE` file for permitted use.

If you would like to reuse, redistribute, or build upon this project beyond the permissions granted in the license, please request written permission from the author.
