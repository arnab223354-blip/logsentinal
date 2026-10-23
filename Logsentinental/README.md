# 🛡️ LogSentinel — Cybersecurity Log Analyzer & Threat Detection Dashboard

**LogSentinel** is a modern, lightweight, beginner-friendly Security Information and Event Management (SIEM) dashboard and threat detection system built with Python, Streamlit, Pandas, Plotly, and SQLite.

LogSentinel ingests authentication event logs, validates timestamps and IP addresses, applies sliding-window heuristic threat detection rules (such as brute force and credential stuffing attacks), persists events and alerts to an SQLite database, and presents actionable security intelligence through an interactive dark-themed SOC (Security Operations Center) dashboard.

---

## 📋 Features

- **Robust Key-Value Log Parser (`log_parser.py`)**:
  - Ingests `.log` and `.txt` files with standard cybersecurity key-value formatted entries.
  - Validates ISO 8601 timestamps and IPv4/IPv6 addresses.
  - Normalizes timestamps across timezones to UTC for reliable correlation.
  - Supports standard authentication event types: `login_failed`, `login_success`, `logout`, `account_locked`.
  - Gracefully handles malformed lines, skips blank lines and comments (`#`, `//`, `;`), and reports errors with line numbers without crashing.

- **Heuristic Threat Detection Engine (`detection.py`)**:
  - **Rule 1 — Repeated Failed Logins (Brute Force Heuristic)**: Flags $\ge 5$ failed login attempts from a single IP within a sliding 5-minute window.
  - **Rule 2 — Successful Login After Failures (Suspicious Success Heuristic)**: Flags a successful authentication immediately following $\ge 3$ failed attempts for the same username and IP within a sliding 10-minute window.
  - **Deduplication Engine**: Suppresses redundant duplicate alerts during ongoing bursts.
  - **Heuristic Integrity**: Contextualizes alerts as educational heuristics rather than definitive claims of attack.

- **Persistent SQLite Storage (`database.py`)**:
  - Automatically provisions `events` and `alerts` tables with performance indexes.
  - Stores parsed logs and flagged threat alerts using parameterized SQL queries.
  - Calculates live forensic metrics (total events, failure rates, high/critical threats).
  - Supports search, filtering, and database wiping with user confirmation.
  - Local database files are excluded from Git version control.

- **Interactive SOC Dashboard (`app.py`)**:
  - Modern cybersecurity dark theme with high-contrast metric cards and severity badges.
  - Interactive Plotly visualizations:
    - Authentication Event Breakdown (donut chart).
    - Event Activity Timeline (histogram/time-series).
    - Top Targeted User Accounts & Source IPs (horizontal bar charts).
  - Searchable and filterable threat alerts and raw event log tables.
  - File uploader and instant "Built-in Sample Log" ingestion.
  - Configurable detection thresholds via sidebar sliders.
  - CSV and JSON export buttons for compliance and forensic auditing.

- **Automated Test Suite (`tests/`)**:
  - Comprehensive Pytest test suite covering valid/invalid inputs, edge cases, time windows, and database persistence.

---

## 🗂️ Folder Structure

```text
LogSentinel/
├── app.py                   # Streamlit SOC dashboard & forensic visualization
├── log_parser.py            # ISO 8601 log parser & IP/timestamp validator
├── detection.py             # Sliding-window heuristic threat detection engine
├── database.py              # SQLite storage, parameterized queries & metrics
├── requirements.txt         # Core project dependencies (Streamlit, Pandas, Plotly, Pytest)
├── README.md                # Comprehensive documentation & setup guide
├── .gitignore               # Git rules excluding .venv, *.db, and cache files
├── data/
│   ├── sample_auth.log      # Synthetic authentication logs with RFC 5737 test IPs
│   └── logsentinel.db       # Persistent SQLite database (auto-generated at runtime)
└── tests/
    ├── test_log_parser.py   # Parser unit tests (valid, malformed, comments, IPv4/IPv6)
    ├── test_detection.py    # Detection tests (sliding windows, thresholds, deduplication)
    └── test_database.py     # SQLite persistence, querying, and clearing tests
```

---

## 🖥️ Windows Setup Instructions

Ensure you have Python 3.10+ installed on your system. Follow these step-by-step instructions in PowerShell or VS Code terminal:

### 1. Open Workspace in PowerShell
Open VS Code in the project root directory (`LogSentinel/`).

### 2. Create Python Virtual Environment
Run the following command to create an isolated virtual environment in `.venv`:
```powershell
python -m venv .venv
```
*(If `python` is not mapped in your PowerShell, you can also use `py -m venv .venv`)*.

### 3. Upgrade Pip
Use the virtual environment's executable directly to avoid PowerShell script execution policy errors:
```powershell
.\.venv\Scripts\python.exe -m pip install --upgrade pip
```

### 4. Install Dependencies
Install all required packages from `requirements.txt`:
```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

---

## 🚀 Launching the Dashboard

Launch the Streamlit web application using:
```powershell
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Once launched:
1. Open your browser at `http://localhost:8501`.
2. Under **Ingest Logs** in the sidebar, select **Built-in Sample Log** and click **🚀 Analyze & Ingest Logs** (or click the quick-start button on the main screen).
3. Explore the live metrics, Plotly charts, alerts table, and event explorer.
4. Adjust sliding window sliders in the sidebar to observe how heuristic sensitivities change.

---

## 🧪 Running Automated Tests

Run the complete test suite with `pytest`:
```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

To run with verbose output:
```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

All 31 unit and integration tests validate:
- Valid and invalid log syntax, malformed timestamps, IPv4/IPv6 addresses, and comment stripping.
- Sliding time windows, threshold boundaries, deduplication, and custom configurations.
- SQLite initialization, batch inserts, parameterized queries, filtering, and database wiping.

---

## 📝 Sample Log Format

LogSentinel expects logs formatted with an ISO 8601 timestamp followed by key-value pairs:

```text
<TIMESTAMP_ISO8601> ip=<IP_ADDRESS> user=<USERNAME> event=<EVENT_TYPE>
```

### Supported Event Types:
- `login_failed`: An unauthenticated or rejected login attempt.
- `login_success`: A verified, successful login.
- `logout`: User session termination.
- `account_locked`: Account locked due to security policy or excessive failures.

### Example Lines:
```text
# Legitimate login
2026-01-15T08:00:15Z ip=192.0.2.10 user=sarah event=login_success

# Failed attempt during a brute-force burst
2026-01-15T09:10:05Z ip=198.51.100.23 user=admin event=login_failed

# Account lockout event
2026-01-15T09:32:00Z ip=203.0.113.88 user=bob event=account_locked
```

> **Note**: In accordance with RFC 5737, the sample logs use documentation-reserved subnets (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) to ensure testing safety.

---

## 🔍 Threat Detection Rules & Heuristics

| Rule Name | Default Parameters | Severity | Detection Logic | SOC Interpretation |
| :--- | :--- | :--- | :--- | :--- |
| **Repeated Failed Logins** | $\ge 5$ failures within $5$ minutes | **HIGH** | Counts failures per source IP in a sliding time window. | Indicates potential automated brute-force attacks or password spraying. Could also be a misconfigured background script. |
| **Successful Login After Failures** | $\ge 3$ failures before success within $10$ minutes | **CRITICAL** | Looks back from a `login_success` event for prior failures on the same `(user, IP)`. | Indicates potential credential compromise or successful password guessing. Could also be a user recalling a forgotten password. |

---

## 🛠️ Troubleshooting Common Errors

### 1. `execution of scripts is disabled on this system` (PowerShell Policy Error)
- **Cause**: PowerShell restricts running activation scripts (`activate.ps1`).
- **Solution**: Do not activate the environment with `activate.ps1`. Instead, invoke the executable directly:
  ```powershell
  .\.venv\Scripts\python.exe -m streamlit run app.py
  ```

### 2. `Python was not found` or `App execution aliases`
- **Cause**: Windows 10/11 app alias redirection.
- **Solution**: Use `py -m venv .venv` or provide the full path to your Python 3.10+ installation:
  ```powershell
  & "C:\Users\<username>\AppData\Local\Programs\Python\Python314\python.exe" -m venv .venv
  ```

### 3. Port 8501 is already in use
- **Cause**: Another Streamlit instance is running.
- **Solution**: Specify an alternative port:
  ```powershell
  .\.venv\Scripts\python.exe -m streamlit run app.py --server.port 8502
  ```

### 4. Corrupted database or schema changes
- **Cause**: Interrupted database writes or manual edits.
- **Solution**: Click the **🧹 Clear All Stored Data** button in the sidebar (with confirmation checked), or delete `data/logsentinel.db`. The application will re-initialize a fresh schema on the next run.

---

## 🔒 Security Limitations & Privacy Guidance

- **Educational Heuristics**: The detection rules are heuristic algorithms designed for educational SIEM demonstration. They do not constitute deterministic proof of an attack. Always cross-reference network telemetry, user behavior analytics (UBA), and MFA logs in a production SOC.
- **Data Privacy**: LogSentinel operates entirely locally on your workstation. It does not transmit log data, telemetry, or IP addresses to any cloud API or external service.
- **Production Scaling**: For production enterprise environments handling millions of events per second, consider using distributed indexing solutions such as OpenSearch, Elasticsearch, or ClickHouse with Kafka ingestion queues instead of local SQLite.

---

## 📦 Publishing to GitHub

To push LogSentinel to your GitHub profile:

1. Initialize git (if not already initialized):
   ```powershell
   git init
   ```
2. Verify `.gitignore` excludes virtual environments and databases:
   ```powershell
   git status
   ```
3. Stage and commit files:
   ```powershell
   git add .
   git commit -m "feat: initial commit of LogSentinel SIEM dashboard and detection engine"
   ```
4. Create a repository on [GitHub](https://github.com/new), link the remote, and push:
   ```powershell
   git branch -M main
   git remote add origin https://github.com/<your-username>/LogSentinel.git
   git push -u origin main
   ```
