# TNS_Cyber_Security_Project

# AI-Assisted Mini-SIEM

A small, explainable security-monitoring tool that reads login logs and detects **brute-force / password-guessing attacks**. It is a learning project, not a full commercial SIEM.

> **Important:** detection is done by **fixed rules, not AI**. The only "AI-assisted" part is an **optional risk score** that is fully explainable: the dashboard shows exactly how many points each feature contributed.

---

## What is a SIEM?

SIEM stands for **Security Information and Event Management**. Organizations collect logs from servers, firewalls, and login systems, and a SIEM scans them for suspicious patterns so analysts don't have to read millions of lines by hand. This project builds a mini version that focuses on one common attack: many failed logins in a short time.

---

## Features

- Upload **CSV or JSON** log files (one or several) in the dashboard
- Rule-based detection: **N failed logins from one IP within M minutes**
- **Deduplication:** a burst of repeated failures becomes one alert, not many
- **Correlation:** flags a successful login from the same IP right after a burst (possible compromised account)
- **Severity** levels: High / Medium
- Optional **explainable risk score** (0 to 100) with a per-feature breakdown
- **Evidence** table behind every alert (the exact log rows that triggered it)
- **SQLite** alert history, with no duplicate entries
- **CSV report** download
- Interactive dashboard: sliders, filters, charts, log explorer

---

## Pipeline

```
Upload logs (CSV/JSON)
   -> Normalize fields (clean, standardize, sort)
   -> Rules / correlation (N fails in M minutes per IP)
   -> Deduplicate repeated events into one alert
   -> Severity (+ optional risk score)
   -> Dashboard, evidence, SQLite history, CSV report
```

---

## How detection works

**Rule:** alert when one IP has **5 or more failed logins within 5 minutes** (default, adjustable with sliders; this is an illustrative threshold).

1. Keep only the `fail` events and group them by IP.
2. Slide a time window across each IP's failed attempts.
3. If the window contains at least the threshold number of failures, raise an alert.
4. Keep extending the burst while attempts continue, so repeated events merge into **one** alert.
5. Check whether the same IP had a **successful login within the window after the burst**.

**Severity**

| Severity | Condition |
|---|---|
| High | 10 or more failed attempts, **or** a successful login followed the burst |
| Medium | Everything else that triggers the rule |

**Optional risk score (0 to 100)**

Added after rule detection. Each feature adds points, and the dashboard shows the breakdown:

| Feature | Max points |
|---|---|
| Attempt rate (fails per minute) | 40 |
| Total failed attempts | 20 |
| Number of users targeted | 15 |
| Privileged account targeted (admin, root, administrator) | 10 |
| Success after burst | 15 |

The score is a transparent, hand-weighted formula, not a trained machine-learning model.

---

## Requirements

- **Python 3.13 (64-bit)**. Python 3.12 to 3.14 also work. 32-bit Python will not work, because pandas and numpy have no prebuilt wheels for it on Windows.
- Packages: `streamlit`, `pandas`

---

## Setup (Windows, VS Code)

```powershell
cd "D:\TNS Group Project"
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install streamlit pandas
```

If PowerShell blocks the activate script, run this once and retry:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Check that `(venv)` appears at the start of the prompt before installing. To verify you are on 64-bit Python:

```powershell
python -c "import struct; print(struct.calcsize('P')*8)"
```

It should print `64`.

**For teammates:** install the same Python version, then

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

(Create `requirements.txt` with `pip freeze > requirements.txt`.)

---

## Run

```powershell
streamlit run mini_siem.py
```

The dashboard opens at `http://localhost:8501`.

---

## Input format

Upload CSV or JSON files with these four fields (any order, header names are case-insensitive):

| Field | Meaning | Example |
|---|---|---|
| `time` | Timestamp of the login attempt | `2026-10-14 09:00:00` |
| `ip` | Source IP address | `203.0.113.50` |
| `user` | Account name | `admin` |
| `status` | `success` or `fail` | `fail` |

Status values such as `failed`, `failure`, `denied`, `successful`, and `ok` are converted automatically.

**CSV example**

```csv
time,ip,user,status
2026-10-14 09:00:00,203.0.113.50,admin,fail
2026-10-14 09:00:20,203.0.113.50,admin,fail
```

**JSON example** (a list of records)

```json
[
  {"time": "2026-10-14 09:00:00", "ip": "203.0.113.50", "user": "admin", "status": "fail"},
  {"time": "2026-10-14 09:00:20", "ip": "203.0.113.50", "user": "admin", "status": "fail"}
]
```

A ready-made test file, `sample_logs.csv`, is included.

---

## Using the dashboard

| Area | What it does |
|---|---|
| **Sidebar** | Sliders for the failed-login threshold (2 to 20) and time window (1 to 60 min); filters for severity, IP, and minimum risk score; toggle for the risk score |
| **Overview tab** | Counters, failed logins over time, top IPs by failed logins |
| **Alerts tab** | Alerts table, CSV download, **Save to history**, and an alert selector showing the summary, score breakdown, and evidence |
| **Log explorer tab** | Filter all logs by status, IP, and user search |
| **History tab** | Alerts stored in SQLite, with a clear-history button |

---

## Expected result with `sample_logs.csv`

| IP | What happened | Result |
|---|---|---|
| `203.0.113.50` | 8 failed logins in about 2 minutes | Alert, Medium |
| `198.51.100.7` | 5 failed logins in 4 minutes, then a success | Alert, High |
| `192.0.2.99` | 5 failed logins spread over 50 minutes | No alert (too slow) |
| `10.0.0.x` | Normal users, mostly successful | No alert |

**Demo tips**

- Set the window to **60 minutes**: the slow guesser (`192.0.2.99`) now triggers an alert.
- Set the threshold to **20**: all alerts disappear.
- Untick **Medium** in the severity filter: only the High alert remains.

---

## Project files

```
mini_siem.py       Main app (loading, detection, scoring, storage, dashboard)
sample_logs.csv    Test log file
siem.db            SQLite history (created automatically on first save)
README.md          This file
requirements.txt   Package list (create with pip freeze)
```

Delete `siem.db` to reset the alert history, and add it and `venv/` to `.gitignore`.

---

## Limitations

- Looks at **one IP at a time**, so a distributed attack (many IPs, a few attempts each) can slip through
- Does not detect **password spraying** (one password tried against many accounts) unless a single IP crosses the threshold
- Threshold and window are illustrative values, not tuned on real traffic
- Works on uploaded batch files, not a live log stream
- The risk score is a simple weighted formula, not a trained model

## Possible future work

- Per-user detection and a distributed-attack rule
- Live log ingestion
- A trained anomaly model (for example Isolation Forest) added **after** the rules, with explanations
- LLM-written analyst summaries
- Email or Slack notifications

---

## Team

- Project: AI-Assisted Mini-SIEM
- Members: Esha Survase, Vaishnavi Purane, Vaishnavi Kumbhar, Iram Kazi, Kashaf Shaikh
