"""
AI-Assisted Mini-SIEM
Pipeline: sample logs -> normalize fields -> rules/correlation -> severity -> dashboard/report

Detection is done by FIXED RULES (not AI). The only "AI-assisted" part is the
optional anomaly/risk score, which is explainable (every feature's points are shown).

Run:  pip install streamlit pandas
      streamlit run mini_siem.py

Input: the user uploads CSV/JSON log file(s) in the dashboard.
Required fields: time, ip, user, status
"""
import sqlite3
from datetime import timedelta
from pathlib import Path

import pandas as pd
import streamlit as st

PRIVILEGED = {"admin", "root", "administrator"}
DB_PATH = Path(__file__).with_name("siem.db")


# ---------- 1. Load uploaded files ----------
def load_files(files):
    """Read every uploaded CSV/JSON file and combine them into one table."""
    frames = []
    for f in files:
        try:
            if f.name.lower().endswith(".json"):
                frames.append(pd.read_json(f))
            else:
                frames.append(pd.read_csv(f))
        except Exception as e:
            st.error(f"Could not read {f.name}: {e}")
    if not frames:
        return None
    return pd.concat(frames, ignore_index=True).drop_duplicates()


# ---------- 2. Normalize fields ----------
def normalize(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.columns = [c.strip().lower() for c in df.columns]

    required = {"time", "ip", "user", "status"}
    if not required.issubset(df.columns):
        st.error(f"Logs must have fields: {', '.join(sorted(required))}")
        st.stop()

    try:
        df["time"] = pd.to_datetime(df["time"])
    except Exception:
        st.error("Could not read the 'time' field. Use a format like 2026-10-14 09:00:00.")
        st.stop()
    df["status"] = df["status"].astype(str).str.strip().str.lower().replace(
        {"failed": "fail", "failure": "fail", "denied": "fail", "invalid": "fail",
         "successful": "success", "ok": "success", "accepted": "success"})
    return df.sort_values("time").reset_index(drop=True)


# ---------- 3. Rules / correlation + dedup ----------
def detect(df: pd.DataFrame, threshold: int = 5, window_min: int = 5):
    """Alert when one IP has `threshold`+ failed logins within `window_min` minutes.
    Repeated events from the same burst are merged into ONE alert.
    Correlation: a successful login from the same IP right after the burst."""
    window = timedelta(minutes=window_min)
    fails = df[df["status"] == "fail"]
    alerts, evidence = [], {}

    for ip, g in fails.groupby("ip"):
        times = g["time"].tolist()
        i = 0
        while i < len(times):
            j = i
            while j + 1 < len(times) and times[j + 1] - times[i] <= window:
                j += 1

            if j - i + 1 >= threshold:
                # extend the burst while attempts keep coming (dedup)
                k = j
                while k + 1 < len(times) and times[k + 1] - times[k] <= window:
                    k += 1

                count = k - i + 1
                first, last = times[i], times[k]
                users = sorted(g.iloc[i:k + 1]["user"].unique())

                after = df[(df["ip"] == ip) & (df["status"] == "success")
                           & (df["time"] > last) & (df["time"] <= last + window)]
                compromised = not after.empty

                # ---- severity (rule-based) ----
                severity = "High" if (compromised or count >= 10) else "Medium"

                alert_id = len(alerts) + 1
                alerts.append({
                    "alert_id": alert_id,
                    "ip": ip,
                    "failed_attempts": count,
                    "first_seen": first,
                    "last_seen": last,
                    "users_targeted": ", ".join(users),
                    "success_after_burst": compromised,
                    "severity": severity,
                    "rule": f"{threshold}+ failed logins within {window_min} min",
                })
                end = after["time"].max() if compromised else last
                evidence[alert_id] = df[(df["ip"] == ip)
                                        & (df["time"] >= first)
                                        & (df["time"] <= end)]
                i = k + 1
            else:
                i += 1
    return pd.DataFrame(alerts), evidence


# ---------- 4. Optional anomaly / risk score (explainable) ----------
def risk_score(a):
    """Simple 0-100 score added AFTER rule detection. Returns (score, breakdown)
    so the dashboard can show exactly which features pushed the score up."""
    minutes = max((a["last_seen"] - a["first_seen"]).total_seconds() / 60, 0.5)
    rate = a["failed_attempts"] / minutes
    users = [u.strip() for u in a["users_targeted"].split(",")]

    parts = {
        "Attempt rate (fails/min, max 40)": round(min(rate / 10, 1) * 40, 1),
        "Total failed attempts (max 20)": round(min(a["failed_attempts"] / 20, 1) * 20, 1),
        "Users targeted (max 15)": round(min(len(users) / 5, 1) * 15, 1),
        "Privileged account targeted (10)": 10.0 if any(u in PRIVILEGED for u in users) else 0.0,
        "Success after burst (15)": 15.0 if a["success_after_burst"] else 0.0,
    }
    return round(float(sum(parts.values())), 1), parts


# ---------- 5. Analyst summary (template text, NOT AI) ----------
def summarize(a) -> str:
    secs = max((a["last_seen"] - a["first_seen"]).total_seconds(), 1)
    text = (f"IP {a['ip']} made {a['failed_attempts']} failed logins in "
            f"{secs / 60:.1f} minutes, targeting: {a['users_targeted']}. "
            "This pattern matches a brute-force / password-guessing attack.")
    if a["success_after_burst"]:
        text += (" A successful login from the same IP followed the burst, so the "
                 "account may be compromised. Reset the password and review the session.")
    else:
        text += " No successful login followed. Consider blocking the IP or adding rate limiting."
    return text


# ---------- 6. SQLite storage (history, no duplicates) ----------
def save_alerts(alerts: pd.DataFrame, db_path=DB_PATH) -> int:
    """Store alerts in SQLite. UNIQUE key means saving twice never duplicates an alert."""
    con = sqlite3.connect(db_path)
    con.execute("""CREATE TABLE IF NOT EXISTS alerts (
        ip TEXT, first_seen TEXT, last_seen TEXT, failed_attempts INTEGER,
        users_targeted TEXT, severity TEXT, risk_score REAL, rule TEXT,
        UNIQUE(ip, first_seen, last_seen))""")
    new = 0
    for _, a in alerts.iterrows():
        cur = con.execute(
            "INSERT OR IGNORE INTO alerts VALUES (?,?,?,?,?,?,?,?)",
            (a["ip"], str(a["first_seen"]), str(a["last_seen"]),
             int(a["failed_attempts"]), a["users_targeted"], a["severity"],
             float(a["risk_score"]), a["rule"]))
        new += cur.rowcount
    con.commit()
    con.close()
    return new


def load_history(db_path=DB_PATH) -> pd.DataFrame:
    if not Path(db_path).exists():
        return pd.DataFrame()
    con = sqlite3.connect(db_path)
    try:
        return pd.read_sql("SELECT * FROM alerts ORDER BY first_seen", con)
    except Exception:
        return pd.DataFrame()
    finally:
        con.close()


def clear_history(db_path=DB_PATH):
    if not Path(db_path).exists():
        return
    con = sqlite3.connect(db_path)
    try:
        con.execute("DELETE FROM alerts")
        con.commit()
    except sqlite3.OperationalError:
        pass
    finally:
        con.close()


# ---------- 7. Interactive dashboard ----------
def main():
    st.set_page_config(page_title="AI-Assisted Mini-SIEM", layout="wide")
    st.title("AI-Assisted Mini-SIEM")
    st.caption("Sample logs → normalize → rules/correlation → severity → dashboard/report. "
               "Detection uses fixed rules (not AI); the optional risk score is explainable.")

    # ----- load data (user uploads only) -----
    files = st.file_uploader("Upload your log file(s) (CSV or JSON)",
                             type=["csv", "json"], accept_multiple_files=True)
    if not files:
        st.info("👆 Upload one or more log files to start. Nothing is analysed until you do.")
        st.write("**Required fields** (any order, header names are case-insensitive):")
        st.dataframe(pd.DataFrame({
            "time": ["2026-10-14 09:00:00", "2026-10-14 09:00:20"],
            "ip": ["203.0.113.50", "203.0.113.50"],
            "user": ["admin", "admin"],
            "status": ["fail", "fail"]}), hide_index=True)
        st.caption("status is `success` or `fail`. A JSON file should be a list of records, "
                   "e.g. [{\"time\": \"...\", \"ip\": \"...\", \"user\": \"...\", "
                   "\"status\": \"fail\"}].")
        st.stop()
    raw = load_files(files)
    if raw is None:
        st.stop()
    df = normalize(raw)
    st.success(f"Loaded {len(df)} events from {len(files)} file(s).")

    # ----- sidebar: rule controls -----
    st.sidebar.header("Detection rule")
    threshold = st.sidebar.slider("Failed logins needed", 2, 20, 5)
    window_min = st.sidebar.slider("Time window (minutes)", 1, 60, 5)
    st.sidebar.info(f"Alert when one IP has **{threshold}+** failed logins "
                    f"within **{window_min} min**.")
    st.sidebar.header("Alert filters")
    sev_filter = st.sidebar.multiselect("Severity", ["High", "Medium"],
                                        default=["High", "Medium"])
    show_score = st.sidebar.checkbox("Show optional risk score", value=True)

    # ----- detect + score -----
    alerts, evidence = detect(df, threshold, window_min)
    breakdowns = {}
    if not alerts.empty:
        scores = []
        for _, a in alerts.iterrows():
            s, parts = risk_score(a)
            scores.append(s)
            breakdowns[a["alert_id"]] = parts
        alerts["risk_score"] = scores

    # ----- sidebar filters that depend on the alerts -----
    min_risk = 0
    ip_filter = []
    if not alerts.empty:
        ip_filter = st.sidebar.multiselect("IP address", sorted(alerts["ip"].unique()),
                                           default=sorted(alerts["ip"].unique()))
        if show_score:
            min_risk = st.sidebar.slider("Minimum risk score", 0, 100, 0)
        alerts_f = alerts[alerts["severity"].isin(sev_filter)
                          & alerts["ip"].isin(ip_filter)
                          & (alerts["risk_score"] >= min_risk)]
    else:
        alerts_f = alerts

    tab_over, tab_alerts, tab_logs, tab_hist = st.tabs(
        ["📊 Overview", "🚨 Alerts", "📜 Log explorer", "🗄️ History"])

    # ----- Overview tab -----
    with tab_over:
        fails = df[df["status"] == "fail"]
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total events", len(df))
        c2.metric("Failed logins", len(fails))
        c3.metric("Alerts", len(alerts_f), delta=f"{len(alerts_f) - len(alerts)} filtered"
                  if len(alerts_f) != len(alerts) else None, delta_color="off")
        c4.metric("High severity", int((alerts_f["severity"] == "High").sum())
                  if not alerts_f.empty else 0)

        left, right = st.columns(2)
        with left:
            st.subheader("Failed logins over time (per 5 min)")
            if fails.empty:
                st.write("No failed logins.")
            else:
                per_time = fails.set_index("time").resample("5min").size()
                st.line_chart(per_time.rename("failed logins").to_frame())
        with right:
            st.subheader("Top IPs by failed logins")
            if fails.empty:
                st.write("No failed logins.")
            else:
                top = fails.groupby("ip").size().sort_values(ascending=False).head(10)
                st.bar_chart(top.rename("failed logins").to_frame())
        st.caption("Try the sidebar: changing the threshold or time window re-runs the "
                   "detection rule on your data instantly.")

    # ----- Alerts tab -----
    with tab_alerts:
        if alerts.empty:
            st.success("No alerts triggered with the current rule. "
                       "Try lowering the threshold or widening the window.")
        elif alerts_f.empty:
            st.warning("Alerts exist, but none match your filters.")
        else:
            shown = alerts_f if show_score else alerts_f.drop(columns=["risk_score"])
            cfg = {}
            if show_score:
                cfg["risk_score"] = st.column_config.ProgressColumn(
                    "risk_score", min_value=0, max_value=100, format="%.1f")
            st.dataframe(shown, width="stretch", hide_index=True, column_config=cfg)

            b1, b2, _ = st.columns([1, 1, 3])
            b1.download_button("⬇️ Download report (CSV)",
                               shown.to_csv(index=False), "alerts_report.csv")
            if b2.button("💾 Save to history"):
                n = save_alerts(alerts_f)
                st.success(f"Saved {n} new alert(s) to SQLite "
                           f"({len(alerts_f) - n} already stored).")

            st.subheader("Investigate an alert")
            ids = alerts_f["alert_id"].tolist()
            labels = {r["alert_id"]: f"Alert {r['alert_id']} - {r['ip']} ({r['severity']})"
                      for _, r in alerts_f.iterrows()}
            chosen = st.selectbox("Pick an alert", ids, format_func=lambda x: labels[x])
            a = alerts_f[alerts_f["alert_id"] == chosen].iloc[0]

            st.info(summarize(a))
            if show_score:
                st.write(f"**Risk score: {a['risk_score']} / 100**. "
                         "Points contributed by each feature:")
                bd = breakdowns[chosen]
                st.bar_chart(pd.DataFrame({"points": list(bd.values())},
                                          index=list(bd.keys())), horizontal=True)
            st.write("Log events that triggered this alert (evidence):")
            st.dataframe(evidence[chosen], width="stretch", hide_index=True)

    # ----- Log explorer tab -----
    with tab_logs:
        f1, f2, f3 = st.columns(3)
        status_sel = f1.multiselect("Status", sorted(df["status"].unique()),
                                    default=sorted(df["status"].unique()))
        ip_sel = f2.multiselect("IP", sorted(df["ip"].unique()))
        user_q = f3.text_input("Search user")

        view = df[df["status"].isin(status_sel)]
        if ip_sel:
            view = view[view["ip"].isin(ip_sel)]
        if user_q:
            view = view[view["user"].astype(str).str.contains(user_q, case=False, na=False)]
        st.write(f"Showing **{len(view)}** of {len(df)} events")
        st.dataframe(view, width="stretch", hide_index=True)

    # ----- History tab -----
    with tab_hist:
        hist = load_history()
        if hist.empty:
            st.write("No stored alerts yet. Use **Save to history** in the Alerts tab.")
        else:
            st.dataframe(hist, width="stretch", hide_index=True)
            if st.button("🗑️ Clear history"):
                clear_history()
                st.rerun()


if __name__ == "__main__":
    main()