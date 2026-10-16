import sqlite3
import io
import os
import hmac
import random
import time
from pathlib import Path
from datetime import datetime, timedelta

import pandas as pd
import streamlit as st

# =========================================================
# LABSENTINEL - REAL-TIME SIMULATOR
# Python event simulator | 5-second refresh | SQLite reviews
# =========================================================

st.set_page_config(
    page_title="LabSentinel | Security Operations",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

DB_FILE = Path(__file__).with_name("incidents.db")
REVIEW_STATUSES = ["Needs Review", "Confirmed Suspicious", "False Positive"]
CSV_BLOCK_MINUTES = 15
REQUIRED_COLUMNS = {
    "event_id", "username", "timestamp", "ip_address",
    "login_status", "lab_id",
}
MULTI_ACCOUNT_THRESHOLD = 3
MULTI_ACCOUNT_WINDOW_MINUTES = 10
REFRESH_SECONDS = 5

# ---------------- STYLE ----------------
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Manrope:wght@400;500;600;700;800&display=swap');
:root{
  --bg:#0b0e0b;
  --panel:#141914;
  --panel2:#1b231b;
  --line:#303d30;
  --sage:#a8bd98;
  --sage-strong:#c4d6b4;
  --sage-soft:#dce7d3;
  --muted:#a4afa0;
  --text:#edf2e9;
  --danger:#e08d83;
  --warning:#d9b875;
}
.stApp{background:var(--bg);font-family:'DM Sans',sans-serif;color:var(--text)}
[data-testid="stHeader"]{background:var(--bg)}
[data-testid="stSidebar"]{background:#101410;border-right:1px solid var(--line)}
[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] h2{font-family:'Manrope',sans-serif;letter-spacing:-.025em}
.block-container{max-width:1500px;padding-top:1.35rem;padding-bottom:3rem}
h1,h2,h3{font-family:'Manrope',sans-serif;color:var(--text)!important;letter-spacing:-.025em}
p,label,[data-testid="stCaptionContainer"]{color:#b8c2b3}
[data-testid="stMetric"]{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:17px 18px;min-height:108px;box-shadow:none}
[data-testid="stMetricLabel"]{color:#aeb9a7!important;font-size:12px!important;letter-spacing:.045em;text-transform:uppercase}
[data-testid="stMetricValue"]{color:var(--sage-soft)!important;font-family:'Manrope',sans-serif;font-weight:800}
[data-testid="stMetricDelta"]{font-size:11px}
[data-testid="stExpander"]{background:var(--panel);border:1px solid var(--line);border-radius:10px}
[data-testid="stFileUploader"]{background:#111711;border:1px dashed #60735a;border-radius:12px;padding:12px}
[data-testid="stDataFrame"],[data-testid="stDataEditor"]{border:1px solid var(--line);border-radius:10px;overflow:hidden;background:var(--panel)}
.stButton>button,.stDownloadButton>button{border-radius:8px;border:1px solid #829b76;background:#283629;color:#f0f5ec;font-weight:700;min-height:2.65rem;box-shadow:none;transition:none}
.stButton>button:hover,.stDownloadButton>button:hover{border:1px solid #829b76;background:#283629;color:#f0f5ec;transform:none;box-shadow:none}
.stButton>button:focus,.stDownloadButton>button:focus{outline:2px solid var(--sage);outline-offset:2px}
[data-testid="stRadio"] label,[data-testid="stSelectbox"] label{color:#c7d0c2}
hr{border-color:var(--line)!important}
.ls-section{display:flex;align-items:center;gap:13px;margin:27px 0 14px;padding:0 0 0 12px;border-left:3px solid var(--sage)}
.ls-section small{display:block;color:var(--sage);text-transform:uppercase;letter-spacing:.14em;font-size:10px;font-weight:800;margin-bottom:4px}
.ls-section strong{color:var(--text);font-family:'Manrope',sans-serif;font-size:22px;letter-spacing:-.025em}
.ls-note{padding:13px 15px;border-radius:10px;background:#151c15;border:1px solid #303d30;color:#d5dfcf;font-size:13px}
.ls-footer{margin-top:34px;padding:17px 12px;border-top:1px solid var(--line);color:#9ca895;font-size:11px;text-align:center;letter-spacing:.025em}
.ls-sidebar-brand{padding:15px 13px;margin:3px 0 20px;border:1px solid #394737;border-radius:11px;background:#171e16}
.ls-sidebar-brand .brand{font-family:'Manrope',sans-serif;color:#eaf1e4;font-weight:800;font-size:21px;letter-spacing:-.035em}
.ls-sidebar-brand .sub{color:var(--sage);font-size:10px;letter-spacing:.13em;text-transform:uppercase;margin-top:5px}
.ls-chip{display:inline-block;border:1px solid #52644c;border-radius:6px;padding:6px 9px;margin:3px 5px 0 0;color:#d4e2cb;font-size:10px;letter-spacing:.06em;background:#151c15}
[data-testid="stAlert"]{border-radius:10px}
@media(max-width:700px){.block-container{padding-top:.8rem}.ls-section strong{font-size:19px}}
</style>
""", unsafe_allow_html=True)

def heading(label, title):
    st.markdown(
        f'<div class="ls-section"><small>{label}</small><strong>{title}</strong></div>',
        unsafe_allow_html=True,
    )


# ---------------- DATABASE ----------------
def init_database():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS incident_reviews (
                alert_key TEXT PRIMARY KEY,
                review_status TEXT NOT NULL,
                review_notes TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # Separate table: block records never modify incident review history.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS csv_account_blocks (
                dataset_name TEXT NOT NULL,
                username TEXT NOT NULL,
                alert_key TEXT NOT NULL,
                blocked_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('BLOCKED', 'UNBLOCKED', 'EXPIRED')),
                blocked_by TEXT NOT NULL,
                unblocked_at TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (dataset_name, username)
            )
        """)
        # Added from app3.py: containment records are separate from review history.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS blocklist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_type TEXT NOT NULL,
                target_value TEXT NOT NULL,
                reason TEXT NOT NULL,
                alert_key TEXT,
                approved_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                admin TEXT,
                action TEXT,
                target TEXT,
                alert_key TEXT
            )
        """)


def load_reviews():
    with sqlite3.connect(DB_FILE) as conn:
        return pd.read_sql_query("SELECT * FROM incident_reviews", conn)


def save_reviews(table):
    with sqlite3.connect(DB_FILE) as conn:
        for _, row in table.iterrows():
            conn.execute("""
                INSERT INTO incident_reviews
                    (alert_key, review_status, review_notes, updated_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(alert_key) DO UPDATE SET
                    review_status=excluded.review_status,
                    review_notes=excluded.review_notes,
                    updated_at=CURRENT_TIMESTAMP
            """, (str(row["alert_key"]), str(row["review_status"]), str(row["review_notes"])))


init_database()


def _block_timestamp(value=None):
    """Use local, timezone-naive timestamps consistently with the dashboard UI."""
    return (value or datetime.now()).replace(microsecond=0)


def expire_csv_blocks():
    """Mark expired CSV-demo blocks; called when the CSV workspace is rendered."""
    now = _block_timestamp().isoformat(sep=" ")
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""
            UPDATE csv_account_blocks
            SET status='EXPIRED'
            WHERE status='BLOCKED' AND expires_at <= ?
        """, (now,))


def get_csv_block(dataset_name, username):
    expire_csv_blocks()
    with sqlite3.connect(DB_FILE) as conn:
        row = conn.execute("""
            SELECT dataset_name, username, alert_key, blocked_at, expires_at,
                   status, blocked_by, unblocked_at
            FROM csv_account_blocks WHERE dataset_name=? AND username=?
        """, (str(dataset_name), str(username))).fetchone()
    if row is None:
        return None
    return dict(zip([
        "dataset_name", "username", "alert_key", "blocked_at", "expires_at",
        "status", "blocked_by", "unblocked_at"
    ], row))


def block_csv_account(dataset_name, username, alert_key, admin_id):
    """Create/refresh a 15-minute response block record for a HIGH-risk CSV alert."""
    now = _block_timestamp()
    expires = now + timedelta(minutes=CSV_BLOCK_MINUTES)
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""
            INSERT INTO csv_account_blocks
                (dataset_name, username, alert_key, blocked_at, expires_at,
                 status, blocked_by, unblocked_at)
            VALUES (?, ?, ?, ?, ?, 'BLOCKED', ?, '')
            ON CONFLICT(dataset_name, username) DO UPDATE SET
                alert_key=excluded.alert_key,
                blocked_at=excluded.blocked_at,
                expires_at=excluded.expires_at,
                status='BLOCKED',
                blocked_by=excluded.blocked_by,
                unblocked_at=''
        """, (str(dataset_name), str(username), str(alert_key),
              now.isoformat(sep=" "), expires.isoformat(sep=" "), str(admin_id)))
    return expires


def unblock_csv_account(dataset_name, username):
    """Manually remove an active CSV-demo block."""
    now = _block_timestamp().isoformat(sep=" ")
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.execute("""
            UPDATE csv_account_blocks
            SET status='UNBLOCKED', unblocked_at=?
            WHERE dataset_name=? AND username=? AND status='BLOCKED'
        """, (now, str(dataset_name), str(username)))
    return cur.rowcount > 0


def get_dataset_blocks(dataset_name):
    expire_csv_blocks()
    with sqlite3.connect(DB_FILE) as conn:
        return pd.read_sql_query("""
            SELECT username, alert_key, blocked_at, expires_at, status,
                   blocked_by, unblocked_at
            FROM csv_account_blocks WHERE dataset_name=?
            ORDER BY blocked_at DESC
        """, conn, params=(str(dataset_name),))


def admin_password_configured():
    """Admin password must be configured outside source code."""
    try:
        secret = st.secrets.get("LABSENTINEL_ADMIN_PASSWORD", "")
    except Exception:
        secret = ""
    return str(secret or os.getenv("LABSENTINEL_ADMIN_PASSWORD", ""))


# ---------------- CONTAINMENT + AUDIT HELPERS (from app3.py) ----------------
def _now():
    return datetime.now().isoformat(timespec="seconds")


def _audit(conn, admin, action, target, alert_key=None):
    conn.execute(
        "INSERT INTO audit_log (ts, admin, action, target, alert_key) "
        "VALUES (?, ?, ?, ?, ?)",
        (_now(), admin, action, target, alert_key),
    )


def block_target(target_type, value, reason, alert_key, admin, minutes):
    now = datetime.now()
    expires = now + timedelta(minutes=int(minutes))
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""
            INSERT INTO blocklist
                (target_type, target_value, reason, alert_key,
                 approved_by, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            target_type, str(value), str(reason), str(alert_key), str(admin),
            now.isoformat(timespec="seconds"),
            expires.isoformat(timespec="seconds"),
        ))
        _audit(
            conn, admin, f"BLOCK {int(minutes)} min",
            f"{target_type}:{value}", alert_key,
        )
    return expires


def is_blocked(target_type, value):
    value = str(value).strip()
    if not value:
        return False
    now = _now()
    with sqlite3.connect(DB_FILE) as conn:
        row = conn.execute("""
            SELECT 1 FROM blocklist
            WHERE target_type = ? AND target_value = ?
              AND active = 1 AND expires_at > ?
        """, (target_type, value, now)).fetchone()
    return row is not None


def unblock(block_id, admin):
    with sqlite3.connect(DB_FILE) as conn:
        row = conn.execute(
            "SELECT target_type, target_value, alert_key "
            "FROM blocklist WHERE id = ? AND active = 1",
            (int(block_id),),
        ).fetchone()
        if not row:
            return False
        conn.execute(
            "UPDATE blocklist SET active = 0 WHERE id = ?",
            (int(block_id),),
        )
        _audit(conn, admin, "UNBLOCK", f"{row[0]}:{row[1]}", row[2])
    return True


def load_active_blocks():
    now = _now()
    with sqlite3.connect(DB_FILE) as conn:
        return pd.read_sql_query("""
            SELECT id, target_type, target_value, reason,
                   approved_by, created_at, expires_at
            FROM blocklist
            WHERE active = 1 AND expires_at > ?
            ORDER BY id DESC
        """, conn, params=(now,))


def load_audit_log():
    with sqlite3.connect(DB_FILE) as conn:
        return pd.read_sql_query(
            "SELECT * FROM audit_log ORDER BY id DESC", conn
        )


# ---------------- DETECTION RULES ----------------
def analyze_logs(uploaded_df, lab_open_hour, lab_close_hour):
    df = uploaded_df.copy()
    missing = REQUIRED_COLUMNS - set(df.columns)
    if missing:
        raise ValueError("Missing required columns: " + ", ".join(sorted(missing)))
    if df.empty:
        raise ValueError("No login records available.")

    for col in ["event_id", "username", "lab_id", "ip_address"]:
        if df[col].isna().any():
            raise ValueError(f"Some values are missing in {col}.")
        df[col] = df[col].astype(str).str.strip()
        if (df[col] == "").any():
            raise ValueError(f"Some values are empty in {col}.")
    if df["event_id"].duplicated().any():
        raise ValueError("Event IDs must be unique.")

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    if df["timestamp"].isna().any():
        raise ValueError("Some timestamps are invalid.")
    df["login_status"] = df["login_status"].astype(str).str.strip().str.upper()
    if not df["login_status"].isin(["SUCCESS", "FAILURE"]).all():
        raise ValueError("Login status must be SUCCESS or FAILURE.")

    df = df.sort_values("timestamp").reset_index(drop=True)
    alerts = []

    # Rule 1: two or more failures followed by success for same user/lab in 10 min
    for (username, lab_id), group in df.groupby(["username", "lab_id"]):
        group = group.sort_values("timestamp")
        for _, row in group.iterrows():
            if row["login_status"] != "SUCCESS":
                continue
            previous = group[
                (group["timestamp"] < row["timestamp"])
                & (group["timestamp"] >= row["timestamp"] - pd.Timedelta(minutes=10))
            ]
            failures = previous[previous["login_status"] == "FAILURE"]
            if len(failures) >= 2:
                evidence = failures["event_id"].tolist() + [row["event_id"]]
                alerts.append({
                    "event_id": row["event_id"], "username": username,
                    "lab_id": lab_id, "timestamp": row["timestamp"],
                    "ip_address": row["ip_address"],
                    "rule_triggered": "Repeated failures followed by success",
                    "evidence": ", ".join(map(str, evidence)),
                    "risk_level": "HIGH",
                    "suggested_action": "Verify the login with the lab administrator",
                })

    # Rule 2: successful login outside lab hours
    for _, row in df[df["login_status"] == "SUCCESS"].iterrows():
        hour = row["timestamp"].hour
        if hour < lab_open_hour or hour >= lab_close_hour:
            alerts.append({
                "event_id": row["event_id"], "username": row["username"],
                "lab_id": row["lab_id"], "timestamp": row["timestamp"],
                "ip_address": row["ip_address"],
                "rule_triggered": "Successful login outside lab hours",
                "evidence": str(row["event_id"]), "risk_level": "MEDIUM",
                "suggested_action": "Confirm whether after-hours access was authorized",
            })

    # Rule 3: three distinct successful usernames from same IP/lab in 10 minutes
    successful = df[df["login_status"] == "SUCCESS"].copy()
    for (ip_address, lab_id), group in successful.groupby(["ip_address", "lab_id"]):
        group = group.sort_values("timestamp").reset_index(drop=True)
        for idx, row in group.iterrows():
            start = row["timestamp"] - pd.Timedelta(minutes=MULTI_ACCOUNT_WINDOW_MINUTES)
            window = group[(group["timestamp"] >= start) & (group["timestamp"] <= row["timestamp"])]
            if window["username"].nunique() < MULTI_ACCOUNT_THRESHOLD:
                continue
            previous_window = group.iloc[:idx]
            previous_window = previous_window[
                (previous_window["timestamp"] >= start)
                & (previous_window["timestamp"] < row["timestamp"])
            ]
            if previous_window["username"].nunique() >= MULTI_ACCOUNT_THRESHOLD:
                continue
            usernames = sorted(window["username"].unique().tolist())
            alerts.append({
                "event_id": row["event_id"], "username": row["username"],
                "lab_id": lab_id, "timestamp": row["timestamp"],
                "ip_address": ip_address,
                "rule_triggered": "Multiple accounts from the same IP",
                "evidence": ", ".join(window["event_id"].tolist()),
                "risk_level": "MEDIUM",
                "suggested_action": (
                    "Review whether shared-IP activity is expected. Accounts in this window: "
                    + ", ".join(usernames)
                ),
            })

    # Rule 4: five consecutive failed attempts for the same username, IP and lab
    # within four minutes, with no successful login interrupting the sequence.
    for (username, ip_address, lab_id), group in df.groupby(["username", "ip_address", "lab_id"]):
        group = group.sort_values("timestamp").reset_index(drop=True)
        for idx in range(len(group)):
            window_start = group.loc[idx, "timestamp"]
            window_end = window_start + pd.Timedelta(minutes=4)
            window = group[(group["timestamp"] >= window_start) & (group["timestamp"] <= window_end)]
            statuses = window["login_status"].tolist()
            consecutive_failures = []
            for _, event in window.iterrows():
                if event["login_status"] == "SUCCESS":
                    break
                consecutive_failures.append(event)
                if len(consecutive_failures) == 5:
                    evidence_ids = [str(item["event_id"]) for item in consecutive_failures]
                    alerts.append({
                        "event_id": str(consecutive_failures[-1]["event_id"]),
                        "username": username,
                        "lab_id": lab_id,
                        "timestamp": consecutive_failures[-1]["timestamp"],
                        "ip_address": ip_address,
                        "rule_triggered": "Repeated login attempts ended in failure",
                        "evidence": ", ".join(evidence_ids),
                        "risk_level": "LOW",
                        "suggested_action": "Review repeated failed logins and verify whether the user needs assistance",
                    })
                    break

    alert_df = pd.DataFrame(alerts)
    if not alert_df.empty:
        alert_df["alert_key"] = alert_df.apply(
            lambda r: f"{r['event_id']}|{r['rule_triggered']}", axis=1
        )
        alert_df = alert_df.drop_duplicates(subset=["alert_key"]).reset_index(drop=True)
    return df, alert_df



def build_incident_pdf(report_df, report_title="Security Incident Report", source_mode="LabSentinel", containment_df=None, audit_df=None):
    """Build a branded, multi-page PDF report with a vector LabSentinel shield logo."""
    from xml.sax.saxutils import escape
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT, TA_CENTER
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
    )

    buffer = io.BytesIO()
    page_width, page_height = A4
    navy = colors.HexColor("#171D17")
    cyan = colors.HexColor("#A8BD98")
    pale = colors.HexColor("#EEF3E9")
    ink = colors.HexColor("#202820")
    muted = colors.HexColor("#687365")
    border = colors.HexColor("#D3DDCD")

    def draw_brand(canvas, doc):
        canvas.saveState()
        # Header band and a simple vector shield logo (no external image required).
        canvas.setFillColor(navy)
        canvas.rect(0, page_height - 27*mm, page_width, 27*mm, stroke=0, fill=1)
        sx, sy = 17*mm, page_height - 13.5*mm
        path = canvas.beginPath()
        path.moveTo(sx, sy + 6*mm)
        path.lineTo(sx + 5.5*mm, sy + 4*mm)
        path.lineTo(sx + 5*mm, sy - 2*mm)
        path.lineTo(sx, sy - 6*mm)
        path.lineTo(sx - 5*mm, sy - 2*mm)
        path.lineTo(sx - 5.5*mm, sy + 4*mm)
        path.close()
        canvas.setFillColor(cyan)
        canvas.drawPath(path, stroke=0, fill=1)
        canvas.setStrokeColor(colors.white)
        canvas.setLineWidth(1.5)
        canvas.line(sx - 2.4*mm, sy, sx - .5*mm, sy - 2*mm)
        canvas.line(sx - .5*mm, sy - 2*mm, sx + 2.8*mm, sy + 2*mm)
        canvas.setFillColor(colors.white)
        canvas.setFont("Helvetica-Bold", 15)
        canvas.drawString(27*mm, page_height - 11*mm, "LabSentinel")
        canvas.setFillColor(colors.HexColor("#D8E5D0"))
        canvas.setFont("Helvetica", 8)
        canvas.drawString(27*mm, page_height - 17*mm, "EXPLAINABLE ACCESS ALERTS FOR SHARED LABS")
        canvas.setStrokeColor(border)
        canvas.line(15*mm, 15*mm, page_width - 15*mm, 15*mm)
        canvas.setFillColor(muted)
        canvas.setFont("Helvetica", 8)
        canvas.drawString(15*mm, 10*mm, "CONFIDENTIAL - For authorized review")
        canvas.drawRightString(page_width - 15*mm, 10*mm, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        buffer, pagesize=A4, rightMargin=16*mm, leftMargin=16*mm,
        topMargin=34*mm, bottomMargin=21*mm, title=report_title,
        author="LabSentinel Security Operations",
    )
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="ReportTitle", parent=styles["Title"],
        fontName="Helvetica-Bold", fontSize=20, leading=24, textColor=navy,
        alignment=TA_LEFT, spaceAfter=4*mm))
    styles.add(ParagraphStyle(name="Subtle", parent=styles["Normal"],
        fontSize=8.5, leading=12, textColor=muted, spaceAfter=2*mm))
    styles.add(ParagraphStyle(name="SectionHeadingLS", parent=styles["Heading2"],
        fontName="Helvetica-Bold", fontSize=12, leading=15, textColor=navy,
        spaceBefore=4*mm, spaceAfter=2*mm))
    styles.add(ParagraphStyle(name="FieldLabelLS", parent=styles["Normal"],
        fontName="Helvetica-Bold", fontSize=8, leading=10, textColor=muted))
    styles.add(ParagraphStyle(name="FieldValueLS", parent=styles["Normal"],
        fontSize=8.5, leading=12, textColor=ink, wordWrap="CJK"))
    styles.add(ParagraphStyle(name="SmallLS", parent=styles["Normal"],
        fontSize=8, leading=10, textColor=ink, wordWrap="CJK"))

    story = []
    story.append(Paragraph(escape(report_title), styles["ReportTitle"]))
    story.append(Paragraph(
        f"Generated: {datetime.now().strftime('%d %b %Y, %H:%M:%S')}  |  "
        f"Data source: {escape(source_mode)}  |  Total incidents: {len(report_df)}",
        styles["Subtle"]))
    story.append(Spacer(1, 3*mm))

    total = len(report_df)
    high = int((report_df["risk_level"] == "HIGH").sum()) if total and "risk_level" in report_df else 0
    medium = int((report_df["risk_level"] == "MEDIUM").sum()) if total and "risk_level" in report_df else 0
    low = int((report_df["risk_level"] == "LOW").sum()) if total and "risk_level" in report_df else 0
    review_pending = int((report_df["review_status"] == "Needs Review").sum()) if total and "review_status" in report_df else 0
    summary = Table([
        [Paragraph("TOTAL ALERTS", styles["FieldLabelLS"]), Paragraph("HIGH RISK", styles["FieldLabelLS"]), Paragraph("MEDIUM RISK", styles["FieldLabelLS"]), Paragraph("NEEDS REVIEW", styles["FieldLabelLS"])],
        [Paragraph(str(total), styles["ReportTitle"]), Paragraph(str(high), styles["ReportTitle"]), Paragraph(str(medium), styles["ReportTitle"]), Paragraph(str(review_pending), styles["ReportTitle"])],
    ], colWidths=[(page_width-32*mm)/4]*4)
    summary.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), pale), ("BOX", (0,0), (-1,-1), .6, border),
        ("INNERGRID", (0,0), (-1,-1), .4, border), ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("LEFTPADDING", (0,0), (-1,-1), 8), ("RIGHTPADDING", (0,0), (-1,-1), 6),
        ("TOPPADDING", (0,0), (-1,0), 7), ("BOTTOMPADDING", (0,0), (-1,0), 2),
        ("TOPPADDING", (0,1), (-1,1), 2), ("BOTTOMPADDING", (0,1), (-1,1), 6),
    ]))
    story.append(summary)
    story.append(Paragraph("Incident details", styles["SectionHeadingLS"]))

    if report_df.empty:
        story.append(Paragraph("No incidents were present in the selected report dataset.", styles["FieldValueLS"]))
    else:
        # A stacked incident card is easier to read/print than a very wide spreadsheet table.
        fields = [
            ("Event ID", "event_id"), ("Username", "username"),
            ("Lab", "lab_id"), ("Timestamp", "timestamp"),
            ("IP address", "ip_address"), ("Detection rule", "rule_triggered"),
            ("Risk level", "risk_level"), ("Evidence event IDs", "evidence"),
            ("Suggested action / reason", "suggested_action"),
            ("Review status", "review_status"), ("Administrator notes", "review_notes"),
        ]
        for idx, (_, row) in enumerate(report_df.iterrows(), start=1):
            risk = str(row.get("risk_level", "UNKNOWN"))
            risk_color = colors.HexColor("#B42318") if risk == "HIGH" else (colors.HexColor("#B45309") if risk == "MEDIUM" else ink)
            title = Table([[
                Paragraph(f"<b>Incident {idx:03d}</b>", styles["FieldValueLS"]),
                Paragraph(f'<font color="{risk_color.hexval()}"><b>{escape(risk)}</b></font>', styles["FieldValueLS"]),
            ]], colWidths=[(page_width-32*mm)*.72, (page_width-32*mm)*.28])
            title.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),pale),("BOX",(0,0),(-1,-1),.5,border),("VALIGN",(0,0),(-1,-1),"MIDDLE"),("LEFTPADDING",(0,0),(-1,-1),7),("TOPPADDING",(0,0),(-1,-1),6),("BOTTOMPADDING",(0,0),(-1,-1),6)]))
            story.append(KeepTogether([title, Spacer(1, 1.5*mm)]))
            detail_rows = []
            for label, key in fields:
                if key not in report_df.columns:
                    continue
                value = row.get(key, "")
                if pd.isna(value) or str(value).strip() == "":
                    value = "Not provided"
                detail_rows.append([Paragraph(escape(label), styles["FieldLabelLS"]), Paragraph(escape(str(value)), styles["SmallLS"])])
            detail_table = Table(detail_rows, colWidths=[43*mm, page_width-32*mm-43*mm], hAlign="LEFT")
            detail_table.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(0,-1),colors.HexColor("#F5F7F2")),
                ("GRID",(0,0),(-1,-1),.35,border), ("VALIGN",(0,0),(-1,-1),"TOP"),
                ("LEFTPADDING",(0,0),(-1,-1),6), ("RIGHTPADDING",(0,0),(-1,-1),6),
                ("TOPPADDING",(0,0),(-1,-1),4), ("BOTTOMPADDING",(0,0),(-1,-1),4),
            ]))
            story.append(detail_table)
            story.append(Spacer(1, 4*mm))

    # Containment and audit information is appended without changing incident details above.
    story.append(Paragraph("Containment actions", styles["SectionHeadingLS"]))
    if containment_df is None or containment_df.empty:
        story.append(Paragraph("No active containment blocks at report generation time.", styles["FieldValueLS"]))
    else:
        containment_fields = [
            ("Block ID", "id"), ("Target type", "target_type"),
            ("Target value", "target_value"), ("Reason", "reason"),
            ("Approved by", "approved_by"), ("Created at", "created_at"),
            ("Expires at", "expires_at"),
        ]
        for idx, (_, block_row) in enumerate(containment_df.iterrows(), start=1):
            story.append(Paragraph(f"Active block {idx:03d}", styles["FieldValueLS"]))
            block_rows = []
            for label, key in containment_fields:
                if key not in containment_df.columns:
                    continue
                value = block_row.get(key, "")
                if pd.isna(value) or str(value).strip() == "":
                    value = "Not provided"
                block_rows.append([Paragraph(escape(label), styles["FieldLabelLS"]), Paragraph(escape(str(value)), styles["SmallLS"])])
            block_table = Table(block_rows, colWidths=[43*mm, page_width-32*mm-43*mm], hAlign="LEFT")
            block_table.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (0,-1), colors.HexColor("#F5F7F2")),
                ("GRID", (0,0), (-1,-1), .35, border), ("VALIGN", (0,0), (-1,-1), "TOP"),
                ("LEFTPADDING", (0,0), (-1,-1), 6), ("RIGHTPADDING", (0,0), (-1,-1), 6),
                ("TOPPADDING", (0,0), (-1,-1), 4), ("BOTTOMPADDING", (0,0), (-1,-1), 4),
            ]))
            story.append(block_table)
            story.append(Spacer(1, 2*mm))

    story.append(Paragraph("Containment audit log", styles["SectionHeadingLS"]))
    if audit_df is None or audit_df.empty:
        story.append(Paragraph("No containment audit actions recorded.", styles["FieldValueLS"]))
    else:
        audit_columns = [
            ("Timestamp", "ts"), ("Administrator", "admin"),
            ("Action", "action"), ("Target", "target"), ("Alert key", "alert_key"),
        ]
        audit_data = [[Paragraph(label, styles["FieldLabelLS"]) for label, key in audit_columns if key in audit_df.columns]]
        included_audit_columns = [(label, key) for label, key in audit_columns if key in audit_df.columns]
        for _, audit_row in audit_df.iterrows():
            audit_data.append([
                Paragraph(escape("Not provided" if pd.isna(audit_row.get(key)) or str(audit_row.get(key, "")).strip() == "" else str(audit_row.get(key))), styles["SmallLS"])
                for label, key in included_audit_columns
            ])
        available_width = page_width - 32*mm
        col_widths = [available_width / max(len(included_audit_columns), 1)] * len(included_audit_columns)
        audit_table = Table(audit_data, colWidths=col_widths, repeatRows=1, hAlign="LEFT")
        audit_table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), pale), ("GRID", (0,0), (-1,-1), .35, border),
            ("VALIGN", (0,0), (-1,-1), "TOP"), ("LEFTPADDING", (0,0), (-1,-1), 4),
            ("RIGHTPADDING", (0,0), (-1,-1), 4), ("TOPPADDING", (0,0), (-1,-1), 4),
            ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ]))
        story.append(audit_table)

    story.append(Spacer(1, 2*mm))
    story.append(Paragraph("Detection rules are indicators for administrator review, not proof of malicious activity. Verify the evidence and lab context before taking action.", styles["Subtle"]))
    doc.build(story, onFirstPage=draw_brand, onLaterPages=draw_brand)
    return buffer.getvalue()


# ---------------- CSV-ONLY DASHBOARD ----------------
# Compact layout: no oversized hero banner. App identity remains in the sidebar.
with st.sidebar:
    st.markdown("""
    <div class="ls-sidebar-brand">
      <div class="brand">◈ LabSentinel</div>
      <div class="sub">SAGE EDITION · CSV ANALYSIS</div>
    </div>
    """, unsafe_allow_html=True)
    st.markdown("### Detection configuration")
    opening_hour = st.selectbox("Lab opening hour", list(range(24)), index=8,
                                format_func=lambda h: f"{h:02d}:00")
    closing_hour = st.selectbox("Lab closing hour", list(range(1, 25)), index=18,
                                format_func=lambda h: f"{h:02d}:00" if h < 24 else "24:00")
    st.caption("Rule 1 · Repeated failures followed by success")
    st.caption("Rule 2 · Successful login outside lab hours")
    st.caption("Rule 3 · Three accounts from one IP/lab within 10 minutes")
    st.caption("Rule 4 · Five consecutive failed attempts for the same user/IP/lab within 4 minutes")
    st.divider()
    st.caption("Only uploaded CSV records are analyzed. No login events are generated.")

if closing_hour <= opening_hour:
    st.error("Closing hour must be later than opening hour.")
    st.stop()

heading("DATA SOURCE", "Import your login dataset")
st.markdown('<div class="ls-note">Upload one or more existing CSV files. LabSentinel will analyze only the records inside the selected files; it will not append or generate events.</div>', unsafe_allow_html=True)
uploaded_files = st.file_uploader("Choose login CSV files", type=["csv"], accept_multiple_files=True, help="Required columns: event_id, username, timestamp, ip_address, login_status, lab_id")

if not uploaded_files:
    st.info("Upload demo_logs.csv, login_logs.csv, test_logs.csv, or multiple CSV files to begin.")
    st.markdown("""
    **Expected columns**
    `event_id` · `username` · `timestamp` · `ip_address` · `login_status` · `lab_id`
    """)
    st.stop()

try:
    frames = []
    source_names = []
    for uploaded_file in uploaded_files:
        file_df = pd.read_csv(uploaded_file)
        source_names.append(Path(uploaded_file.name).name)
        file_df["_labsentinel_source_file"] = Path(uploaded_file.name).name
        # Preserve original event IDs unless they collide across the selected files.
        frames.append(file_df)
    raw_df = pd.concat(frames, ignore_index=True)
    if raw_df["event_id"].astype(str).duplicated(keep=False).any():
        raw_df["event_id"] = raw_df.apply(
            lambda row: f"{Path(str(row['_labsentinel_source_file'])).stem}:{row['event_id']}", axis=1
        )
    df, alerts = analyze_logs(raw_df.drop(columns=["_labsentinel_source_file"], errors="ignore"), opening_hour, closing_hour)
except Exception as exc:
    st.error(f"Could not analyze the selected CSV file(s): {exc}")
    st.stop()

# Keep selected file identity in alert keys so reviews for different datasets do not collide.
dataset_name = ", ".join(source_names)
if not alerts.empty:
    alerts["alert_key"] = alerts["alert_key"].astype(str).map(
        lambda key: f"{dataset_name}|{key}"
    )

saved_reviews = load_reviews()
if not alerts.empty:
    alerts = alerts.merge(
        saved_reviews[["alert_key", "review_status", "review_notes"]],
        on="alert_key", how="left",
    )
    alerts["review_status"] = alerts["review_status"].fillna("Needs Review")
    alerts["review_notes"] = alerts["review_notes"].fillna("")
else:
    alerts["review_status"] = pd.Series(dtype=str)
    alerts["review_notes"] = pd.Series(dtype=str)

heading("OVERVIEW", "Dataset at a glance")
m1, m2, m3, m4 = st.columns(4)
m1.metric("Login Records", len(df))
m2.metric("Successful Logins", int((df["login_status"] == "SUCCESS").sum()))
m3.metric("Detected Alerts", len(alerts))
m4.metric("High Risk", int((alerts["risk_level"] == "HIGH").sum()) if not alerts.empty else 0)
st.caption(f"Dataset: {dataset_name} · Analysis uses uploaded records only · {datetime.now().strftime('%d %b %Y, %H:%M')}")

heading("EVENT REGISTER", "Uploaded login records")
st.dataframe(df, use_container_width=True, hide_index=True)

heading("DETECTION CENTER", "Explainable incidents")
if alerts.empty:
    st.success("No alerts were triggered by the selected detection rules for this dataset.")
else:
    f1, f2 = st.columns(2)
    with f1:
        risk_options = sorted(alerts["risk_level"].unique().tolist())
        selected_risks = st.multiselect("Risk level", risk_options, default=risk_options, key="csv_risks")
    with f2:
        status_options = REVIEW_STATUSES
        selected_statuses = st.multiselect("Review status", status_options, default=status_options, key="csv_statuses")

    filtered = alerts[
        alerts["risk_level"].isin(selected_risks)
        & alerts["review_status"].isin(selected_statuses)
    ].copy()

    st.dataframe(
        filtered[["event_id", "username", "lab_id", "timestamp", "ip_address",
                  "rule_triggered", "risk_level", "review_status"]],
        use_container_width=True, hide_index=True
    )

    if not filtered.empty:
        heading("EVIDENCE", "Incident timeline")
        incident_options = {
            f"{r['event_id']} · {r['rule_triggered']}": r
            for _, r in filtered.iterrows()
        }
        chosen_incident = st.selectbox("Select an incident", list(incident_options.keys()), key="csv_timeline")
        incident = incident_options[chosen_incident]
        evidence_ids = [x.strip() for x in str(incident["evidence"]).split(",")]
        evidence_rows = df[df["event_id"].astype(str).isin(evidence_ids)].sort_values("timestamp")
        st.markdown(f"**Detection rule:** {incident['rule_triggered']}  \n**Risk:** {incident['risk_level']}  \n**Why flagged:** {incident['suggested_action']}")
        st.dataframe(evidence_rows, use_container_width=True, hide_index=True)

    heading("ADMIN WORKSPACE", "Review decisions")
    review_columns = [
        "alert_key", "event_id", "username", "lab_id", "timestamp",
        "ip_address", "rule_triggered", "evidence", "risk_level",
        "suggested_action", "review_status", "review_notes",
    ]
    edited = st.data_editor(
        filtered[review_columns],
        use_container_width=True, hide_index=True,
        disabled=[
            "alert_key", "event_id", "username", "lab_id", "timestamp",
            "ip_address", "rule_triggered", "evidence", "risk_level", "suggested_action",
        ],
        column_config={
            "alert_key": None,
            "review_status": st.column_config.SelectboxColumn(
                "Review status", options=REVIEW_STATUSES, required=True
            ),
            "review_notes": st.column_config.TextColumn("Administrator notes"),
        },
        key="csv_review_editor",
    )
    if st.button("Save review decisions", type="primary", key="csv_save_reviews"):
        save_reviews(edited[["alert_key", "review_status", "review_notes"]])
        st.success("Review decisions saved to incidents.db.")
        st.rerun()


# ---------------- CONTAINMENT (INCIDENT RESPONSE) ----------------
heading("INCIDENT RESPONSE", "Containment")
st.caption(
    "Detect → Analyze → Contain → Recover → Review. "
    "Containment actions are stored in SQLite, can expire automatically, "
    "can be reversed, and are recorded in the audit log."
)
st.markdown(
    '<div class="ls-note">Containment is a prototype response workflow for the uploaded CSV. '
    'It records block decisions and demonstrates a gateway check; it does not block a real '
    'authentication service unless that service is integrated with LabSentinel.</div>',
    unsafe_allow_html=True,
)

admin_name = st.text_input("Approving administrator", key="containment_admin_name")
admin_password = admin_password_configured()
entered_admin_password = ""
admin_authenticated = False
if not admin_password:
    st.warning(
        "Containment actions are disabled until LABSENTINEL_ADMIN_PASSWORD is configured "
        "as an environment variable or Streamlit secret."
    )
else:
    entered_admin_password = st.text_input(
        "Administrator password", type="password", key="containment_admin_password"
    )
    admin_authenticated = bool(admin_name.strip()) and hmac.compare_digest(
        entered_admin_password, admin_password
    )

confirmed_alerts = alerts[alerts["review_status"] == "Confirmed Suspicious"]

if not admin_password:
    st.caption("Configure the administrator password to unlock containment actions.")
elif not admin_authenticated:
    st.caption("Enter the administrator name and correct password to unlock containment actions.")
elif confirmed_alerts.empty:
    st.info(
        "Mark an alert as 'Confirmed Suspicious' in Review decisions, save it, "
        "and then the containment options will become available."
    )
else:
    alert_lookup = confirmed_alerts.set_index("alert_key")
    chosen_key = st.selectbox(
        "Alert to contain",
        options=list(alert_lookup.index),
        format_func=lambda k: (
            f"{alert_lookup.loc[k, 'event_id']} — "
            f"{alert_lookup.loc[k, 'username']} — "
            f"{alert_lookup.loc[k, 'rule_triggered']}"
        ),
        key="containment_alert_choice",
    )
    chosen = alert_lookup.loc[chosen_key]

    action_choice = st.radio(
        "Containment action",
        [
            f"🔒 Lock account ({chosen['username']})",
            f"🚫 Block IP ({chosen['ip_address']})",
        ],
        horizontal=True,
        key="containment_action_choice",
    )
    duration = st.selectbox(
        "Block duration",
        options=[15, 60, 1440],
        format_func=lambda m: f"{m} minutes" if m < 1440 else "24 hours",
        key="containment_duration",
    )

    if action_choice.startswith("🚫"):
        st.warning(
            "Shared labs may use one public IP. Blocking it can affect other users; "
            "prefer account containment unless the IP is confirmed as the target."
        )

    if st.button("Approve containment", type="primary", key="approve_containment"):
        if not admin_name.strip():
            st.error("Enter the approving administrator's name.")
        else:
            if action_choice.startswith("🔒"):
                block_target(
                    "USER", str(chosen["username"]),
                    str(chosen["rule_triggered"]), str(chosen_key),
                    admin_name.strip(), int(duration),
                )
                target_label = f"account {chosen['username']}"
            else:
                block_target(
                    "IP", str(chosen["ip_address"]),
                    str(chosen["rule_triggered"]), str(chosen_key),
                    admin_name.strip(), int(duration),
                )
                target_label = f"IP {chosen['ip_address']}"
            st.success(f"Containment recorded for {target_label}. The action was added to the audit log.")
            st.rerun()

# ---- Active blocks + manual recovery ----
st.markdown("#### Active blocks")
active_blocks = load_active_blocks()
if active_blocks.empty:
    st.caption("No active blocks.")
else:
    for _, block_row in active_blocks.iterrows():
        col_a, col_b = st.columns([6, 1])
        col_a.write(
            f"**{block_row['target_type']}: {block_row['target_value']}** — "
            f"expires {block_row['expires_at']} — "
            f"approved by {block_row['approved_by']} — "
            f"reason: {block_row['reason']}"
        )
        if col_b.button("Unblock", key=f"containment_unblock_{int(block_row['id'])}"):
            if not admin_name.strip():
                st.error("Enter the approving administrator's name before unblocking.")
            elif unblock(int(block_row["id"]), admin_name.strip()):
                st.success("Block removed and unblock action recorded.")
                st.rerun()
            else:
                st.info("This block is already inactive.")

# ---- Gateway simulator ----
st.markdown("#### Gateway simulator")
st.caption(
    "Test-only demonstration: this mock gateway checks the stored blocklist "
    "before returning an allow/deny result."
)
gateway_col1, gateway_col2 = st.columns(2)
sim_user = gateway_col1.text_input("Test username", key="containment_sim_user")
sim_ip = gateway_col2.text_input("Test IP address", key="containment_sim_ip")
if st.button("Attempt test login", key="containment_gateway_test"):
    if is_blocked("USER", sim_user) or is_blocked("IP", sim_ip):
        st.error("403 BLOCKED — this account or IP has an active containment record.")
    else:
        st.success("200 ALLOWED — no active containment record matched this username or IP.")

# ---- Audit log ----
with st.expander("Audit log", expanded=False):
    audit_df = load_audit_log()
    if audit_df.empty:
        st.write("No containment actions recorded yet.")
    else:
        st.dataframe(audit_df, use_container_width=True, hide_index=True)


heading("REPORTING", "Professional incident report")
report_cols = [
    "event_id", "username", "lab_id", "timestamp", "ip_address",
    "rule_triggered", "evidence", "risk_level", "suggested_action",
    "review_status", "review_notes",
]
report = alerts.reindex(columns=report_cols).copy()
r1, r2, r3 = st.columns(3)
r1.metric("Total alerts", len(report))
r2.metric("High risk", int((report["risk_level"] == "HIGH").sum()) if not report.empty else 0)
r3.metric("Needs review", int((report["review_status"] == "Needs Review").sum()) if not report.empty else 0)

pdf_ready = report.copy()
pdf_ready.insert(0, "source_dataset", dataset_name)
pdf_bytes = build_incident_pdf(
    pdf_ready,
    report_title="Security Incident Report",
    source_mode=f"Uploaded CSV: {dataset_name}",
    containment_df=load_active_blocks(),
    audit_df=load_audit_log(),
)
st.download_button(
    "Download professional incident report (PDF)",
    data=pdf_bytes,
    file_name=f"LabSentinel_Incident_Report_{Path(dataset_name).stem}.pdf",
    mime="application/pdf",
    type="primary",
)
st.caption("The PDF contains only alerts detected from the uploaded CSV. If no alerts are found, the PDF reports zero incidents.")
st.markdown(
    '<div class="ls-footer">◈ LabSentinel · Explainable Access Alerts for Shared Labs<br>'
    'CSV-only analysis · No synthetic login events are generated</div>',
    unsafe_allow_html=True,
)
