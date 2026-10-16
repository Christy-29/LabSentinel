import pandas as pd

# LabSentinel: Shared Lab Login Detection Engine

CSV_FILE = "login_logs.csv"

# Example lab opening hours: 8 AM to 6 PM
LAB_OPEN_HOUR = 8
LAB_CLOSE_HOUR = 18

df = pd.read_csv(CSV_FILE)

required_columns = {
    "event_id", "username", "timestamp",
    "ip_address", "login_status", "lab_id"
}

if not required_columns.issubset(df.columns):
    missing = required_columns - set(df.columns)
    raise ValueError(f"Missing CSV columns: {missing}")

df["timestamp"] = pd.to_datetime(df["timestamp"], errors="raise")
df["login_status"] = df["login_status"].str.strip().str.upper()
df = df.sort_values("timestamp").reset_index(drop=True)

alerts = []

# Rule 1: Repeated failed logins followed by success
for (username, lab_id), group in df.groupby(["username", "lab_id"]):
    group = group.sort_values("timestamp").reset_index(drop=True)

    for i, row in group.iterrows():
        if row["login_status"] != "SUCCESS":
            continue

        # Find failures from the same account and lab
        # within the previous 10 minutes
        previous = group[
            (group["timestamp"] < row["timestamp"]) &
            (group["timestamp"] >=
             row["timestamp"] - pd.Timedelta(minutes=10))
        ]

        failures = previous[
            previous["login_status"] == "FAILURE"
        ]

        if len(failures) >= 2:
            event_ids = failures["event_id"].tolist()
            event_ids.append(row["event_id"])

            alerts.append({
                "event_id": row["event_id"],
                "username": username,
                "lab_id": lab_id,
                "timestamp": row["timestamp"],
                "rule_triggered": "Repeated failures followed by success",
                "evidence": ", ".join(event_ids),
                "risk_level": "HIGH",
                "review_action": "Verify the login with the lab administrator"
            })

# Rule 2: Successful login outside lab hours
successes = df[df["login_status"] == "SUCCESS"]

for _, row in successes.iterrows():
    hour = row["timestamp"].hour

    if hour < LAB_OPEN_HOUR or hour >= LAB_CLOSE_HOUR:
        alerts.append({
            "event_id": row["event_id"],
            "username": row["username"],
            "lab_id": row["lab_id"],
            "timestamp": row["timestamp"],
            "rule_triggered": "Successful login outside lab hours",
            "evidence": row["event_id"],
            "risk_level": "MEDIUM",
            "review_action": "Confirm whether after-hours access was authorized"
        })

# Display the results
print("\n=== LABSENTINEL DETECTION REPORT ===")
print(f"Total login records: {len(df)}")
print(f"Suspicious alerts: {len(alerts)}")

if alerts:
    results = pd.DataFrame(alerts)
    print("\n", results.to_string(index=False))

    results.to_csv("alerts.csv", index=False)
    print("\nAlerts saved to alerts.csv")
else:
    print("No suspicious activity detected.")

print("\nAlerts require human review; they do not prove wrongdoing.")
