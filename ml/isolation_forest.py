import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


# ============================================
# PHASE 3: ISOLATION FOREST ANOMALY DETECTION
# ============================================

INPUT_FILE = "data/cybersecurity_intrusion_cleaned.csv"
OUTPUT_FILE = "data/anomaly_results.csv"


print("============================================")
print("       CYBER INCIDENT DETECTION SYSTEM")
print("       PHASE 3 - ISOLATION FOREST")
print("============================================")


# 1. Load cleaned cybersecurity dataset
df = pd.read_csv(INPUT_FILE)

print("\n===== DATASET INFORMATION =====")
print(f"Total records: {len(df)}")
print(f"Total columns: {len(df.columns)}")


# 2. Select numerical cybersecurity features
features = [
    "network_packet_size",
    "login_attempts",
    "session_duration",
    "ip_reputation_score",
    "failed_logins",
    "unusual_time_access"
]

X = df[features].copy()


# 3. Handle any remaining invalid values
X = X.replace([float("inf"), float("-inf")], pd.NA)
X = X.fillna(X.median())


# 4. Standardize numerical features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)


# 5. Create Isolation Forest model
model = IsolationForest(
    n_estimators=100,
    contamination=0.20,
    random_state=42
)


# 6. Train the model
model.fit(X_scaled)


# 7. Generate anomaly scores
df["anomaly_score"] = model.decision_function(X_scaled)


# 8. Generate anomaly predictions
#    1  = Normal
#   -1  = Anomaly
df["anomaly"] = model.predict(X_scaled)


# 9. Convert prediction into readable status
df["status"] = df["anomaly"].map({
    1: "Normal",
    -1: "Anomaly"
})


# 10. Convert anomaly score into a 0-100 risk score
# Lower Isolation Forest score = more anomalous
score_min = df["anomaly_score"].min()
score_max = df["anomaly_score"].max()

if score_max != score_min:
    df["risk_score"] = (
        (score_max - df["anomaly_score"])
        / (score_max - score_min)
        * 100
    )
else:
    df["risk_score"] = 0


df["risk_score"] = df["risk_score"].round(2)


# 11. Assign severity
def get_severity(score):
    if score >= 75:
        return "Critical"
    elif score >= 50:
        return "High"
    elif score >= 25:
        return "Medium"
    else:
        return "Low"


df["severity"] = df["risk_score"].apply(get_severity)


# 12. Display anomaly detection results
print("\n===== ANOMALY DETECTION RESULTS =====")

display_columns = [
    "network_packet_size",
    "login_attempts",
    "session_duration",
    "ip_reputation_score",
    "failed_logins",
    "unusual_time_access",
    "anomaly_score",
    "anomaly",
    "status",
    "risk_score",
    "severity"
]

print(df[display_columns].to_string(index=False))


# 13. Display detected anomalies
anomalies = df[df["status"] == "Anomaly"]

print("\n===== DETECTED ANOMALIES =====")

if len(anomalies) > 0:
    print(
        anomalies[display_columns]
        .to_string(index=False)
    )
else:
    print("No anomalies detected.")


# 14. Detection summary
normal_count = len(df[df["status"] == "Normal"])
anomaly_count = len(df[df["status"] == "Anomaly"])

print("\n===== DETECTION SUMMARY =====")
print(f"Total records      : {len(df)}")
print(f"Normal records     : {normal_count}")
print(f"Anomalous records  : {anomaly_count}")


# 15. Severity summary
print("\n===== RISK SUMMARY =====")
print(df["severity"].value_counts())


# 16. Save results
df.to_csv(OUTPUT_FILE, index=False)

print("\n============================================")
print(f"Results saved to: {OUTPUT_FILE}")
print("Phase 3 completed successfully.")
print("============================================")