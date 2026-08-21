import pandas as pd
from sklearn.ensemble import IsolationForest


# ============================================
# PHASE 3: ISOLATION FOREST ANOMALY DETECTION
# ============================================

# 1. Load the network dataset
df = pd.read_csv("data/network_data.csv")

print("============================================")
print("        CYBER INCIDENT DETECTION SYSTEM")
print("        PHASE 3 - ISOLATION FOREST")
print("============================================")

print("\n===== ORIGINAL DATA =====")
print(df)


# 2. Select numerical features for ML
features = [
    "flow_duration",
    "packet_count",
    "byte_count",
    "port"
]

X = df[features]


# 3. Create Isolation Forest model
model = IsolationForest(
    n_estimators=100,
    contamination=0.2,
    random_state=42
)


# 4. Train the model
model.fit(X)


# 5. Generate anomaly scores
df["anomaly_score"] = model.decision_function(X)


# 6. Generate anomaly predictions
#    1  = Normal
#   -1  = Anomaly
df["anomaly"] = model.predict(X)


# 7. Convert prediction into readable status
df["status"] = df["anomaly"].map({
    1: "Normal",
    -1: "Anomaly"
})


# 8. Display complete results
print("\n===== ANOMALY DETECTION RESULTS =====")

print(
    df[
        [
            "timestamp",
            "source_ip",
            "destination_ip",
            "flow_duration",
            "packet_count",
            "byte_count",
            "port",
            "anomaly_score",
            "anomaly",
            "status"
        ]
    ].to_string(index=False)
)


# 9. Display only detected anomalies
anomalies = df[df["status"] == "Anomaly"]

print("\n===== DETECTED ANOMALIES =====")

if len(anomalies) > 0:
    print(
        anomalies[
            [
                "timestamp",
                "source_ip",
                "destination_ip",
                "flow_duration",
                "packet_count",
                "byte_count",
                "port",
                "anomaly_score",
                "status"
            ]
        ].to_string(index=False)
    )
else:
    print("No anomalies detected.")


# 10. Display summary
normal_count = len(df[df["status"] == "Normal"])
anomaly_count = len(df[df["status"] == "Anomaly"])

print("\n===== DETECTION SUMMARY =====")
print(f"Total network flows : {len(df)}")
print(f"Normal flows        : {normal_count}")
print(f"Anomalous flows     : {anomaly_count}")


# 11. Save results for Phase 4
output_file = "data/anomaly_results.csv"

df.to_csv(output_file, index=False)

print("\n============================================")
print(f"Results saved to: {output_file}")
print("Phase 3 completed successfully.")
print("============================================")