import pandas as pd

print("============================================")
print("        CYBER INCIDENT DETECTION SYSTEM")
print("        PHASE 4 - ALERT GENERATION")
print("============================================")


# STEP 1: Load Phase 3 results
input_file = "data/anomaly_results.csv"

df = pd.read_csv(input_file)

print("\n===== PHASE 3 RESULTS LOADED =====")
print(df.to_string(index=False))


# STEP 2: Select only anomalies
anomalies = df[df["status"] == "Anomaly"].copy()

print("\n===== ANOMALIES FOUND =====")
print(f"Total anomalies: {len(anomalies)}")


# STEP 3: Generate alerts
if anomalies.empty:

    print("\nNo anomalies detected.")
    print("No alerts generated.")

else:

    # Create Alert IDs
    anomalies["alert_id"] = [
        f"ALERT-{i:03d}"
        for i in range(1, len(anomalies) + 1)
    ]


    # Generate alert type
    def generate_alert_type(row):

        if row["packet_count"] >= 2000:
            return "High Traffic Anomaly"

        elif row["packet_count"] >= 500:
            return "Suspicious Network Activity"

        else:
            return "Network Anomaly"


    anomalies["alert_type"] = anomalies.apply(
        generate_alert_type,
        axis=1
    )


    # Generate human-readable alert message
    def generate_alert_message(row):

        return (
            f"Unusual network activity detected from "
            f"{row['source_ip']} to "
            f"{row['destination_ip']} "
            f"on port {row['port']}."
        )


    anomalies["alert_message"] = anomalies.apply(
        generate_alert_message,
        axis=1
    )


    # Set initial alert status
    anomalies["alert_status"] = "NEW"


    # Select columns for alerts
    alerts = anomalies[
        [
            "alert_id",
            "timestamp",
            "source_ip",
            "destination_ip",
            "port",
            "flow_duration",
            "packet_count",
            "byte_count",
            "anomaly_score",
            "alert_type",
            "alert_message",
            "alert_status"
        ]
    ]


    # Display generated alerts
    print("\n===== GENERATED SECURITY ALERTS =====")

    print(alerts.to_string(index=False))


    # Save alerts
    output_file = "data/alerts.csv"

    alerts.to_csv(
        output_file,
        index=False
    )


    # Summary
    print("\n===== ALERT SUMMARY =====")
    print(f"Total anomalies detected : {len(anomalies)}")
    print(f"Total alerts generated   : {len(alerts)}")

    print("\n============================================")
    print(f"Alerts saved to: {output_file}")
    print("Phase 4 completed successfully.")
    print("============================================")