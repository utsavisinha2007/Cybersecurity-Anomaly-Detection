from database import (
    init_db,
    save_incident,
    save_alert,
    fetch_all_incidents
)


print("=" * 40)
print("       PHASE 9 DATABASE TEST")
print("=" * 40)

# 1. Initialize database
init_db()

# 2. Save test incident
save_incident(
    "TEST-001",
    8.5,
    "HIGH",
    [
        "High anomaly score",
        "Multiple related alerts"
    ]
)

# 3. Save related alerts
save_alert(
    "TEST-001",
    "Network Anomaly",
    "HIGH"
)

save_alert(
    "TEST-001",
    "Multiple Connections",
    "MEDIUM"
)

# 4. Retrieve incidents
incidents = fetch_all_incidents()

print("\nStored incidents:")
for incident in incidents:
    print(incident)

print("\n" + "=" * 40)
print("       PHASE 9 TEST COMPLETE")
print("=" * 40)