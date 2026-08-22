def generate_explanation(
    anomaly_score,
    priority,
    related_alerts,
    repeated_activity=False,
    asset_impact="LOW"
):
    """
    PHASE 8 - INCIDENT EXPLAINABILITY

    Explains why an incident received its Phase 7 priority.
    """

    reasons = []

    # 1. Anomaly score
    if anomaly_score >= 0.80:
        reasons.append(
            "Very high anomaly score indicates highly unusual network behaviour."
        )
    elif anomaly_score >= 0.60:
        reasons.append(
            "High anomaly score indicates unusual network behaviour."
        )
    elif anomaly_score >= 0.40:
        reasons.append(
            "Moderate anomaly score indicates some deviation from normal behaviour."
        )
    else:
        reasons.append(
            "Low anomaly score indicates relatively normal network behaviour."
        )

    # 2. Related alerts
    if related_alerts >= 5:
        reasons.append(
            f"{related_alerts} related alerts indicate a concentrated "
            "sequence of suspicious activity."
        )
    elif related_alerts >= 3:
        reasons.append(
            f"{related_alerts} related alerts indicate multiple suspicious events."
        )
    elif related_alerts == 2:
        reasons.append(
            "Multiple related alerts were detected."
        )

    # 3. Repeated activity
    if repeated_activity:
        reasons.append(
            "Repeated suspicious activity was detected from the same activity source."
        )

    # 4. Asset impact
    asset_impact = str(asset_impact).upper()

    if asset_impact == "CRITICAL":
        reasons.append(
            "The affected asset has critical impact, increasing the potential risk."
        )
    elif asset_impact == "HIGH":
        reasons.append(
            "The affected asset has high impact, increasing the potential risk."
        )
    elif asset_impact == "MEDIUM":
        reasons.append(
            "The affected asset has moderate impact."
        )

    # Keep Phase 7 priority unchanged
    priority = str(priority).upper()

    return {
        "priority": priority,
        "reasons": reasons,
        "evidence": {
            "anomaly_score": round(float(anomaly_score), 6),
            "related_alerts": int(related_alerts),
            "repeated_activity": bool(repeated_activity),
            "asset_impact": asset_impact
        }
    }


# ==========================================
# PHASE 8 TEST
# ==========================================

if __name__ == "__main__":

    explanation = generate_explanation(
        anomaly_score=0.91,
        priority="HIGH",
        related_alerts=5,
        repeated_activity=True,
        asset_impact="HIGH"
    )

    print("\n========================================")
    print("      PHASE 8 EXPLAINABILITY TEST")
    print("========================================")

    print("\nPriority:")
    print(explanation["priority"])

    print("\nWhy?")

    for reason in explanation["reasons"]:
        print("✓", reason)

    print("\nEvidence:")

    for key, value in explanation["evidence"].items():
        print(f"{key}: {value}")