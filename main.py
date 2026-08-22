import os
import pandas as pd

from fastapi import FastAPI, HTTPException
from contextlib import asynccontextmanager

from database.database import (
    init_db,
    save_incident,
    save_alert,
    fetch_all_incidents
)

from risk.explainability import generate_explanation


# ============================================================
# CONFIGURATION
# ============================================================

ALERTS_FILE = "data/alerts.csv"

alerts_cache = pd.DataFrame()
incidents_cache = pd.DataFrame()


# ============================================================
# PHASE 4 — LOAD PROJECT ALERT DATA
# ============================================================

def load_alerts():
    global alerts_cache

    if not os.path.exists(ALERTS_FILE):
        print("ERROR: data/alerts.csv not found!")
        print("Please run Phase 4 first.")
        return pd.DataFrame()

    try:

        # Try UTF-8 first
        try:
            df = pd.read_csv(
                ALERTS_FILE,
                encoding="utf-8"
            )

        except UnicodeDecodeError:
            # Some Phase 4 files may be UTF-16
            df = pd.read_csv(
                ALERTS_FILE,
                encoding="utf-16"
            )

        # Standardize column names
        df.columns = (
            df.columns
            .str.strip()
            .str.lower()
            .str.replace(" ", "_")
        )

        alerts_cache = df

        print(
            f"Loaded {len(df)} project alerts successfully."
        )

        return df

    except Exception as e:

        print(f"Error loading alerts: {e}")

        return pd.DataFrame()


# ============================================================
# PHASE 5 — ALERT PRIORITY
# ============================================================

def calculate_priority(row):

    severity = str(
        row.get("severity", "")
    ).lower()

    confidence = str(
        row.get("confidence", "")
    ).lower()

    if severity == "critical":
        return "CRITICAL"

    if severity == "high":
        return "HIGH"

    if severity == "medium":
        return "MEDIUM"

    if severity == "low":
        return "LOW"

    if confidence in [
        "high",
        "0.9",
        "0.95",
        "1.0"
    ]:
        return "HIGH"

    return "MEDIUM"


# ============================================================
# PHASE 6 — ALERT CORRELATION / INCIDENT FORMATION
# ============================================================

def correlate_alerts(df):

    if df.empty:
        return pd.DataFrame()

    data = df.copy()

    # --------------------------------------------------------
    # Find source IP column
    # --------------------------------------------------------

    source_col = None

    for col in [
        "source_ip",
        "src_ip",
        "src"
    ]:

        if col in data.columns:
            source_col = col
            break

    # --------------------------------------------------------
    # Find destination IP column
    # --------------------------------------------------------

    destination_col = None

    for col in [
        "destination_ip",
        "dst_ip",
        "destination",
        "dst"
    ]:

        if col in data.columns:
            destination_col = col
            break

    # --------------------------------------------------------
    # Create correlation key
    # --------------------------------------------------------

    if source_col and destination_col:

        data["correlation_key"] = (
            data[source_col].astype(str)
            + " -> "
            + data[destination_col].astype(str)
        )

    elif source_col:

        data["correlation_key"] = (
            data[source_col].astype(str)
        )

    else:

        data["correlation_key"] = "UNKNOWN"

    incidents = []

    # --------------------------------------------------------
    # Create one incident per correlated group
    # --------------------------------------------------------

    for incident_id, (key, group) in enumerate(
        data.groupby("correlation_key"),
        start=1
    ):

        priorities = group.apply(
            calculate_priority,
            axis=1
        )

        if "CRITICAL" in priorities.values:
            priority = "CRITICAL"

        elif "HIGH" in priorities.values:
            priority = "HIGH"

        elif "MEDIUM" in priorities.values:
            priority = "MEDIUM"

        else:
            priority = "LOW"

        # ----------------------------------------------------
        # Anomaly score
        # ----------------------------------------------------

        anomaly_score = 0.0

        if "anomaly_score" in group.columns:

            numeric_scores = pd.to_numeric(
                group["anomaly_score"],
                errors="coerce"
            ).dropna()

            if not numeric_scores.empty:
                anomaly_score = float(
                    numeric_scores.mean()
                )

        # ----------------------------------------------------
        # Repeated activity
        # ----------------------------------------------------

        repeated_activity = len(group) >= 2

        # ----------------------------------------------------
        # Incident record
        # ----------------------------------------------------

        incidents.append(
            {
                "incident_id": incident_id,
                "correlation_key": key,
                "alert_count": len(group),
                "priority": priority,
                "anomaly_score": anomaly_score,
                "repeated_activity": repeated_activity
            }
        )

    return pd.DataFrame(incidents)


# ============================================================
# PHASE 7 — INCIDENT PRIORITIZATION
# ============================================================

def prioritize_incidents(incidents_df):

    if incidents_df.empty:
        return incidents_df

    prioritized = incidents_df.copy()

    def calculate_incident_risk(row):

        score = 0

        # ----------------------------------------------------
        # Existing Phase 6 priority
        # ----------------------------------------------------

        priority = str(
            row.get("priority", "")
        ).upper()

        priority_scores = {
            "CRITICAL": 70,
            "HIGH": 50,
            "MEDIUM": 30,
            "LOW": 10
        }

        score += priority_scores.get(
            priority,
            20
        )

        # ----------------------------------------------------
        # Number of correlated alerts
        # ----------------------------------------------------

        alert_count = int(
            row.get("alert_count", 0)
        )

        if alert_count >= 100:
            score += 30

        elif alert_count >= 10:
            score += 20

        elif alert_count >= 5:
            score += 10

        elif alert_count >= 2:
            score += 5

        return min(score, 100)

    # Calculate risk score
    prioritized["risk_score"] = prioritized.apply(
        calculate_incident_risk,
        axis=1
    )

    # --------------------------------------------------------
    # Final priority
    # --------------------------------------------------------

    def assign_final_priority(score):

        if score >= 80:
            return "CRITICAL"

        elif score >= 60:
            return "HIGH"

        elif score >= 30:
            return "MEDIUM"

        else:
            return "LOW"

    prioritized["final_priority"] = (
        prioritized["risk_score"]
        .apply(assign_final_priority)
    )

    # Highest risk first
    prioritized = prioritized.sort_values(
        by="risk_score",
        ascending=False
    ).reset_index(drop=True)

    return prioritized


# ============================================================
# PHASE 8 — INCIDENT EXPLAINABILITY
# ============================================================

def add_explanations(incidents_df):

    if incidents_df.empty:
        return incidents_df

    explained = incidents_df.copy()

    explanations = []

    for _, row in explained.iterrows():

        explanation = generate_explanation(
            anomaly_score=float(
                row.get("anomaly_score", 0)
            ),
            priority=str(
                row.get(
                    "final_priority",
                    row.get("priority", "LOW")
                )
            ),
            related_alerts=int(
                row.get("alert_count", 0)
            ),
            repeated_activity=bool(
                row.get("repeated_activity", False)
            ),
            asset_impact="LOW"
        )

        explanations.append(explanation)

    explained["explanation"] = [
        item["reasons"]
        for item in explanations
    ]

    explained["evidence"] = [
        item["evidence"]
        for item in explanations
    ]

    return explained


# ============================================================
# PHASE 9 — SAVE REAL PROJECT DATA TO DATABASE
# ============================================================

def save_project_data_to_database(
    alerts,
    incidents
):

    if incidents.empty:
        print("No incidents to save.")
        return

    print(
        "Saving Phase 6/7/8 project incidents "
        "to Phase 9 database..."
    )

    # --------------------------------------------------------
    # Save incidents
    # --------------------------------------------------------

    for _, incident in incidents.iterrows():

        incident_id = str(
            incident["incident_id"]
        )

        risk_score = float(
            incident.get("risk_score", 0)
        )

        priority = str(
            incident.get(
                "final_priority",
                incident.get("priority", "LOW")
            )
        )

        reasons = incident.get(
            "explanation",
            []
        )

        if not isinstance(reasons, list):
            reasons = [str(reasons)]

        save_incident(
            incident_id=incident_id,
            risk_score=risk_score,
            priority=priority,
            reasons=reasons
        )

    # --------------------------------------------------------
    # Save alerts belonging to each incident
    # --------------------------------------------------------

    if alerts.empty:
        return

    data = alerts.copy()

    # Find source column
    source_col = None

    for col in [
        "source_ip",
        "src_ip",
        "src"
    ]:

        if col in data.columns:
            source_col = col
            break

    # Find destination column
    destination_col = None

    for col in [
        "destination_ip",
        "dst_ip",
        "destination",
        "dst"
    ]:

        if col in data.columns:
            destination_col = col
            break

    # Recreate correlation key
    if source_col and destination_col:

        data["correlation_key"] = (
            data[source_col].astype(str)
            + " -> "
            + data[destination_col].astype(str)
        )

    elif source_col:

        data["correlation_key"] = (
            data[source_col].astype(str)
        )

    else:

        data["correlation_key"] = "UNKNOWN"

    # Map correlation key → incident ID
    incident_map = {}

    for _, incident in incidents.iterrows():

        incident_map[
            incident["correlation_key"]
        ] = str(
            incident["incident_id"]
        )

    # Save each real project alert
    for _, alert in data.iterrows():

        correlation_key = alert[
            "correlation_key"
        ]

        incident_id = incident_map.get(
            correlation_key
        )

        if incident_id is None:
            continue

        alert_type = alert.get(
            "alert_type",
            alert.get(
                "label",
                "Network Alert"
            )
        )

        severity = alert.get(
            "severity",
            "UNKNOWN"
        )

        save_alert(
            incident_id=incident_id,
            alert_type=str(alert_type),
            severity=str(severity)
        )

    print(
        "Phase 9 database storage completed."
    )


# ============================================================
# APPLICATION STARTUP
# ============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):

    global incidents_cache

    print("")
    print("==============================================")
    print(" CYBERSECURITY INCIDENT PRIORITIZATION SYSTEM")
    print("==============================================")

    # --------------------------------------------------------
    # PHASE 9 — Initialize database
    # --------------------------------------------------------

    init_db()

    # --------------------------------------------------------
    # PHASE 4 — Load REAL project alerts
    # --------------------------------------------------------

    alerts = load_alerts()

    if alerts.empty:

        incidents_cache = pd.DataFrame()

        print(
            "WARNING: No project alerts available."
        )

    else:

        # ----------------------------------------------------
        # PHASE 6 — Correlation
        # ----------------------------------------------------

        incidents_cache = correlate_alerts(
            alerts
        )

        print(
            f"Created {len(incidents_cache)} "
            "correlated incidents."
        )

        # ----------------------------------------------------
        # PHASE 7 — Prioritization
        # ----------------------------------------------------

        incidents_cache = prioritize_incidents(
            incidents_cache
        )

        print(
            "Phase 7 incident prioritization completed."
        )

        # ----------------------------------------------------
        # PHASE 8 — Explainability
        # ----------------------------------------------------

        incidents_cache = add_explanations(
            incidents_cache
        )

        print(
            "Phase 8 incident explainability completed."
        )

        # ----------------------------------------------------
        # PHASE 9 — Database
        # ----------------------------------------------------

        save_project_data_to_database(
            alerts,
            incidents_cache
        )

    print("Application startup complete.")

    yield

    print("Shutting down application.")


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="Cybersecurity Incident Prioritization",
    description=(
        "End-to-end cybersecurity anomaly detection, "
        "alert correlation, incident prioritization, "
        "explainability and database storage."
    ),
    version="10.0",
    lifespan=lifespan
)


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():

    return {
        "project": "Cybersecurity Incident Prioritization",
        "phases": "4-10",
        "status": "running"
    }


# ============================================================
# ORIGINAL ALERT ENDPOINT
# ============================================================

@app.get("/alerts")
def get_alerts():

    if alerts_cache.empty:

        return {
            "count": 0,
            "alerts": []
        }

    return {
        "count": len(alerts_cache),
        "alerts": alerts_cache.to_dict(
            orient="records"
        )
    }


# ============================================================
# ORIGINAL INCIDENT ENDPOINT
# ============================================================

@app.get("/incidents")
def get_incidents():

    if incidents_cache.empty:

        return {
            "count": 0,
            "incidents": []
        }

    return {
        "count": len(incidents_cache),
        "incidents": incidents_cache.to_dict(
            orient="records"
        )
    }


# ============================================================
# ORIGINAL SINGLE INCIDENT ENDPOINT
# ============================================================

@app.get("/incidents/{incident_id}")
def get_incident(incident_id: int):

    if incidents_cache.empty:

        raise HTTPException(
            status_code=404,
            detail="No incidents available"
        )

    incident = incidents_cache[
        incidents_cache["incident_id"] == incident_id
    ]

    if incident.empty:

        raise HTTPException(
            status_code=404,
            detail="Incident not found"
        )

    return incident.iloc[0].to_dict()


# ============================================================
# ORIGINAL DATABASE ENDPOINT
# ============================================================

@app.get("/database/incidents")
def get_database_incidents():

    records = fetch_all_incidents()

    return {
        "count": len(records),
        "incidents": [
            {
                "incident_id": row[0],
                "risk_score": row[1],
                "priority": row[2],
                "reasons": row[3],
                "timestamp": row[4]
            }
            for row in records
        ]
    }


# ============================================================
# PHASE 10 — BACKEND API
# ============================================================

@app.get("/health")
def health_check():

    return {
        "status": "healthy",
        "service": "Cybersecurity Incident Prioritization API",
        "phase": 10
    }


# ------------------------------------------------------------
# PHASE 10 — ALERTS API
# ------------------------------------------------------------

@app.get("/api/alerts")
def api_get_alerts():

    if alerts_cache.empty:

        return {
            "count": 0,
            "alerts": []
        }

    return {
        "count": len(alerts_cache),
        "alerts": alerts_cache.to_dict(
            orient="records"
        )
    }


# ------------------------------------------------------------
# PHASE 10 — INCIDENTS API
# ------------------------------------------------------------

@app.get("/api/incidents")
def api_get_incidents():

    if incidents_cache.empty:

        return {
            "count": 0,
            "incidents": []
        }

    return {
        "count": len(incidents_cache),
        "incidents": incidents_cache.to_dict(
            orient="records"
        )
    }


# ------------------------------------------------------------
# PHASE 10 — SINGLE INCIDENT API
# ------------------------------------------------------------

@app.get("/api/incidents/{incident_id}")
def api_get_incident(incident_id: int):

    if incidents_cache.empty:

        raise HTTPException(
            status_code=404,
            detail="No incidents available"
        )

    incident = incidents_cache[
        incidents_cache["incident_id"] == incident_id
    ]

    if incident.empty:

        raise HTTPException(
            status_code=404,
            detail="Incident not found"
        )

    return incident.iloc[0].to_dict()


# ------------------------------------------------------------
# PHASE 10 — DATABASE INCIDENTS API
# ------------------------------------------------------------

@app.get("/api/database/incidents")
def api_get_database_incidents():

    records = fetch_all_incidents()

    return {
        "count": len(records),
        "incidents": [
            {
                "incident_id": row[0],
                "risk_score": row[1],
                "priority": row[2],
                "reasons": row[3],
                "timestamp": row[4]
            }
            for row in records
        ]
    }


# ------------------------------------------------------------
# PHASE 10 — STATISTICS API
# ------------------------------------------------------------

@app.get("/api/statistics")
def get_statistics():

    if incidents_cache.empty:

        return {
            "total_incidents": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "total_alerts": len(alerts_cache)
        }

    priority_column = "final_priority"

    if priority_column not in incidents_cache.columns:
        priority_column = "priority"

    priorities = (
        incidents_cache[priority_column]
        .astype(str)
        .str.upper()
    )

    return {
        "total_incidents": len(incidents_cache),
        "total_alerts": len(alerts_cache),
        "critical": int(
            (priorities == "CRITICAL").sum()
        ),
        "high": int(
            (priorities == "HIGH").sum()
        ),
        "medium": int(
            (priorities == "MEDIUM").sum()
        ),
        "low": int(
            (priorities == "LOW").sum()
        )
    }


# ============================================================
# RUN APPLICATION
# ============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=8000,
        reload=True
    )