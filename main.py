import os
import pandas as pd
from fastapi import FastAPI, HTTPException
from contextlib import asynccontextmanager


ALERTS_FILE = "data/alerts.csv"

alerts_cache = pd.DataFrame()
incidents_cache = pd.DataFrame()


def load_alerts():
    global alerts_cache

    if not os.path.exists(ALERTS_FILE):
        print("ERROR: data/alerts.csv not found!")
        print("Please run Phase 4 first.")
        return pd.DataFrame()

    try:
        # Try UTF-8 first
        try:
            df = pd.read_csv(ALERTS_FILE, encoding="utf-8")
        except UnicodeDecodeError:
            # Phase 4 CSV may be UTF-16
            df = pd.read_csv(ALERTS_FILE, encoding="utf-16")

        df.columns = (
            df.columns
            .str.strip()
            .str.lower()
            .str.replace(" ", "_")
        )

        alerts_cache = df

        print(f"Loaded {len(df)} alerts successfully.")

        return df

    except Exception as e:
        print(f"Error loading alerts: {e}")
        return pd.DataFrame()


def calculate_priority(row):
    """
    Phase 5 priority calculation.

    Priority is based on severity and confidence.
    """

    severity = str(row.get("severity", "")).lower()
    confidence = str(row.get("confidence", "")).lower()

    if severity == "critical":
        return "CRITICAL"

    if severity == "high":
        return "HIGH"

    if severity == "medium":
        return "MEDIUM"

    if severity == "low":
        return "LOW"

    if confidence in ["high", "0.9", "0.95", "1.0"]:
        return "HIGH"

    return "MEDIUM"


def correlate_alerts(df):
    """
    Group related alerts into incidents.

    Alerts are correlated using source/destination information
    when those fields are available.
    """

    if df.empty:
        return pd.DataFrame()

    data = df.copy()

    # Possible column names from different dataset versions
    source_col = None
    destination_col = None

    for col in ["source_ip", "src_ip", "src"]:
        if col in data.columns:
            source_col = col
            break

    for col in ["destination_ip", "dst_ip", "destination", "dst"]:
        if col in data.columns:
            destination_col = col
            break

    if source_col and destination_col:
        data["correlation_key"] = (
            data[source_col].astype(str)
            + " -> "
            + data[destination_col].astype(str)
        )
    elif source_col:
        data["correlation_key"] = data[source_col].astype(str)
    else:
        data["correlation_key"] = "UNKNOWN"

    incidents = []

    for incident_id, (key, group) in enumerate(
        data.groupby("correlation_key"),
        start=1
    ):

        priorities = group.apply(calculate_priority, axis=1)

        if "CRITICAL" in priorities.values:
            priority = "CRITICAL"
        elif "HIGH" in priorities.values:
            priority = "HIGH"
        elif "MEDIUM" in priorities.values:
            priority = "MEDIUM"
        else:
            priority = "LOW"

        incidents.append(
            {
                "incident_id": incident_id,
                "correlation_key": key,
                "alert_count": len(group),
                "priority": priority,
            }
        )

    return pd.DataFrame(incidents)


@asynccontextmanager
async def lifespan(app: FastAPI):

    global incidents_cache

    print("Starting Phase 5 Incident Correlation Engine...")

    alerts = load_alerts()

    if not alerts.empty:
        incidents_cache = correlate_alerts(alerts)

        print(
            f"Created {len(incidents_cache)} correlated incidents."
        )

    yield

    print("Shutting down Phase 5 engine...")


app = FastAPI(
    title="Cybersecurity Incident Prioritization",
    description="Phase 5 - Alert Correlation and Incident Formation",
    version="5.0",
    lifespan=lifespan,
)


@app.get("/")
def root():
    return {
        "project": "Cybersecurity Incident Prioritization",
        "phase": "Phase 5",
        "status": "running",
    }


@app.get("/alerts")
def get_alerts():
    if alerts_cache.empty:
        return {
            "count": 0,
            "alerts": []
        }

    return {
        "count": len(alerts_cache),
        "alerts": alerts_cache.to_dict(orient="records")
    }


@app.get("/incidents")
def get_incidents():
    if incidents_cache.empty:
        return {
            "count": 0,
            "incidents": []
        }

    return {
        "count": len(incidents_cache),
        "incidents": incidents_cache.to_dict(orient="records")
    }


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


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=8000,
        reload=True
    )