import os
import pandas as pd

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from risk.explainability import generate_explanation


# ============================================================
# FILE CONFIGURATION
# ============================================================

ANOMALY_RESULTS_FILE = "data/anomaly_results.csv"

incidents_cache = pd.DataFrame()


# ============================================================
# LOAD ANOMALY RESULTS
# ============================================================

def load_incidents():
    global incidents_cache

    if not os.path.exists(ANOMALY_RESULTS_FILE):
        print("ERROR: data/anomaly_results.csv not found!")
        print("Please run Phase 3 first:")
        print("python ml/isolation_forest.py")
        return pd.DataFrame()

    try:
        df = pd.read_csv(ANOMALY_RESULTS_FILE)

        # Clean column names
        df.columns = (
            df.columns
            .str.strip()
            .str.lower()
            .str.replace(" ", "_")
        )

        print(f"Loaded {len(df)} anomaly records successfully.")

        # ----------------------------------------------------
        # Create incident IDs
        # ----------------------------------------------------

        df.insert(
            0,
            "incident_id",
            range(1, len(df) + 1)
        )

        # ----------------------------------------------------
        # Convert attack label to readable incident type
        # ----------------------------------------------------

        if "attack_detected" in df.columns:

            df["incident_type"] = df["attack_detected"].map({
                0: "Normal",
                1: "Attack"
            }).fillna("Unknown")

        else:
            df["incident_type"] = "Unknown"

        # ----------------------------------------------------
        # Use Isolation Forest risk score
        # ----------------------------------------------------

        if "risk_score" in df.columns:

            df["risk_score"] = pd.to_numeric(
                df["risk_score"],
                errors="coerce"
            ).fillna(0)

        else:
            df["risk_score"] = 0

        # ----------------------------------------------------
        # Create priority from risk score
        # ----------------------------------------------------

        df["priority"] = df["risk_score"].apply(
            assign_final_priority
        )

        # ----------------------------------------------------
        # Alert count
        # Each dataset row represents one security event
        # ----------------------------------------------------

        df["alert_count"] = 1

        incidents_cache = df

        print(
            f"Created {len(incidents_cache)} incidents."
        )

        return df

    except Exception as e:

        print(
            f"Error loading anomaly results: {e}"
        )

        return pd.DataFrame()


# ============================================================
# PHASE 7 — RISK / PRIORITY
# ============================================================

def assign_final_priority(score):

    score = float(score)

    if score >= 75:
        return "CRITICAL"

    elif score >= 50:
        return "HIGH"

    elif score >= 25:
        return "MEDIUM"

    else:
        return "LOW"


def prioritize_incidents(incidents_df):

    if incidents_df.empty:
        return incidents_df

    prioritized = incidents_df.copy()

    # Make sure risk score exists
    if "risk_score" not in prioritized.columns:

        prioritized["risk_score"] = 0

    prioritized["risk_score"] = pd.to_numeric(
        prioritized["risk_score"],
        errors="coerce"
    ).fillna(0)

    # Final priority
    prioritized["final_priority"] = (
        prioritized["risk_score"]
        .apply(assign_final_priority)
    )

    # Keep priority synchronized
    prioritized["priority"] = (
        prioritized["final_priority"]
    )

    # Highest risk first
    prioritized = prioritized.sort_values(
        by="risk_score",
        ascending=False
    ).reset_index(drop=True)

    return prioritized


# ============================================================
# PHASE 8 — EXPLAINABILITY
# ============================================================

def add_explanations(incidents_df):

    if incidents_df.empty:
        return incidents_df

    explained = incidents_df.copy()

    def create_explanation(row):

        anomaly_score = row.get(
            "anomaly_score",
            0.0
        )

        priority = row.get(
            "final_priority",
            row.get(
                "priority",
                "LOW"
            )
        )

        related_alerts = row.get(
            "alert_count",
            1
        )

        # Repeated activity
        repeated_activity = (
            int(related_alerts) >= 3
        )

        # Prototype asset impact
        asset_impact = "HIGH"

        return generate_explanation(
            anomaly_score=anomaly_score,
            priority=priority,
            related_alerts=related_alerts,
            repeated_activity=repeated_activity,
            asset_impact=asset_impact
        )

    explained["explanation"] = (
        explained.apply(
            create_explanation,
            axis=1
        )
    )

    return explained


# ============================================================
# FASTAPI LIFESPAN
# ============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):

    global incidents_cache

    print("============================================")
    print(" CYBERSECURITY INCIDENT PRIORITIZATION")
    print("============================================")
    print("Loading Isolation Forest results...")
    print("============================================")

    incidents = load_incidents()

    if not incidents.empty:

        incidents = prioritize_incidents(
            incidents
        )

        print(
            "Phase 7 incident prioritization completed."
        )

        incidents = add_explanations(
            incidents
        )

        print(
            "Phase 8 incident explainability completed."
        )

        incidents_cache = incidents

        print(
            f"Final incidents available: "
            f"{len(incidents_cache)}"
        )

        print("\n===== PRIORITY SUMMARY =====")

        print(
            incidents_cache[
                "priority"
            ].value_counts()
        )

    else:

        incidents_cache = pd.DataFrame()

    yield

    print(
        "Shutting down incident prioritization engine..."
    )


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="Cybersecurity Incident Prioritization",
    description=(
        "AI-assisted cybersecurity anomaly "
        "detection and incident prioritization system"
    ),
    version="6.0",
    lifespan=lifespan,
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,

    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],

    allow_credentials=True,

    allow_methods=["*"],

    allow_headers=["*"],
)


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():

    return {
        "project":
            "Cybersecurity Incident Prioritization",

        "status":
            "running",

        "dataset":
            "cybersecurity_intrusion_cleaned.csv",

        "records":
            len(incidents_cache)
    }


# ============================================================
# GET INCIDENTS
# ============================================================

@app.get("/incidents")
def get_incidents():

    if incidents_cache.empty:

        return {
            "count": 0,
            "incidents": []
        }

    clean_data = incidents_cache.where(
        pd.notnull(incidents_cache),
        None
    )

    return {
        "count":
            len(clean_data),

        "incidents":
            clean_data.to_dict(
                orient="records"
            )
    }


# ============================================================
# GET SINGLE INCIDENT
# ============================================================

@app.get("/incidents/{incident_id}")
def get_incident(incident_id: int):

    if incidents_cache.empty:

        raise HTTPException(
            status_code=404,
            detail="No incidents available"
        )

    incident = incidents_cache[
        incidents_cache["incident_id"]
        == incident_id
    ]

    if incident.empty:

        raise HTTPException(
            status_code=404,
            detail="Incident not found"
        )

    record = incident.iloc[0]

    record = record.where(
        pd.notnull(record),
        None
    )

    return record.to_dict()


# ============================================================
# SUMMARY
# ============================================================

@app.get("/summary")
def get_summary():

    if incidents_cache.empty:

        return {
            "total_incidents": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }

    priority_counts = (
        incidents_cache["priority"]
        .value_counts()
    )

    return {

        "total_incidents":
            len(incidents_cache),

        "critical":
            int(
                priority_counts.get(
                    "CRITICAL",
                    0
                )
            ),

        "high":
            int(
                priority_counts.get(
                    "HIGH",
                    0
                )
            ),

        "medium":
            int(
                priority_counts.get(
                    "MEDIUM",
                    0
                )
            ),

        "low":
            int(
                priority_counts.get(
                    "LOW",
                    0
                )
            )
    }


# ============================================================
# RUN SERVER
# ============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=8000,
        reload=True
    )