import glob
import pandas as pd
from fastapi import FastAPI
from contextlib import asynccontextmanager

df_cache = pd.DataFrame()

def load_all_data():
    csv_files = glob.glob("data/*.csv")
    if not csv_files:
        print("WARNING: No CSV files found in 'data/' folder!")
        return pd.DataFrame()
    
    print("Loading CICIDS dataset files into memory...")
    df_list = []
    for file in csv_files:
        try:
            temp_df = pd.read_csv(file)
            # Standardize column headers: strip spaces, lowercase, replace spaces/hyphens with underscores
            temp_df.columns = temp_df.columns.str.strip().str.lower().str.replace(' ', '_').str.replace('-', '_')
            df_list.append(temp_df)
        except Exception as e:
            print(f"Error loading {file}: {e}")

    if not df_list:
        return pd.DataFrame()

    df = pd.concat(df_list, ignore_index=True)
    print("Dataset successfully loaded!")
    return df

@asynccontextmanager
async def lifespan(app: FastAPI):
    global df_cache
    df_cache = load_all_data()
    yield

app = FastAPI(title="SOC Alert Correlation Engine (CICIDS)", lifespan=lifespan)

@app.get("/")
def home():
    return {"status": "SOC Engine Running", "endpoint": "/incidents"}

@app.get("/incidents")
def generate_incidents():
    if df_cache.empty:
        return {"error": "No data available. Check that CSV files are inside the 'data/' folder."}

    # Filter out normal 'BENIGN' traffic to focus purely on attack alerts
    attack_df = df_cache[df_cache['label'].str.upper() != 'BENIGN'].copy() if 'label' in df_cache.columns else df_cache.copy()

    if attack_df.empty:
        # Fallback if dataset only contains BENIGN rows or labels aren't string-mapped
        attack_df = df_cache

    # --- PHASE 5: ALERT CORRELATION ---
    # Correlate alerts based on Target Destination Port and Attack Label
    grouped_alerts = attack_df.groupby(['destination_port', 'label'])
    incidents = []
    
    # --- PHASE 6: INCIDENT FORMATION ---
    for incident_idx, ((dest_port, attack_label), group) in enumerate(grouped_alerts, start=1):
        alert_count = len(group)
        
        # Calculate dynamic severity based on alert count & volume
        if alert_count >= 100 or attack_label.lower() in ['dos', 'ddos', 'bot']:
            severity = "CRITICAL"
        elif alert_count >= 10:
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        # Aggregate flow metrics across the grouped alerts
        total_fwd_pkts = int(group['total_fwd_packets'].sum()) if 'total_fwd_packets' in group.columns else 0
        total_bwd_pkts = int(group['total_backward_packets'].sum()) if 'total_backward_packets' in group.columns else 0
        avg_flow_duration = float(group['flow_duration'].mean()) if 'flow_duration' in group.columns else 0.0

        incident_obj = {
            "incident_id": f"INC-{incident_idx:03d}",
            "destination_port": int(dest_port),
            "attack_type": str(attack_label),
            "severity": severity,
            "alert_count": alert_count,
            "metrics": {
                "total_forward_packets": total_fwd_pkts,
                "total_backward_packets": total_bwd_pkts,
                "average_flow_duration_ms": round(avg_flow_duration, 2)
            }
        }
        incidents.append(incident_obj)

    # Sort incidents so highest threat activity appears first
    incidents = sorted(incidents, key=lambda x: x['alert_count'], reverse=True)

    return {
        "total_incidents": len(incidents),
        "incidents": incidents
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)