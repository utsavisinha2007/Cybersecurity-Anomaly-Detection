import { useEffect, useState } from "react";
import "./App.css";

const API_URL = "http://127.0.0.1:8000";

function App() {
  const [incidents, setIncidents] = useState([]);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    fetchIncidents();
  }, []);

  async function fetchIncidents() {
    try {
      setLoading(true);
      setError("");

      const response = await fetch(`${API_URL}/incidents`);

      if (!response.ok) {
        throw new Error("Failed to load incidents");
      }

      const data = await response.json();

      setIncidents(data.incidents || []);
    } catch (err) {
      console.error(err);
      setError(
        "Unable to load incidents. Make sure the FastAPI backend is running."
      );
    } finally {
      setLoading(false);
    }
  }

  const critical = incidents.filter(
    (i) =>
      String(i.final_priority || i.priority).toUpperCase() === "CRITICAL"
  ).length;

  const high = incidents.filter(
    (i) => String(i.final_priority || i.priority).toUpperCase() === "HIGH"
  ).length;

  const medium = incidents.filter(
    (i) => String(i.final_priority || i.priority).toUpperCase() === "MEDIUM"
  ).length;

  const low = incidents.filter(
    (i) => String(i.final_priority || i.priority).toUpperCase() === "LOW"
  ).length;

  return (
    <div className="app">
      <header className="header">
        <div>
          <h1>Cyber Incident Dashboard</h1>
          <p>Cybersecurity Incident Prioritization System</p>
        </div>

        <button onClick={fetchIncidents}>Refresh</button>
      </header>

      <main className="container">
        <section className="summary">
          <div className="card">
            <h3>Total Incidents</h3>
            <strong>{incidents.length}</strong>
          </div>

          <div className="card critical">
            <h3>Critical</h3>
            <strong>{critical}</strong>
          </div>

          <div className="card high">
            <h3>High</h3>
            <strong>{high}</strong>
          </div>

          <div className="card medium">
            <h3>Medium</h3>
            <strong>{medium}</strong>
          </div>

          <div className="card low">
            <h3>Low</h3>
            <strong>{low}</strong>
          </div>
        </section>

        {loading && <p className="message">Loading incidents...</p>}

        {error && <p className="error">{error}</p>}

        {!loading && !error && (
          <section className="content">
            <div className="incident-list">
              <h2>Incidents</h2>

              {incidents.length === 0 ? (
                <p>No incidents found.</p>
              ) : (
                <table>
                  <thead>
                    <tr>
                      <th>Incident ID</th>
                      <th>Risk Score</th>
                      <th>Priority</th>
                      <th>Alerts</th>
                    </tr>
                  </thead>

                  <tbody>
                    {incidents.map((incident) => {
                      const priority = String(
                        incident.final_priority || incident.priority || "UNKNOWN"
                      ).toUpperCase();

                      return (
                        <tr
                          key={incident.incident_id}
                          onClick={() => setSelectedIncident(incident)}
                        >
                          <td>{incident.incident_id}</td>

                          <td>
                            {incident.risk_score ?? "N/A"}
                          </td>

                          <td>
                            <span className={`priority ${priority.toLowerCase()}`}>
                              {priority}
                            </span>
                          </td>

                          <td>{incident.alert_count ?? "N/A"}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              )}
            </div>

            <div className="details">
              <h2>Incident Details</h2>

              {!selectedIncident ? (
                <p>Select an incident from the table.</p>
              ) : (
                <>
                  <div className="detail-header">
                    <h3>
                      Incident #{selectedIncident.incident_id}
                    </h3>

                    <span
                      className={`priority ${String(
                        selectedIncident.final_priority ||
                          selectedIncident.priority ||
                          "UNKNOWN"
                      ).toLowerCase()}`}
                    >
                      {String(
                        selectedIncident.final_priority ||
                          selectedIncident.priority ||
                          "UNKNOWN"
                      ).toUpperCase()}
                    </span>
                  </div>

                  <div className="evidence">
                    <p>
                      <b>Risk Score:</b>{" "}
                      {selectedIncident.risk_score ?? "N/A"}
                    </p>

                    <p>
                      <b>Anomaly Score:</b>{" "}
                      {selectedIncident.anomaly_score ?? "N/A"}
                    </p>

                    <p>
                      <b>Related Alerts:</b>{" "}
                      {selectedIncident.related_alerts ??
                        selectedIncident.alert_count ??
                        "N/A"}
                    </p>

                    <p>
                      <b>Repeated Activity:</b>{" "}
                      {String(selectedIncident.repeated_activity)}
                    </p>

                    <p>
                      <b>Asset Impact:</b>{" "}
                      {selectedIncident.asset_impact ?? "N/A"}
                    </p>
                  </div>

                  {selectedIncident.explanation && (
                    <div className="explanation">
                      <h3>Why was this incident prioritized?</h3>

                      {selectedIncident.explanation.reasons?.map(
                        (reason, index) => (
                          <p key={index}>✓ {reason}</p>
                        )
                      )}
                    </div>
                  )}
                </>
              )}
            </div>
          </section>
        )}
      </main>
    </div>
  );
}

export default App;