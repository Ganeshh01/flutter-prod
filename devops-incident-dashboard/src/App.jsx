
import { useEffect, useState } from "react";
import IncidentOperations from "./components/IncidentOperations";

import {
  Activity,
  AlertTriangle,
  Boxes,
  CheckCircle2,
  Cpu,
  Server,
  ShieldCheck,
  Clock,
  History,
  RefreshCw,
} from "lucide-react";

import Sidebar from "./components/Sidebar";
import ChatPanel from "./components/ChatPanel";

import {
  getHealth,
  getClusterOverview,
  getAlerts,
} from "./services/api";


function Card({ icon: Icon, title, value, note }) {
  return (
    <div className="card">
      <Icon />
      <small>{title}</small>
      <strong>{value}</strong>
      <span>{note}</span>
    </div>
  );
}


function IncidentStatus({ status }) {
  const styles = {
    active: {
      color: "#fca5a5",
      background: "rgba(239,68,68,0.14)",
      border: "1px solid rgba(239,68,68,0.35)",
      label: "Active",
    },
    historical: {
      color: "#94a3b8",
      background: "rgba(148,163,184,0.12)",
      border: "1px solid rgba(148,163,184,0.25)",
      label: "Historical",
    },
    unverified: {
      color: "#fcd34d",
      background: "rgba(245,158,11,0.13)",
      border: "1px solid rgba(245,158,11,0.3)",
      label: "Unverified",
    },
    resolved: {
      color: "#86efac",
      background: "rgba(34,197,94,0.12)",
      border: "1px solid rgba(34,197,94,0.3)",
      label: "Resolved",
    },
  };

  const current = styles[status] || styles.active;

  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        padding: "6px 11px",
        borderRadius: "20px",
        fontSize: "12px",
        fontWeight: 700,
        color: current.color,
        background: current.background,
        border: current.border,
        whiteSpace: "nowrap",
      }}
    >
      {current.label}
    </span>
  );
}


function IncidentPanel({ alerts = [] }) {
  const panelStyle = {
    background: "#111c2d",
    border: "1px solid #26364d",
    borderRadius: "14px",
    padding: "20px",
    color: "#e2e8f0",
  };

  if (alerts.length === 0) {
    return (
      <section className="panel" style={panelStyle}>
        <div className="panel-header">
          <div>
            <small style={{ color: "#60a5fa", fontWeight: 700 }}>
              INCIDENT MANAGEMENT
            </small>
            <h2 style={{ color: "#f8fafc", margin: "8px 0" }}>
              Detected incidents
            </h2>
          </div>
        </div>

        <div
          style={{
            marginTop: "18px",
            padding: "22px",
            borderRadius: "10px",
            background: "#172438",
            border: "1px solid #2d4059",
            color: "#cbd5e1",
          }}
        >
          <h3 style={{ margin: "0 0 8px", color: "#86efac" }}>
            No active incidents detected
          </h3>
          <p style={{ margin: 0, fontSize: "13px", color: "#94a3b8" }}>
            No incident alerts are currently available from the backend.
          </p>
        </div>
      </section>
    );
  }

  return (
    <section className="panel" style={panelStyle}>
      <div
        className="panel-header"
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: "14px",
        }}
      >
        <div>
          <small
            style={{
              color: "#60a5fa",
              fontWeight: 700,
              letterSpacing: "0.8px",
            }}
          >
            INCIDENT MANAGEMENT
          </small>

          <h2 style={{ color: "#f8fafc", margin: "8px 0 5px" }}>
            Detected incidents
          </h2>

          <p style={{ color: "#94a3b8", margin: 0, fontSize: "13px" }}>
            Kubernetes alerts, failure signals and historical events
          </p>
        </div>

        <span
          style={{
            background: "rgba(59,130,246,0.14)",
            color: "#93c5fd",
            border: "1px solid rgba(59,130,246,0.3)",
            borderRadius: "20px",
            padding: "7px 13px",
            fontSize: "12px",
            fontWeight: 700,
          }}
        >
          {alerts.length} alerts
        </span>
      </div>

      <div
        style={{
          display: "flex",
          flexDirection: "column",
          gap: "13px",
          marginTop: "22px",
        }}
      >
        {alerts.map((alert, index) => {
          const status = alert.status || "active";
          const events = Array.isArray(alert.events) ? alert.events : [];

          const isHistorical = status === "historical";
          const severity = (alert.severity || "unknown").toLowerCase();

          const severityColor =
            severity === "critical"
              ? "#fca5a5"
              : severity === "high"
              ? "#fdba74"
              : severity === "medium"
              ? "#fcd34d"
              : "#94a3b8";

          return (
            <article
              key={`${alert.namespace || "default"}-${alert.resource}-${alert.type}-${index}`}
              style={{
                background: "#172438",
                border: `1px solid ${
                  isHistorical ? "#334155" : "rgba(239,68,68,0.3)"
                }`,
                borderLeft: `4px solid ${
                  isHistorical ? "#64748b" : "#ef4444"
                }`,
                borderRadius: "11px",
                padding: "17px 19px",
                color: "#e2e8f0",
                transition: "border-color 0.2s ease",
              }}
            >
              {/* Incident title and status */}
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "flex-start",
                  flexWrap: "wrap",
                  gap: "12px",
                }}
              >
                <div>
                  <h3
                    style={{
                      margin: "0 0 8px",
                      color: "#f8fafc",
                      fontSize: "16px",
                      fontWeight: 700,
                    }}
                  >
                    {alert.type || "Kubernetes Incident"}
                  </h3>

                  <div style={{ fontSize: "13px", color: "#94a3b8" }}>
                    {alert.resource_kind || "Resource"}:{" "}
                    <strong style={{ color: "#cbd5e1" }}>
                      {alert.resource || "Unknown"}
                    </strong>
                  </div>
                </div>

                <IncidentStatus status={status} />
              </div>

              {/* Incident metadata */}
              <div
                style={{
                  display: "flex",
                  flexWrap: "wrap",
                  gap: "10px 22px",
                  marginTop: "17px",
                  fontSize: "12px",
                  color: "#cbd5e1",
                }}
              >
                <span>
                  <span style={{ color: "#64748b" }}>Namespace</span>
                  <br />
                  <strong>
                    {alert.namespace || "food-delivery"}
                  </strong>
                </span>

                <span>
                  <span style={{ color: "#64748b" }}>Severity</span>
                  <br />
                  <strong
                    style={{
                      color: severityColor,
                      textTransform: "uppercase",
                    }}
                  >
                    {severity}
                  </strong>
                </span>

                <span>
                  <span style={{ color: "#64748b" }}>Related events</span>
                  <br />
                  <strong>{alert.event_count ?? events.length ?? 1}</strong>
                </span>

                {alert.count != null && (
                  <span>
                    <span style={{ color: "#64748b" }}>Occurrences</span>
                    <br />
                    <strong>{alert.count}</strong>
                  </span>
                )}
              </div>

              {/* Event reasons */}
              {alert.reasons?.length > 0 && (
                <div style={{ marginTop: "16px" }}>
                  <div
                    style={{
                      color: "#94a3b8",
                      fontSize: "12px",
                      fontWeight: 700,
                      marginBottom: "9px",
                    }}
                  >
                    FAILURE SIGNALS
                  </div>

                  <div
                    style={{
                      display: "flex",
                      flexWrap: "wrap",
                      gap: "8px",
                    }}
                  >
                    {alert.reasons.map((reason, reasonIndex) => (
                      <span
                        key={`${reason}-${reasonIndex}`}
                        style={{
                          padding: "6px 10px",
                          background: "#24364e",
                          color: "#bfdbfe",
                          border: "1px solid #344b68",
                          borderRadius: "6px",
                          fontSize: "12px",
                        }}
                      >
                        {reason}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Incident details */}
              <div
                style={{
                  marginTop: "16px",
                  padding: "13px 15px",
                  borderRadius: "8px",
                  background: "#101b2b",
                  border: "1px solid #293b52",
                  fontSize: "13px",
                  lineHeight: 1.6,
                  overflowWrap: "anywhere",
                }}
              >
                <div
                  style={{
                    color: "#93c5fd",
                    fontWeight: 700,
                    marginBottom: "5px",
                  }}
                >
                  INCIDENT DETAILS
                </div>

                <p style={{ margin: 0, color: "#cbd5e1" }}>
                  {alert.message || "No additional details available."}
                </p>
              </div>

              {/* Original Kubernetes events */}
              {events.length > 0 && (
                <details style={{ marginTop: "15px" }}>
                  <summary
                    style={{
                      cursor: "pointer",
                      color: "#93c5fd",
                      fontSize: "13px",
                      fontWeight: 600,
                    }}
                  >
                    View Kubernetes events ({events.length})
                  </summary>

                  <div
                    style={{
                      display: "flex",
                      flexDirection: "column",
                      gap: "9px",
                      marginTop: "12px",
                    }}
                  >
                    {events.map((event, eventIndex) => (
                      <div
                        key={event.name || eventIndex}
                        style={{
                          padding: "12px",
                          borderLeft: "3px solid #64748b",
                          background: "#101b2b",
                          borderRadius: "6px",
                          color: "#cbd5e1",
                          fontSize: "12px",
                        }}
                      >
                        <strong style={{ color: "#f8fafc" }}>
                          {event.reason || "Kubernetes event"}
                        </strong>

                        <p
                          style={{
                            margin: "6px 0",
                            overflowWrap: "anywhere",
                          }}
                        >
                          {event.message}
                        </p>

                        <small style={{ color: "#94a3b8" }}>
                          Occurrences: {event.count ?? 1}
                          {" · "}
                          {event.last_timestamp || "Timestamp unavailable"}
                        </small>
                      </div>
                    ))}
                  </div>
                </details>
              )}

              {/* Last event */}
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "7px",
                  marginTop: "15px",
                  color: "#94a3b8",
                  fontSize: "12px",
                }}
              >
                <Clock size={14} />
                Last event: {alert.last_timestamp || "Unavailable"}
              </div>
            </article>
          );
        })}
      </div>
    </section>
  );
}



export default function App() {
  const [active, setActive] = useState("Overview");
  const [health, setHealth] = useState(null);
  const [overview, setOverview] = useState(null);
  const [error, setError] = useState("");
  const [alerts, setAlerts] = useState([]);
  const [lastUpdated, setLastUpdated] = useState(null);

  // Fetch backend health and live Kubernetes data.
  useEffect(() => {
    let isMounted = true;

    const fetchDashboardData = async () => {
      try {
        const [healthData, overviewData, alertsData] =
          await Promise.all([
            getHealth(),
            getClusterOverview(),
            getAlerts(),
          ]);

        if (!isMounted) return;

        setHealth(healthData);
        setOverview(overviewData);

        setAlerts(
          Array.isArray(alertsData.alerts)
            ? alertsData.alerts
            : []
        );

        setLastUpdated(new Date());
        setError("");
      } catch (err) {
        console.error("Dashboard refresh error:", err);

        if (isMounted) {
          setError(err.message || "Unable to reach backend");
        }
      }
    };

    // Initial fetch.
    fetchDashboardData();

    // Refresh every 5 seconds.
    const intervalId = setInterval(
      fetchDashboardData,
      5000
    );

    // Clean up polling.
    return () => {
      isMounted = false;
      clearInterval(intervalId);
    };
  }, []);

  const connected = health?.status === "ok";

  // Live Pod information.
  const podsReady = overview?.pods?.ready ?? 0;
  const podsTotal = overview?.pods?.total ?? 0;

  // Structured Pod CPU, memory and status information.
  const podMetrics = Array.isArray(overview?.pod_metrics)
    ? overview.pod_metrics
    : [];

  // Deployment count.
  const deploymentCount = overview?.deployments?.length ?? 0;

  // Live node metrics.
  const node = overview?.node_metrics?.[0];

  // Separate active, historical and unverified incidents.
  // Alerts without a status field are treated as active
  // for compatibility with the existing backend alerts.
  const activeAlerts = alerts.filter(
    (alert) =>
      alert.status !== "historical" &&
      alert.status !== "unverified"
  );

  const historicalAlerts = alerts.filter(
    (alert) => alert.status === "historical"
  );

  const unverifiedAlerts = alerts.filter(
    (alert) => alert.status === "unverified"
  );

  const criticalAlerts = activeAlerts.filter(
    (alert) => alert.severity === "critical"
  );

  return (
    <div className="shell">

      {/* Sidebar */}
      <Sidebar
        active={active}
        onNavigate={setActive}
      />

      <main>

        {/* Top navigation */}
        <div className="top">
          <div>
            <small>
              CLUSTERS / DOCKER-DESKTOP / FOOD-DELIVERY
            </small>

            <h1>{active}</h1>
          </div>

          <span className={connected ? "green" : "red"}>
            {connected
              ? "● API connected"
              : "● API disconnected"}
          </span>
        </div>

        {/* Backend error */}
        {error && (
          <div className="error">
            Backend unavailable: {error}.
            Start FastAPI on port 8000.
          </div>
        )}

        {/* Cluster introduction */}
        <section className="intro">
          <div>
            <small>KUBERNETES OPERATIONS CENTER</small>

            <h2>Cluster overview</h2>

            <p>
              Monitor workloads and investigate incidents
              with AI assistance.
            </p>
          </div>

          <span>
            ● Namespace <b>food-delivery</b>
          </span>
        </section>

        {/* Dashboard summary cards */}
        <div className="cards">

          <Card
            icon={Boxes}
            title="Pods ready"
            value={
              overview
                ? `${podsReady}/${podsTotal}`
                : "Loading..."
            }
            note="Live Kubernetes Pod status"
          />

          <Card
            icon={Server}
            title="Deployments"
            value={
              overview
                ? deploymentCount
                : "Loading..."
            }
            note="Selected namespace"
          />

          <Card
            icon={AlertTriangle}
            title="Active alerts"
            value={activeAlerts.length}
            note={
              activeAlerts.length > 0
                ? `${criticalAlerts.length} critical alerts`
                : "No active alerts"
            }
          />

          <Card
            icon={History}
            title="Historical incidents"
            value={historicalAlerts.length}
            note="Previously detected incidents"
          />

          <Card
            icon={ShieldCheck}
            title="AI agent"
            value={connected ? "Online" : "Offline"}
            note={
              health?.service || "Waiting for backend"
            }
          />

        </div>

        {/* Incident summary */}
        <section className="panel">
          <div className="panel-header">
            <div>
              <small>INCIDENT SUMMARY</small>
              <h2>Incident overview</h2>
              <p>
                Grouped incidents collected from Kubernetes
              </p>
            </div>

            <span className="live-badge">
              <RefreshCw
                size={12}
                style={{ display: "inline", marginRight: "5px" }}
              />
              Auto refresh
            </span>
          </div>

          <div
            className="cards"
            style={{ marginTop: "18px" }}
          >
            <Card
              icon={AlertTriangle}
              title="Active"
              value={activeAlerts.length}
              note="Require investigation"
            />

            <Card
              icon={History}
              title="Historical"
              value={historicalAlerts.length}
              note="Resolved or inactive records"
            />

            <Card
              icon={Clock}
              title="Unverified"
              value={unverifiedAlerts.length}
              note="Resource state not confirmed"
            />

            <Card
              icon={Activity}
              title="Total grouped"
              value={alerts.length}
              note="Unique grouped alert records"
            />
          </div>

          {lastUpdated && (
            <p className="table-footer">
              Last updated: {lastUpdated.toLocaleTimeString()}
              {" · "}Refresh interval: 5 seconds
            </p>
          )}
        </section>

        {/* Node resource metrics */}
        <section className="panel">
          <header>
            <div>
              <small>CLUSTER RESOURCE USAGE</small>
              <h2>Node metrics</h2>
            </div>
          </header>

          {node ? (
            <div className="cards">

              <Card
                icon={Cpu}
                title="Node CPU"
                value={node.cpu_percent}
                note={`${node.cpu} used`}
              />

              <Card
                icon={Server}
                title="Node Memory"
                value={node.memory_percent}
                note={`${node.memory} used`}
              />

            </div>
          ) : (
            <p>Loading node metrics...</p>
          )}
        </section>

        {/* Kubernetes Pod Resource Table */}
        <section className="panel pod-resource-panel">

          <div className="panel-header">
            <div>
              <small>KUBERNETES WORKLOADS</small>

              <h2>Pod Resource Usage</h2>

              <p>
                Live CPU, memory and Pod status
              </p>
            </div>

            <span className="live-badge">
              ● Live
            </span>
          </div>

          <div className="table-wrapper">

            <table className="resource-table">

              <thead>
                <tr>
                  <th>Pod Name</th>
                  <th>Status</th>
                  <th>CPU Usage</th>
                  <th>Memory Usage</th>
                </tr>
              </thead>

              <tbody>

                {podMetrics.map((pod) => (
                  <tr key={pod.name}>

                    <td className="pod-name">
                      {pod.name}
                    </td>

                    <td>
                      <span
                        className={
                          pod.status === "Running"
                            ? "status-running"
                            : "status-warning"
                        }
                      >
                        {pod.status || "Unknown"}
                      </span>
                    </td>

                    <td>{pod.cpu}</td>

                    <td>{pod.memory}</td>

                  </tr>
                ))}

                {podMetrics.length === 0 && (
                  <tr>
                    <td colSpan="4">
                      No Pod metrics available
                    </td>
                  </tr>
                )}

              </tbody>

            </table>

          </div>

          <p className="table-footer">
            Metrics collected through Kubernetes Metrics Server.
            Refresh interval: 5 seconds.
          </p>

        </section>

        {/* Grouped incidents and historical events */}
        <IncidentPanel alerts={alerts} />
        <IncidentOperations />

        {/* Incident lifecycle and AI chat */}
        <div className="grid">

          <div className="left">

            <section className="panel workflow">

              <header>
                <div>
                  <small>INCIDENT LIFECYCLE</small>

                  <h2>AI-assisted response workflow</h2>
                </div>

                <span>Human approval required</span>
              </header>

              {[
                [
                  "01",
                  "Detect failure",
                  "Pod and deployment health",
                  Activity,
                ],
                [
                  "02",
                  "Collect evidence",
                  "Status, events and application logs",
                  Boxes,
                ],
                [
                  "03",
                  "Analyse with AI",
                  "Gemini incident analysis",
                  Cpu,
                ],
                [
                  "04",
                  "Identify root cause",
                  "Evidence-backed findings",
                  AlertTriangle,
                ],
                [
                  "05",
                  "Recommend remediation",
                  "Proposed fix and verification",
                  ShieldCheck,
                ],
                [
                  "06",
                  "Approve and verify",
                  "Human approval and recovery",
                  CheckCircle2,
                ],
              ].map(([number, title, description, Icon]) => (
                <div className="step" key={number}>

                  <em>{number}</em>

                  <Icon />

                  <div>
                    <b>{title}</b>
                    <small>{description}</small>
                  </div>

                  <label>Ready to investigate</label>

                </div>
              ))}

            </section>

            {/* Live metrics information */}
            <div className="panel note">
              <b>Live Kubernetes integration</b>

              <p>
                Cluster health, deployment status, CPU and memory
                are collected from the Kubernetes API and
                Metrics Server through FastAPI.
              </p>
            </div>

          </div>

          {/* AI Chat */}
          <ChatPanel />

        </div>

        <footer>
          OpsPilot AI · Read-only collection by default ·
          Remediation requires human approval
        </footer>

      </main>
    </div>
  );
}
