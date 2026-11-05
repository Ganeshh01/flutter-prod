
import { useCallback, useEffect, useState } from "react";

import {
  getIncidents,
  getIncidentActions,
  approveAction,
  rejectAction,
  executeAction,
  getAudit,
} from "../services/api";

const colors = {
  panel: "#111c2d",
  card: "#172438",
  nested: "#101b2b",
  border: "#344b68",
  text: "#e2e8f0",
  heading: "#f8fafc",
  muted: "#94a3b8",
  blue: "#93c5fd",
  green: "#86efac",
  red: "#fca5a5",
  yellow: "#fcd34d",
};

const cardStyle = {
  background: colors.card,
  border: `1px solid ${colors.border}`,
  borderRadius: "10px",
  padding: "16px",
  marginTop: "12px",
  color: colors.text,
};

const nestedStyle = {
  background: colors.nested,
  border: `1px solid ${colors.border}`,
  borderRadius: "8px",
  padding: "13px",
  marginTop: "10px",
  color: colors.text,
};

const headingStyle = {
  color: colors.heading,
  marginTop: 0,
};

const mutedStyle = {
  color: colors.muted,
  fontSize: "13px",
};

const codeStyle = {
  display: "block",
  background: "#0b1422",
  color: colors.blue,
  border: `1px solid ${colors.border}`,
  borderRadius: "7px",
  padding: "11px",
  marginTop: "9px",
  fontSize: "12px",
  lineHeight: 1.6,
  whiteSpace: "pre-wrap",
  overflowWrap: "anywhere",
};

function StatusBadge({ status }) {
  const value = (status || "unknown").toLowerCase();

  let color = colors.muted;
  let background = "rgba(148,163,184,0.12)";

  if (
    ["completed", "executed", "approved", "resolved"].includes(value)
  ) {
    color = colors.green;
    background = "rgba(34,197,94,0.12)";
  } else if (
    ["failed", "rejected", "critical", "active"].includes(value)
  ) {
    color = colors.red;
    background = "rgba(239,68,68,0.13)";
  } else if (
    ["investigating", "pending_approval", "warning"].includes(value)
  ) {
    color = colors.yellow;
    background = "rgba(245,158,11,0.13)";
  }

  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        padding: "6px 10px",
        borderRadius: "20px",
        color,
        background,
        border: `1px solid ${color}55`,
        fontSize: "11px",
        fontWeight: 700,
        whiteSpace: "nowrap",
      }}
    >
      {(status || "Unknown").replaceAll("_", " ")}
    </span>
  );
}

function ActionButton({ children, onClick, disabled, variant = "primary" }) {
  const variants = {
    primary: {
      background: "#1d4ed8",
      color: "#ffffff",
      border: "1px solid #3b82f6",
    },
    danger: {
      background: "rgba(239,68,68,0.13)",
      color: "#fca5a5",
      border: "1px solid rgba(239,68,68,0.4)",
    },
    success: {
      background: "rgba(34,197,94,0.14)",
      color: "#86efac",
      border: "1px solid rgba(34,197,94,0.4)",
    },
  };

  return (
    <button
      type="button"
      disabled={disabled}
      onClick={onClick}
      style={{
        ...variants[variant],
        borderRadius: "7px",
        padding: "9px 14px",
        fontSize: "12px",
        fontWeight: 700,
        cursor: disabled ? "not-allowed" : "pointer",
        opacity: disabled ? 0.5 : 1,
      }}
    >
      {children}
    </button>
  );
}

export default function IncidentOperations() {
  const [incidents, setIncidents] = useState([]);
  const [actions, setActions] = useState({});
  const [audit, setAudit] = useState([]);
  const [approver, setApprover] = useState("Ganesh");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  const refresh = useCallback(async () => {
    try {
      const [incidentData, auditData] = await Promise.all([
        getIncidents(),
        getAudit(),
      ]);

      const records = incidentData.incidents || [];

      setIncidents(records);
      setAudit(auditData.events || []);

      const actionResults = await Promise.all(
        records.map(async (incident) => {
          try {
            const result = await getIncidentActions(
              incident.incident_key
            );

            return [
              incident.incident_key,
              result.actions || [],
            ];
          } catch {
            return [incident.incident_key, []];
          }
        })
      );

      setActions(Object.fromEntries(actionResults));
      setError("");
    } catch (err) {
      setError(
        err.response?.data?.detail ||
          err.message ||
          "Unable to load incident operations"
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();

    const interval = setInterval(refresh, 5000);

    return () => clearInterval(interval);
  }, [refresh]);

  async function handleAction(type, incidentKey, actionId) {
    const key = `${incidentKey}:${actionId}`;

    try {
      setBusy(key);
      setError("");
      setMessage("");

      let result;

      if (type === "approve") {
        result = await approveAction(
          incidentKey,
          actionId,
          approver
        );
      } else if (type === "reject") {
        result = await rejectAction(incidentKey, actionId);
      } else {
        result = await executeAction(incidentKey, actionId);
      }

      setMessage(result.message || result.status || "Action completed");
      await refresh();
    } catch (err) {
      setError(
        err.response?.data?.detail ||
          err.message ||
          "Action failed"
      );
    } finally {
      setBusy("");
    }
  }

  return (
    <section
      className="panel"
      style={{
        background: colors.panel,
        color: colors.text,
        border: `1px solid ${colors.border}`,
        borderRadius: "14px",
        padding: "20px",
      }}
    >
      {/* Header */}
      <div
        className="panel-header"
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: "12px",
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
            AI INCIDENT OPERATIONS
          </small>

          <h2 style={{ color: colors.heading, margin: "8px 0" }}>
            Investigation & Response
          </h2>

          <p style={{ ...mutedStyle, margin: 0 }}>
            AI findings, human approval, execution and audit history
          </p>
        </div>

        <span
          style={{
            background: "rgba(59,130,246,0.13)",
            color: colors.blue,
            border: "1px solid rgba(59,130,246,0.3)",
            borderRadius: "20px",
            padding: "7px 12px",
            fontSize: "12px",
            fontWeight: 700,
          }}
        >
          {incidents.length} incidents
        </span>
      </div>

      {/* Loading and notifications */}
      {loading && (
        <p style={{ color: colors.muted }}>
          Loading incident operations...
        </p>
      )}

      {error && (
        <div
          style={{
            ...nestedStyle,
            color: colors.red,
            borderColor: "rgba(239,68,68,0.4)",
          }}
        >
          <strong>Request failed:</strong> {error}
        </div>
      )}

      {message && (
        <div
          style={{
            ...nestedStyle,
            color: colors.green,
            borderColor: "rgba(34,197,94,0.4)",
          }}
        >
          {message}
        </div>
      )}

      {!loading && incidents.length === 0 && (
        <div style={nestedStyle}>
          <h3 style={{ color: colors.green, marginTop: 0 }}>
            No incident investigations available
          </h3>
          <p style={mutedStyle}>
            The backend has not returned any incident investigations yet.
          </p>
        </div>
      )}

      {/* Incident cards */}
      {incidents.map((incident) => {
        const incidentActions =
          actions[incident.incident_key] || [];

        const analysis = incident.ai_analysis || {};
        const diagnosis = incident.diagnosis || {};

        return (
          <article
            key={incident.incident_key}
            style={{
              ...cardStyle,
              borderLeft: "4px solid #3b82f6",
            }}
          >
            {/* Incident heading */}
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                flexWrap: "wrap",
                gap: "10px",
              }}
            >
              <h3 style={{ ...headingStyle, marginBottom: 0 }}>
                {incident.alert?.resource || incident.incident_key}
              </h3>

              <StatusBadge status={incident.status} />
            </div>

            <p style={mutedStyle}>
              Incident ID: {incident.incident_key}
            </p>

            <p style={{ color: colors.text }}>
              <strong>Alert:</strong>{" "}
              {incident.alert?.type || "Kubernetes alert"}
            </p>

            <p style={{ color: colors.text }}>
              <strong>Severity:</strong>{" "}
              {incident.alert?.severity || "Unknown"}
            </p>

            <p style={{ color: colors.text }}>
              <strong>Incident status:</strong>{" "}
              {incident.status || "Unknown"}
            </p>

            <div style={nestedStyle}>
              <strong style={{ color: colors.blue }}>
                Initial diagnosis
              </strong>
              <p style={{ marginBottom: 0, lineHeight: 1.6 }}>
                {diagnosis.summary || "Diagnosis not available yet."}
              </p>
            </div>

            {/* Root cause analysis */}
            <div style={{ marginTop: "20px" }}>
              <h3 style={headingStyle}>AI root cause analysis</h3>

              {analysis.causes?.length ? (
                analysis.causes.map((cause, index) => (
                  <div key={index} style={nestedStyle}>
                    <p style={{ color: colors.text, lineHeight: 1.6 }}>
                      {cause.claim}
                    </p>

                    <small style={mutedStyle}>
                      Confidence: {cause.confidence || "Unknown"}
                      {" · "}
                      Evidence:{" "}
                      {(cause.evidence_ids || []).join(", ") || "None"}
                    </small>
                  </div>
                ))
              ) : (
                <p style={mutedStyle}>
                  No AI root causes available yet.
                </p>
              )}
            </div>

            {/* Remediation recommendations */}
            <div style={{ marginTop: "20px" }}>
              <h3 style={headingStyle}>
                AI remediation recommendations
              </h3>

              <div style={cardStyle}>
                {analysis.fixes?.length ? (
                  analysis.fixes.map((fix, index) => (
                    <div key={index} style={nestedStyle}>
                      <p style={{ color: colors.text, lineHeight: 1.6 }}>
                        {fix.description}
                      </p>

                      {fix.command && (
                        <code style={codeStyle}>
                          {fix.command}
                        </code>
                      )}

                      <p
                        style={{
                          color: colors.yellow,
                          fontSize: "12px",
                          fontWeight: 600,
                          marginBottom: 0,
                        }}
                      >
                        Recommendation only — not executed.
                      </p>
                    </div>
                  ))
                ) : (
                  <p style={mutedStyle}>
                    No remediation recommendations available.
                  </p>
                )}
              </div>
            </div>

            {/* Human approval and actions */}
            <div style={{ marginTop: "22px" }}>
              <h3 style={headingStyle}>
                Human approval & actions
              </h3>

              <label
                style={{
                  display: "block",
                  color: colors.text,
                  fontSize: "13px",
                  fontWeight: 600,
                }}
              >
                Approver name

                <input
                  value={approver}
                  onChange={(event) => setApprover(event.target.value)}
                  placeholder="Enter approver name"
                  style={{
                    display: "block",
                    width: "100%",
                    maxWidth: "280px",
                    boxSizing: "border-box",
                    background: colors.nested,
                    color: colors.heading,
                    border: `1px solid ${colors.border}`,
                    borderRadius: "7px",
                    padding: "10px",
                    marginTop: "7px",
                    marginBottom: "14px",
                    outline: "none",
                  }}
                />
              </label>

              {incidentActions.length === 0 && (
                <p style={mutedStyle}>
                  No proposed actions available for this incident.
                </p>
              )}

              {incidentActions.map((action) => {
                const busyKey =
                  `${incident.incident_key}:${action.id}`;

                const isBusy = busy === busyKey;

                return (
                  <div key={action.id} style={nestedStyle}>
                    <div
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        flexWrap: "wrap",
                        gap: "10px",
                      }}
                    >
                      <strong style={{ color: colors.heading }}>
                        {action.id}: {action.description}
                      </strong>

                      <StatusBadge status={action.status} />
                    </div>

                    <p style={{ color: colors.text }}>
                      Status: {action.status}
                    </p>

                    {action.command?.length > 0 && (
                      <code style={codeStyle}>
                        {action.command.join(" ")}
                      </code>
                    )}

                    {action.changes_environment && (
                      <p
                        style={{
                          color: colors.yellow,
                          fontSize: "12px",
                        }}
                      >
                        This action changes the environment.
                        Review it carefully before approval.
                      </p>
                    )}

                    <div
                      style={{
                        display: "flex",
                        flexWrap: "wrap",
                        gap: "9px",
                        marginTop: "14px",
                      }}
                    >
                      {action.status === "pending_approval" && (
                        <>
                          <ActionButton
                            variant="success"
                            disabled={isBusy || !approver.trim()}
                            onClick={() =>
                              handleAction(
                                "approve",
                                incident.incident_key,
                                action.id
                              )
                            }
                          >
                            {isBusy ? "Processing..." : "Approve"}
                          </ActionButton>

                          <ActionButton
                            variant="danger"
                            disabled={isBusy}
                            onClick={() =>
                              handleAction(
                                "reject",
                                incident.incident_key,
                                action.id
                              )
                            }
                          >
                            Reject
                          </ActionButton>
                        </>
                      )}

                      {action.status === "approved" && (
                        <ActionButton
                          variant="primary"
                          disabled={isBusy}
                          onClick={() =>
                            handleAction(
                              "execute",
                              incident.incident_key,
                              action.id
                            )
                          }
                        >
                          {isBusy
                            ? "Executing..."
                            : "Execute approved action"}
                        </ActionButton>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Verification */}
            <div style={{ marginTop: "22px" }}>
              <h3 style={headingStyle}>Verification checks</h3>

              {analysis.verification?.length ? (
                analysis.verification.map((item, index) => (
                  <code key={index} style={codeStyle}>
                    {item.command}
                  </code>
                ))
              ) : (
                <p style={mutedStyle}>
                  No verification commands available.
                </p>
              )}
            </div>
          </article>
        );
      })}

      {/* Audit history */}
      <div style={{ marginTop: "28px" }}>
        <h3 style={headingStyle}>Audit history</h3>

        {audit.length === 0 ? (
          <div style={nestedStyle}>
            <p style={mutedStyle}>
              No audit events recorded yet.
            </p>
          </div>
        ) : (
          <div
            style={{
              ...nestedStyle,
              overflowX: "auto",
              padding: "0",
            }}
          >
            <table
              style={{
                width: "100%",
                borderCollapse: "collapse",
                textAlign: "left",
                minWidth: "550px",
                color: colors.text,
                fontSize: "12px",
              }}
            >
              <thead>
                <tr style={{ background: "#1d3048" }}>
                  {["Event", "Action", "Approver", "Time"].map(
                    (heading) => (
                      <th
                        key={heading}
                        style={{
                          padding: "13px",
                          color: colors.blue,
                          borderBottom: `1px solid ${colors.border}`,
                        }}
                      >
                        {heading}
                      </th>
                    )
                  )}
                </tr>
              </thead>

              <tbody>
                {audit.slice().reverse().map((event, index) => (
                  <tr
                    key={`${event.ts}-${index}`}
                    style={{
                      borderBottom: `1px solid ${colors.border}`,
                    }}
                  >
                    <td style={{ padding: "13px" }}>
                      {event.event || "Unknown"}
                    </td>

                    <td style={{ padding: "13px" }}>
                      {event.action || "—"}
                    </td>

                    <td style={{ padding: "13px" }}>
                      {event.approver || "—"}
                    </td>

                    <td
                      style={{
                        padding: "13px",
                        color: colors.muted,
                      }}
                    >
                      {event.ts
                        ? new Date(event.ts * 1000).toLocaleString()
                        : "Unavailable"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </section>
  );
}
