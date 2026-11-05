
import axios from "axios";

const api = axios.create({
  baseURL: "/api",
  timeout: 120000,
});

// Backend health
export async function getHealth() {
  return (await api.get("/health")).data;
}

// AI assistant
export async function askAgent(question) {
  return (await api.post("/ask", { question })).data;
}

// Kubernetes cluster overview
export async function getClusterOverview() {
  return (await api.get("/cluster/overview")).data;
}

// Kubernetes alerts
export async function getAlerts() {
  return (await api.get("/alerts")).data;
}

// Incident investigation history
export async function getIncidents() {
  return (await api.get("/incidents")).data;
}

// Actions associated with an incident
export async function getIncidentActions(incidentKey) {
  const key = encodeURIComponent(incidentKey);
  return (await api.get(`/incidents/${key}/actions`)).data;
}

// Approve an action
export async function approveAction(incidentKey, actionId, approver) {
  const key = encodeURIComponent(incidentKey);

  return (
    await api.post(
      `/incidents/${key}/actions/${actionId}/approve`,
      { approver }
    )
  ).data;
}

// Reject an action
export async function rejectAction(incidentKey, actionId) {
  const key = encodeURIComponent(incidentKey);

  return (
    await api.post(
      `/incidents/${key}/actions/${actionId}/reject`
    )
  ).data;
}

// Execute an approved action
export async function executeAction(incidentKey, actionId) {
  const key = encodeURIComponent(incidentKey);

  return (
    await api.post(
      `/incidents/${key}/actions/${actionId}/execute`
    )
  ).data;
}

// Audit history
export async function getAudit() {
  return (await api.get("/audit")).data;
}
