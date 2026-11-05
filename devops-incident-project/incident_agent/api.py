
"""HTTP API for live Kubernetes questions and incident analysis."""

import os
import json
import subprocess
import re
from types import SimpleNamespace

from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field

from .cli import build_collectors
from .analyzer import diagnose
from .models import assign_ids
from .approval import (
    ApprovalGate,
    Executor,
    ApprovalRequired,
    PolicyViolation,
)
from .audit import AuditLog
from .llm.gemini_client import GeminiClient, GeminiError
from .llm.prompt import build_messages
from .llm.validate import ValidationError, validate
from .tools.kubernetes_tools import TOOLS as KUBERNETES_TOOLS


app = FastAPI(title="DevOps Incident Agent", version="3.0.0")
# In-memory incident investigation store
INCIDENTS = {}
INVESTIGATING = set()

# Approval and execution state for the API.
AUDIT = AuditLog(
    os.getenv("INCIDENT_AUDIT_LOG", "incident-audit.jsonl")
)

ACTION_STORE = {}
APPROVAL_STORE = {}
ACTION_STATUS = {}


class ApprovalRequest(BaseModel):
    approver: str = Field(default="operator", min_length=1, max_length=100)


class Question(BaseModel):
    question: str = Field(min_length=3, max_length=1000)


def run_kubectl(args):
    """Run only predefined, read-only kubectl commands."""

    result = subprocess.run(
        ["kubectl"] + args,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "kubectl command failed")

    return result.stdout.strip()


def get_live_pods(namespace):
    """Fetch current Pod details from Kubernetes."""

    output = run_kubectl([
        "get", "pods",
        "-n", namespace,
        "-o", "json",
    ])

    return json.loads(output)
def get_pod_metrics(namespace):
    """Fetch structured Pod CPU and memory usage."""

    try:
        output = run_kubectl([
            "top", "pods",
            "-n", namespace,
            "--no-headers",
        ])

        pods = []

        for line in output.strip().splitlines():
            columns = line.split()

            if len(columns) >= 3:
                pods.append({
                    "name": columns[0],
                    "cpu": columns[1],
                    "memory": columns[2],
                })

        return pods

    except (RuntimeError, subprocess.TimeoutExpired) as exc:
        return {
            "error": f"Metrics unavailable: {exc}"
        }
    
def get_node_metrics():
    """Fetch current node CPU and memory usage."""

    output = run_kubectl([
        "top", "nodes"
    ])

    lines = output.splitlines()

    if len(lines) < 2:
        return []

    metrics = []

    for line in lines[1:]:
        values = line.split()

        if len(values) >= 5:
            metrics.append({
                "name": values[0],
                "cpu": values[1],
                "cpu_percent": values[2],
                "memory": values[3],
                "memory_percent": values[4],
            })

    return metrics


def get_deployment_overview(namespace):
    """Fetch deployment readiness information."""

    output = run_kubectl([
        "get", "deployments",
        "-n", namespace,
        "-o", "json",
    ])

    data = json.loads(output)

    deployments = []

    for deployment in data.get("items", []):
        spec = deployment.get("spec", {})
        status = deployment.get("status", {})

        deployments.append({
            "name": deployment["metadata"]["name"],
            "desired_replicas": spec.get("replicas", 0),
            "ready_replicas": status.get("readyReplicas", 0),
            "available_replicas": status.get("availableReplicas", 0),
        })

    return deployments


def get_kubernetes_warning_events(namespace):
    """Collect Kubernetes Warning events from a namespace."""

    try:
        output = run_kubectl([
            "get", "events",
            "-n", namespace,
            "--field-selector", "type=Warning",
            "-o", "json",
        ])

        data = json.loads(output)
        events = []

        for event in data.get("items", []):
            metadata = event.get("metadata", {})
            involved_object = event.get("involvedObject", {})

            events.append({
                "name": metadata.get("name", "Unknown"),
                "reason": event.get("reason", "Unknown"),
                "message": event.get("message", ""),
                "resource": involved_object.get("name", "Unknown"),
                "resource_kind": involved_object.get("kind", "Unknown"),
                "namespace": involved_object.get("namespace", namespace),
                "count": event.get("count", 1),
                "last_timestamp": (
                    event.get("lastTimestamp")
                    or event.get("eventTime")
                    or metadata.get("creationTimestamp")
                ),
            })

        return events

    except (RuntimeError, subprocess.TimeoutExpired) as exc:
        return {
            "error": f"Warning events unavailable: {exc}"
        }
def detect_kubernetes_alerts(namespace):
    """Detect Kubernetes issues using live cluster information."""

    alerts = []

    # 1. Check node CPU and memory
    try:
        nodes = get_node_metrics()

        for node in nodes:
            cpu = int(node["cpu_percent"].replace("%", ""))
            memory = int(node["memory_percent"].replace("%", ""))

            if cpu > 70:
                alerts.append({
                    "type": "High CPU",
                    "severity": "warning",
                    "resource": node["name"],
                    "message": f"Node CPU utilization is {cpu}%",
                })

            if memory > 80:
                alerts.append({
                    "type": "High Memory",
                    "severity": "critical",
                    "resource": node["name"],
                    "message": f"Node memory utilization is {memory}%",
                })

    except (RuntimeError, subprocess.TimeoutExpired):
        pass

    # 2. Check Pod status and container failures
    pods_data = get_live_pods(namespace)

    for pod in pods_data.get("items", []):
        metadata = pod.get("metadata", {})
        status = pod.get("status", {})

        pod_name = metadata.get("name", "Unknown")

        ready = any(
            condition.get("type") == "Ready"
            and condition.get("status") == "True"
            for condition in status.get("conditions", [])
        )

        if not ready:
            alerts.append({
                "type": "Pod Not Ready",
                "severity": "critical",
                "resource": pod_name,
                "message": f"Pod {pod_name} is not Ready",
            })

        for container in status.get("containerStatuses", []):
            waiting = container.get("state", {}).get("waiting", {})
            reason = waiting.get("reason")

            if reason in ["CrashLoopBackOff", "ImagePullBackOff"]:
                alerts.append({
                    "type": reason,
                    "severity": "critical",
                    "resource": pod_name,
                    "message": (
                        f"Container {container.get('name')} "
                        f"is in {reason}"
                    ),
                })

    # 3. Check Deployment availability
    deployments = get_deployment_overview(namespace)

    for deployment in deployments:
        if deployment["ready_replicas"] < deployment["desired_replicas"]:
            alerts.append({
                "type": "Deployment Unavailable",
                "severity": "warning",
                "resource": deployment["name"],
                "message": (
                    f"Only {deployment['ready_replicas']} of "
                    f"{deployment['desired_replicas']} replicas are Ready"
                ),
            })

    # 4. Collect and group Kubernetes Warning Events
    warning_events = get_kubernetes_warning_events(namespace)

    if isinstance(warning_events, list):

        # Build a map of currently existing Pods
        live_pod_status = {}

        for pod in pods_data.get("items", []):
            metadata = pod.get("metadata", {})
            status = pod.get("status", {})

            pod_name = metadata.get("name", "Unknown")

            ready = any(
                condition.get("type") == "Ready"
                and condition.get("status") == "True"
                for condition in status.get("conditions", [])
            )

            live_pod_status[pod_name] = ready

        # Group events by namespace, resource kind and resource name
        grouped_events = {}

        for event in warning_events:
            key = (
                event["namespace"],
                event["resource_kind"],
                event["resource"],
            )

            if key not in grouped_events:
                grouped_events[key] = []

            grouped_events[key].append(event)

        # Create one alert for each resource
        for key, events in grouped_events.items():

            event_namespace, resource_kind, resource = key

            if resource_kind == "Pod":
                if resource not in live_pod_status:
                    incident_status = "historical"
                elif live_pod_status[resource]:
                    incident_status = "historical"
                else:
                    incident_status = "active"
            else:
                incident_status = "unverified"

            alerts.append({
                "type": "Kubernetes Warning",
                "severity": "warning",
                "status": incident_status,
                "resource": resource,
                "resource_kind": resource_kind,
                "namespace": event_namespace,
                "event_count": len(events),
                "reasons": list(set(
                    event["reason"] for event in events
                )),
                "count": max(
                    event["count"] for event in events
                ),
                "last_timestamp": max(
                    event["last_timestamp"] or ""
                    for event in events
                ),
                "message": "; ".join(
                    event["message"] for event in events
                ),
                "events": events,
            })

    return alerts
def answer_kubernetes_question(question, namespace, pods_data):
    """Answer common Kubernetes questions from live cluster data."""

    q = question.lower()
    pods = pods_data.get("items", [])

    # List Kubernetes namespaces
    # List or count Kubernetes namespaces
    if "namespace" in q and any(
        word in q for word in [
            "which", "list", "show", "available",
            "what", "how many", "count"
        ]
    ):
        return run_kubectl(["get", "namespaces"])

    # List Deployments
    if "deployment" in q and any(
        word in q for word in ["which", "list", "show", "available", "what"]
    ):
        return run_kubectl(["get", "deployments", "-n", namespace])

    # List Services
    if "service" in q and any(
        word in q for word in ["which", "list", "show", "available", "what"]
    ):
        return run_kubectl(["get", "services", "-n", namespace])

    # List Nodes
    if "node" in q and any(
        word in q for word in ["which", "list", "show", "available", "what"]
    ):
        return run_kubectl(["get", "nodes", "-o", "wide"])

    # Actual kubectl command output
    if (
        "kubectl" in q
        and ("output" in q or "run" in q or "execute" in q)
        and "get pods" in q
    ):
        return run_kubectl(["get", "pods", "-n", namespace])

    # CPU and memory usage
    if (
        ("cpu" in q or "memory" in q or "ram" in q)
        and ("pod" in q or "container" in q)
    ):
        return get_pod_metrics(namespace)

    # Pod names and status
    if "pod" in q and any(
        word in q for word in ["name", "list", "which", "show"]
    ):
        if not pods:
            return f"No Pods found in namespace {namespace}."

        lines = []

        for pod in pods:
            metadata = pod.get("metadata", {})
            status = pod.get("status", {})
            conditions = status.get("conditions", [])

            ready = any(
                condition.get("type") == "Ready"
                and condition.get("status") == "True"
                for condition in conditions
            )

            restarts = sum(
                container.get("restartCount", 0)
                for container in status.get("containerStatuses", [])
            )

            lines.append(
                f"Pod: {metadata.get('name', 'Unknown')} | "
                f"Phase: {status.get('phase', 'Unknown')} | "
                f"Ready: {ready} | Restarts: {restarts}"
            )

        return "\n".join(lines)

    # Number of running Pods
    if "pod" in q and "how many" in q:
        running = sum(
            pod.get("status", {}).get("phase") == "Running"
            for pod in pods
        )

        ready = sum(
            any(
                condition.get("type") == "Ready"
                and condition.get("status") == "True"
                for condition in pod.get("status", {}).get("conditions", [])
            )
            for pod in pods
        )

        if "running" in q:
            return (
                f"{running} Pods are Running out of "
                f"{len(pods)} total Pods in namespace {namespace}."
            )

        return (
            f"Total Pods: {len(pods)}\n"
            f"Running Pods: {running}\n"
            f"Ready Pods: {ready}\n"
            f"Not Ready Pods: {len(pods) - ready}"
        )

    return None

@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "DevOps Incident Agent",
        "data_mode": "live_kubernetes",
    }


@app.get("/cluster/overview")
def cluster_overview():

    namespace = os.getenv("K8S_NAMESPACE", "food-delivery")

    try:
        # 1. Get live Pod information
        pods_data = get_live_pods(namespace)
        pods = pods_data.get("items", [])

        pods_total = len(pods)

        pods_ready = sum(
            any(
                condition.get("type") == "Ready"
                and condition.get("status") == "True"
                for condition in pod.get("status", {}).get("conditions", [])
            )
            for pod in pods
        )

        # 2. Get deployment information
        deployments = get_deployment_overview(namespace)

        # 3. Get current Pod CPU and memory
        pod_metrics = get_pod_metrics(namespace)

        # 4. Map actual Kubernetes Pod statuses
        pod_status_map = {}

        for pod in pods:
            metadata = pod.get("metadata", {})
            status = pod.get("status", {})

            pod_name = metadata.get("name", "Unknown")
            pod_phase = status.get("phase", "Unknown")

            ready = any(
                condition.get("type") == "Ready"
                and condition.get("status") == "True"
                for condition in status.get("conditions", [])
            )

            if pod_phase == "Running" and not ready:
                pod_phase = "NotReady"

            pod_status_map[pod_name] = pod_phase

        # 5. Add actual status to each Pod metrics record
        if isinstance(pod_metrics, list):
            for metric in pod_metrics:
                metric["status"] = pod_status_map.get(
                    metric["name"], "Unknown"
                )

        # 6. Get current node CPU and memory
        node_metrics = get_node_metrics()

        return {
            "status": "ok",
            "data_mode": "live_kubernetes",
            "namespace": namespace,
            "pods": {
                "total": pods_total,
                "ready": pods_ready,
                "not_ready": pods_total - pods_ready,
            },
            "deployments": deployments,
            "pod_metrics": pod_metrics,
            "node_metrics": node_metrics,
        }

    except subprocess.TimeoutExpired as exc:
        raise HTTPException(
            status_code=504,
            detail="Kubernetes command timed out.",
        ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        ) from exc


def investigate_incident(incident_key, alert, namespace):
    """Investigate one active incident using live evidence and Gemini."""

    # Store a clean copy without the response-only investigation field.
    incident_alert = {
        key: value
        for key, value in alert.items()
        if key != "investigation"
    }

    try:
        INCIDENTS[incident_key] = {
            "status": "investigating",
            "alert": incident_alert,
        }

        deployment = os.getenv("K8S_DEPLOYMENT", "food-delivery-ui")

        args = SimpleNamespace(
            bundle=None,
            health_url=None,
            docker_container=None,
            logs_file=None,
            ci_repo=None,
            ci_branch="master",
            namespace=namespace,
            deployment=deployment,
        )

        collectors, expected = build_collectors(args, "k8s")

        evidence = []
        for collector in collectors:
            evidence.extend(collector.collect())

        # Scope namespace-wide Kubernetes warning events to this incident's resource.
        # Historical and unrelated Pod events must not influence this investigation.
        incident_resource = incident_alert.get("resource")
        for item in evidence:
            if item.source != "deployment" or item.error:
                continue

            warnings = item.data.get("warnings", [])
            scoped_warnings = [
                warning
                for warning in warnings
                if str(warning.get("status", "")).lower() == "active"
                and (warning.get("object") or warning.get("resource")) == incident_resource
            ]
            item.data["warnings"] = scoped_warnings
            item.excerpt = "; ".join(
                "%s %s" % (warning.get("reason", "Warning"), warning.get("message", ""))
                for warning in scoped_warnings[:3]
            )

        evidence = assign_ids(evidence)

        diagnosis = diagnose(
            evidence,
            namespace,
            deployment,
            expected,
            incident_resource=incident_resource,
        )
        # Keep analyzer-generated actions as the trusted action source.
        ACTION_STORE[incident_key] = {
            action.id: action for action in diagnosis.actions
        }

        for action in diagnosis.actions:
            ACTION_STATUS[(incident_key, action.id)] = (
                "manual" if not action.command else "pending_approval"
            )

        client = GeminiClient(model=os.getenv("GEMINI_MODEL"))

        system, evidence_prompt = build_messages(diagnosis.evidence)

        user_prompt = (
            evidence_prompt
            + "\n\nINCIDENT RESOURCE CONTEXT:"
            + "\nThe exact incident resource is: "
            + str(incident_resource)
            + "\nTreat this resource as the source of the incident."
            + "\nIf it is a Pod, all root-cause descriptions and verification "
            "commands must refer to that Pod."
            + "\nDo not use Deployment-specific commands unless the Deployment "
            "itself is explicitly identified as the failing resource."
            + "\n\nAutomatically investigate this active Kubernetes alert: "
            + json.dumps(incident_alert, default=str)
        )

        raw = client.generate_json(system, user_prompt)

        analysis = validate(
            raw,
            {item.id for item in diagnosis.evidence},
            incident_resource=incident_resource,
        )

        INCIDENTS[incident_key] = {
            "status": "completed",
            "alert": incident_alert,
            "diagnosis": {
                "status": diagnosis.status,
                "summary": diagnosis.summary,
            },
            "ai_analysis": {
                "causes": [
                    {
                        "claim": item.claim,
                        "type": item.declared,
                        "evidence_ids": item.evidence_ids,
                        "confidence": item.confidence,
                        "status": item.status,
                        "note": item.note,
                    }
                    for item in analysis.causes
                ],
                "fixes": [
                    {
                        "description": item.description,
                        "command": item.command,
                        "command_class": item.command_class,
                    }
                    for item in analysis.fixes
                ],
                "verification": [
                    {
                        "command": command,
                        "command_class": command_class,
                    }
                    for command, command_class in analysis.verification
                ],
                "problems": analysis.problems,
                "actions": [
                    {
                        "id": action.id,
                        "description": action.description,
                        "command": list(action.command),
                        "changes_environment": action.changes_environment,
                        "rationale": action.rationale,
                        "status": ACTION_STATUS.get(
                            (incident_key, action.id), "pending_approval"
                        ),
                    }
                    for action in diagnosis.actions
                ],
            },
        }

    except Exception as exc:
        INCIDENTS[incident_key] = {
            "status": "failed",
            "alert": incident_alert,
            "error": str(exc)[:300],
        }

    finally:
        INVESTIGATING.discard(incident_key)


@app.get("/alerts")
def get_alerts(background_tasks: BackgroundTasks):

    namespace = os.getenv("K8S_NAMESPACE", "food-delivery")

    try:
        alerts = detect_kubernetes_alerts(namespace)

        active_keys = set()

        for alert in alerts:
            # Warning events must explicitly be confirmed active.
            if alert.get("type") == "Kubernetes Warning":
                is_active = alert.get("status") == "active"
            else:
                # These alerts come from current live cluster checks.
                is_active = True

            if not is_active:
                continue

            incident_key = "{}:{}".format(
                namespace,
                alert.get("resource", "unknown"),
            )

            active_keys.add(incident_key)

            # Schedule only new incidents, not every dashboard poll.
            if (
                incident_key not in INVESTIGATING
                and INCIDENTS.get(incident_key, {}).get("status")
                not in ("investigating", "completed")
            ):
                INVESTIGATING.add(incident_key)

                background_tasks.add_task(
                    investigate_incident,
                    incident_key,
                    alert,
                    namespace,
                )

            alert["investigation"] = INCIDENTS.get(
                incident_key,
                {"status": "pending"},
            )

        # Mark incidents no longer detected as resolved.
        for incident_key, incident in INCIDENTS.items():
            if (
                incident_key.startswith(namespace + ":")
                and incident_key not in active_keys
                and incident.get("status") != "resolved"
            ):
                incident["status"] = "resolved"

        return {
            "status": "ok",
            "namespace": namespace,
            "total_alerts": len(alerts),
            "alerts": alerts,
        }

    except subprocess.TimeoutExpired as exc:
        raise HTTPException(
            status_code=504,
            detail="Kubernetes command timed out.",
        ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        ) from exc


@app.get("/incidents")
def get_incidents():
    """Return incident investigations for the configured namespace."""

    namespace = os.getenv("K8S_NAMESPACE", "food-delivery")
    incidents = []

    for incident_key, incident in INCIDENTS.items():
        if not incident_key.startswith(namespace + ":"):
            continue

        incidents.append({
            "incident_key": incident_key,
            "status": incident.get("status", "unknown"),
            "alert": incident.get("alert", {}),
            "diagnosis": incident.get("diagnosis"),
            "ai_analysis": incident.get("ai_analysis"),
            "error": incident.get("error"),
        })

    return {
        "status": "ok",
        "namespace": namespace,
        "total_incidents": len(incidents),
        "incidents": incidents,
    }


# Gemini function declarations. The model can select only these registered,
# read-only Kubernetes operations; it cannot submit arbitrary shell commands.
KUBERNETES_TOOL_DECLARATIONS = [
    {
        "name": "list_namespaces",
        "description": "List all namespaces in the Kubernetes cluster.",
        "parameters": {"type": "OBJECT", "properties": {}},
    },
    {
        "name": "list_pods",
        "description": "List Pods in a Kubernetes namespace. Use the namespace specified by the user.",
        "parameters": {
            "type": "OBJECT",
            "properties": {"namespace": {"type": "STRING", "description": "Kubernetes namespace"}},
        },
    },
    {
        "name": "list_services",
        "description": "List Services in a Kubernetes namespace. Use the namespace specified by the user.",
        "parameters": {
            "type": "OBJECT",
            "properties": {"namespace": {"type": "STRING", "description": "Kubernetes namespace"}},
        },
    },
    {
        "name": "list_deployments",
        "description": "List Deployments in a Kubernetes namespace.",
        "parameters": {
            "type": "OBJECT",
            "properties": {"namespace": {"type": "STRING", "description": "Kubernetes namespace"}},
        },
    },
    {
        "name": "get_pod_details",
        "description": "Describe a specific Pod, including status, container state and events.",
        "parameters": {
            "type": "OBJECT",
            "properties": {
                "pod_name": {"type": "STRING", "description": "Exact Pod name"},
                "namespace": {"type": "STRING", "description": "Kubernetes namespace"},
            },
            "required": ["pod_name"],
        },
    },
    {
        "name": "get_pod_logs",
        "description": "Read logs from a specific Pod.",
        "parameters": {
            "type": "OBJECT",
            "properties": {
                "pod_name": {"type": "STRING", "description": "Exact Pod name"},
                "namespace": {"type": "STRING", "description": "Kubernetes namespace"},
            },
            "required": ["pod_name"],
        },
    },
    {
        "name": "get_pod_metrics",
        "description": "Get CPU and memory metrics for Pods in a namespace.",
        "parameters": {
            "type": "OBJECT",
            "properties": {"namespace": {"type": "STRING", "description": "Kubernetes namespace"}},
        },
    },
    {
        "name": "get_kubernetes_events",
        "description": "List Kubernetes events in a namespace.",
        "parameters": {
            "type": "OBJECT",
            "properties": {"namespace": {"type": "STRING", "description": "Kubernetes namespace"}},
        },
    },
]


def _validated_namespace(value, fallback):
    """Validate a namespace before passing it to a fixed kubectl tool."""
    namespace = value or fallback
    if not isinstance(namespace, str) or not re.fullmatch(
        r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?", namespace
    ):
        raise ValueError("Invalid Kubernetes namespace.")
    return namespace


def _build_kubernetes_tool_registry(default_namespace):
    """Bind safe tools to a validated default namespace."""
    def with_namespace(function):
        def wrapped(namespace=None, **kwargs):
            target = _validated_namespace(namespace, default_namespace)
            return function(namespace=target, **kwargs)
        return wrapped

    def pod_tool(function):
        def wrapped(pod_name, namespace=None):
            target = _validated_namespace(namespace, default_namespace)
            if not isinstance(pod_name, str) or not re.fullmatch(
                r"[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?", pod_name
            ):
                raise ValueError("Invalid Pod name.")
            return function(pod_name=pod_name, namespace=target)
        return wrapped

    return {
        "list_namespaces": KUBERNETES_TOOLS["list_namespaces"],
        "list_pods": with_namespace(KUBERNETES_TOOLS["list_pods"]),
        "list_services": with_namespace(KUBERNETES_TOOLS["list_services"]),
        "list_deployments": with_namespace(KUBERNETES_TOOLS["list_deployments"]),
        "get_pod_details": pod_tool(KUBERNETES_TOOLS["get_pod_details"]),
        "get_pod_logs": pod_tool(KUBERNETES_TOOLS["get_pod_logs"]),
        "get_pod_metrics": with_namespace(KUBERNETES_TOOLS["get_pod_metrics"]),
        "get_kubernetes_events": with_namespace(KUBERNETES_TOOLS["get_kubernetes_events"]),
    }


@app.post("/ask")
def ask_question(request: Question):
    """Use Gemini to understand the question, select safe tools and explain results."""
    namespace = os.getenv("K8S_NAMESPACE", "food-delivery")
    deployment = os.getenv("K8S_DEPLOYMENT", "food-delivery-ui")

    try:
        client = GeminiClient(model=os.getenv("GEMINI_MODEL"))

        system = (
            "You are OpsPilot AI, a Kubernetes and DevOps assistant. "
            "Understand the user's natural-language request and use the available "
            "Kubernetes tools to retrieve live facts. Select the most relevant tool "
            "and pass the namespace explicitly when the user names one. If no "
            "namespace is specified, use the configured default namespace "
            f"'{namespace}'. Never invent cluster data. Only use the provided tools. "
            "All available tools are read-only. Do not claim to have changed anything. "
            "After receiving tool results, answer clearly and conversationally. "
            "If a tool fails or data is unavailable, explain that honestly."
        )

        tool_registry = _build_kubernetes_tool_registry(namespace)
        result = client.generate_with_tools(
            system=system,
            user=request.question,
            tool_declarations=KUBERNETES_TOOL_DECLARATIONS,
            tool_registry=tool_registry,
        )

        tool_evidence = [
            {
                "id": f"T{index}",
                "source": "live_kubernetes",
                "summary": (
                    f"{item['tool']}({json.dumps(item['arguments'], default=str)}): "
                    f"{str(item['result'])[:500]}"
                ),
            }
            for index, item in enumerate(result["tool_calls"], start=1)
        ]

        return {
            "question": request.question,
            "answer": result["answer"],
            "tool_calls": result["tool_calls"],
            "evidence": tool_evidence,
            "data_mode": "live_kubernetes",
            "namespace": namespace,
            "deployment": deployment,
        }

    except GeminiError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(
            status_code=504,
            detail="Kubernetes command timed out.",
        ) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc



def get_incident_action(incident_key, action_id):
    """Return a trusted analyzer-generated action."""
    actions = ACTION_STORE.get(incident_key)

    if actions is None:
        raise HTTPException(status_code=404, detail="Incident actions not found")

    action = actions.get(action_id)

    if action is None:
        raise HTTPException(status_code=404, detail="Action not found")

    return action


@app.get("/incidents/{incident_key}/actions")
def list_incident_actions(incident_key):
    actions = ACTION_STORE.get(incident_key)

    if actions is None:
        raise HTTPException(status_code=404, detail="Incident actions not found")

    return {
        "incident_key": incident_key,
        "actions": [
            {
                "id": action.id,
                "description": action.description,
                "command": list(action.command),
                "changes_environment": action.changes_environment,
                "rationale": action.rationale,
                "status": ACTION_STATUS.get(
                    (incident_key, action.id), "pending_approval"
                ),
            }
            for action in actions.values()
        ],
    }


@app.post("/incidents/{incident_key}/actions/{action_id}/approve")
def approve_incident_action(
    incident_key, action_id, request: ApprovalRequest
):
    action = get_incident_action(incident_key, action_id)
    key = (incident_key, action_id)

    if not action.command:
        raise HTTPException(
            status_code=400,
            detail="This is a manual remediation step and cannot be executed automatically.",
        )

    if key in APPROVAL_STORE:
        raise HTTPException(status_code=409, detail="Action already approved")

    gate = ApprovalGate(
        ask=lambda prompt: "yes %s" % action.id,
        approver=request.approver,
        audit=AUDIT,
    )

    approval = gate.request(action)

    if approval is None:
        raise HTTPException(status_code=403, detail="Approval rejected")

    APPROVAL_STORE[key] = approval
    ACTION_STATUS[key] = "approved"

    return {
        "status": "approved",
        "action_id": action_id,
        "approver": request.approver,
        "message": "Action approved. Execution still requires a separate request.",
    }


@app.post("/incidents/{incident_key}/actions/{action_id}/reject")
def reject_incident_action(
    incident_key, action_id, request: ApprovalRequest
):
    action = get_incident_action(incident_key, action_id)
    key = (incident_key, action_id)

    if key in APPROVAL_STORE:
        raise HTTPException(status_code=409, detail="Action is already approved")

    if ACTION_STATUS.get(key) == "rejected":
        raise HTTPException(status_code=409, detail="Action already rejected")

    AUDIT.record(
        "proposed",
        action=action.id,
        command=" ".join(action.command),
        changes_environment=action.changes_environment,
    )
    AUDIT.record(
        "rejected",
        action=action.id,
        approver=request.approver,
    )

    ACTION_STATUS[key] = "rejected"

    return {
        "status": "rejected",
        "action_id": action_id,
        "approver": request.approver,
    }


def run_approved_command(argv):
    """Execute argv only after the Executor has enforced its policy."""
    import subprocess

    result = subprocess.run(
        list(argv),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    output = result.stdout or result.stderr or ""

    return result.returncode, output[:2000]


@app.post("/incidents/{incident_key}/actions/{action_id}/execute")
def execute_incident_action(incident_key, action_id):
    action = get_incident_action(incident_key, action_id)
    key = (incident_key, action_id)
    approval = APPROVAL_STORE.get(key)

    if approval is None:
        raise HTTPException(
            status_code=403,
            detail="Explicit approval is required before execution",
        )

    if ACTION_STATUS.get(key) != "approved":
        raise HTTPException(
            status_code=409,
            detail="Action is not in approved state",
        )

    executor = Executor(run_approved_command, AUDIT)

    try:
        returncode, output = executor.execute(action, approval)

        ACTION_STATUS[key] = (
            "executed" if returncode == 0 else "execution_failed"
        )

        return {
            "status": ACTION_STATUS[key],
            "action_id": action_id,
            "returncode": returncode,
            "output": output,
        }

    except (ApprovalRequired, PolicyViolation) as exc:
        ACTION_STATUS[key] = "blocked"
        raise HTTPException(status_code=403, detail=str(exc))

    except Exception as exc:
        ACTION_STATUS[key] = "execution_failed"
        AUDIT.record(
            "execution_error",
            action=action_id,
            error=str(exc)[:300],
        )
        raise HTTPException(status_code=500, detail="Execution failed")


@app.get("/audit")
def get_audit():
    return {
        "total_events": len(AUDIT.entries),
        "events": AUDIT.entries,
    }
