"""Safe, read-only Kubernetes tools for OpsPilot AI."""

import json
import subprocess


def run_kubectl(args):
    """Execute a predefined read-only kubectl operation."""
    allowed_operations = {
        "get",
        "describe",
        "logs",
        "top",
    }

    if not args or args[0] not in allowed_operations:
        raise ValueError("Kubernetes operation is not permitted.")

    command = ["kubectl"] + args

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return "Kubernetes command timed out."

    if result.returncode != 0:
        return "Kubernetes command failed: " + result.stderr.strip()

    return result.stdout.strip()


def list_namespaces():
    return run_kubectl(["get", "namespaces"])


def list_pods(namespace="default"):
    return run_kubectl(["get", "pods", "-n", namespace])


def list_services(namespace="default"):
    return run_kubectl(["get", "services", "-n", namespace])


def list_deployments(namespace="default"):
    return run_kubectl(["get", "deployments", "-n", namespace])


def get_pod_details(pod_name, namespace="default"):
    return run_kubectl([
        "describe", "pod", pod_name, "-n", namespace
    ])


def get_pod_logs(pod_name, namespace="default"):
    return run_kubectl([
        "logs", pod_name, "-n", namespace
    ])


def get_pod_metrics(namespace="default"):
    return run_kubectl(["top", "pods", "-n", namespace])


def get_kubernetes_events(namespace="default"):
    return run_kubectl([
        "get", "events", "-n", namespace, "--sort-by=.lastTimestamp"
    ])


TOOLS = {
    "list_namespaces": list_namespaces,
    "list_pods": list_pods,
    "list_services": list_services,
    "list_deployments": list_deployments,
    "get_pod_details": get_pod_details,
    "get_pod_logs": get_pod_logs,
    "get_pod_metrics": get_pod_metrics,
    "get_kubernetes_events": get_kubernetes_events,
}