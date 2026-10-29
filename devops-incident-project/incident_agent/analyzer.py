"""Deterministic diagnosis rules. Every finding cites evidence ids and says whether it is
OBSERVED, INFERRED (with reasoning) or ASSUMED. Missing or unreadable sources become
unknowns, never conclusions. Log text is treated as data: nothing in it can create an action.
"""
from .models import (ASSUMED, INFERRED, OBSERVED, Diagnosis, Finding, ProposedAction)

SOURCES = ("health", "logs", "ci", "deployment")
_BAD_WAITING = {"ImagePullBackOff", "ErrImagePull", "CrashLoopBackOff", "CreateContainerConfigError"}


def _cause_for_waiting(reason):
    return {
        "ImagePullBackOff": ("The node cannot obtain the container image (missing tag, not loaded "
                             "into the cluster, or registry unreachable)."),
        "ErrImagePull": ("The node cannot obtain the container image (missing tag, not loaded "
                         "into the cluster, or registry unreachable)."),
        "CrashLoopBackOff": "The container starts and then exits repeatedly.",
        "CreateContainerConfigError": "The pod references configuration (ConfigMap/Secret) that is missing or invalid.",
    }[reason]


def _ci_category(step):
    s = step.lower()
    if "test" in s:
        return "a test failure (possible regression in code or tests)"
    if "analy" in s or "format" in s:
        return "a static-analysis or formatting failure"
    if "scan" in s or "trivy" in s or "vulnerab" in s:
        return "a vulnerability-scan finding"
    if "build" in s or "docker" in s or "image" in s:
        return "a build failure"
    return "a failure in a step that this agent has no rule for"


def diagnose(evidence, namespace="food-delivery", deployment="food-delivery-ui", expected=SOURCES):
    by = {}
    for ev in evidence:
        by.setdefault(ev.source, ev)
    findings, unknowns, actions = [], [], []
    failure_signals = []

    def act(description, command=(), changes=False, rationale=""):
        action = ProposedAction("A%d" % (len(actions) + 1), description, tuple(command), changes, rationale)
        actions.append(action)
        return action

    # --- missing / unreadable sources -> unknowns -----------------------------------
    for src in expected:
        ev = by.get(src)
        if ev is None:
            unknowns.append("No %s evidence was collected, so nothing can be concluded about it." % src)
        elif ev.error:
            unknowns.append("%s evidence could not be read (%s); nothing is concluded about it." % (
                src, ev.error[:120]))

    def usable(src):
        ev = by.get(src)
        return ev if ev is not None and not ev.error else None

    # --- health ---------------------------------------------------------------------
    health = usable("health")
    health_failing = False
    if health:
        if health.data["ok"]:
            findings.append(Finding("The health endpoint responds with 200.", OBSERVED, [health.id], "high"))
        else:
            health_failing = True
            failure_signals.append("health")
            findings.append(Finding("The health endpoint is failing: %s." % health.summary, OBSERVED,
                                    [health.id], "high"))

    # --- logs -----------------------------------------------------------------------
    logs = usable("logs")
    if logs:
        d = logs.data
        if d["total"] == 0 and not d["error_lines"]:
            findings.append(Finding("The log window contains no request records.", OBSERVED, [logs.id], "medium"))
            unknowns.append("With no request records, it is unknown whether there was no traffic or logging is broken.")
        if d["s5xx"]:
            failure_signals.append("logs")
            findings.append(Finding("%d of %d logged requests returned a 5xx status." % (d["s5xx"], d["total"]),
                                    OBSERVED, [logs.id], "high"))
            act("Inspect the application error log for the failing requests",
                ("kubectl", "-n", namespace, "logs", "-l", "app.kubernetes.io/name=%s" % deployment, "--tail=50"),
                False, "5xx responses were logged; the error log usually names the cause.")
        if d["error_lines"]:
            failure_signals.append("logs")
            findings.append(Finding("nginx error-log lines are present, e.g.: %s" % d["error_lines"][0][:160],
                                    OBSERVED, [logs.id], "medium"))
        if d["total"] and d["unparsed"]:
            findings.append(Finding("%d log lines were not in the expected JSON format." % d["unparsed"],
                                    OBSERVED, [logs.id], "medium"))
        if d["total"] and d["s4xx"] / d["total"] > 0.5:
            findings.append(Finding("More than half of logged requests were 4xx.", INFERRED, [logs.id], "low",
                                    "%d of %d requests returned 4xx; this pattern can mean broken links, a bad "
                                    "client, or scanning, but the logs alone cannot say which." % (d["s4xx"], d["total"])))

    # --- CI -------------------------------------------------------------------------
    ci = usable("ci")
    ci_failed = False
    if ci:
        d = ci.data
        if d["conclusion"] == "failure":
            ci_failed = True
            failure_signals.append("ci")
            for f in d["failed"] or [{"job": "unknown job", "step": "unknown step"}]:
                findings.append(Finding("CI failed in job '%s' at step '%s'." % (f["job"], f["step"]),
                                        OBSERVED, [ci.id], "high"))
                findings.append(Finding("The failing step suggests %s." % _ci_category(f["step"]),
                                        INFERRED, [ci.id], "medium",
                                        "Classified from the step name '%s' only; the step's log was not read." % f["step"]))
            act("Open the failed CI run and read the failing step's log", (), False,
                "The step log is the evidence that would confirm the cause. %s" % d.get("url", ""))
        elif d["status"] in ("in_progress", "queued"):
            findings.append(Finding("The latest CI run has not finished yet.", OBSERVED, [ci.id], "high"))
        elif d["conclusion"] == "success":
            findings.append(Finding("The latest CI run succeeded.", OBSERVED, [ci.id], "high"))
        elif d["conclusion"] is None and d["status"] == "none":
            unknowns.append("No CI run exists for this branch.")

    # --- deployment -----------------------------------------------------------------
    dep = usable("deployment")
    dep_degraded = False
    if dep:
        d = dep.data
        if d["ready"] < d["desired"]:
            dep_degraded = True
            failure_signals.append("deployment")
            findings.append(Finding("Only %s of %s replicas are ready." % (d["ready"], d["desired"]),
                                    OBSERVED, [dep.id], "high"))
        any_waiting = False
        explained = set()                      # one explanation per reason, not per pod
        for pod in d["pods"]:
            reason = pod["waiting_reason"]
            if reason in _BAD_WAITING:
                any_waiting = True
                findings.append(Finding("Pod %s is waiting with reason %s." % (pod["name"], reason),
                                        OBSERVED, [dep.id], "high"))
                if reason not in explained:
                    explained.add(reason)
                    findings.append(Finding(_cause_for_waiting(reason), INFERRED, [dep.id], "medium",
                                            "%s is the standard Kubernetes signal for this condition; the pod's own "
                                            "events/logs were not read, so the exact trigger is unconfirmed." % reason))
                act("Describe pod %s to read its events" % pod["name"],
                    ("kubectl", "-n", namespace, "describe", "pod", pod["name"]), False,
                    "Confirms the exact cause of %s." % reason)
                if reason == "CrashLoopBackOff":
                    act("Read the previous container logs of %s" % pod["name"],
                        ("kubectl", "-n", namespace, "logs", pod["name"], "--previous"), False,
                        "Shows why the last run exited.")
            elif pod["restarts"] >= 3:
                findings.append(Finding("Pod %s has restarted %d times." % (pod["name"], pod["restarts"]),
                                        OBSERVED, [dep.id], "high"))
        reasons = {p["waiting_reason"] for p in d["pods"]}
        if reasons & {"ImagePullBackOff", "ErrImagePull"}:
            act("Check that the image tag exists on the cluster nodes (for a local cluster, load it again)", (), False,
                "A pod cannot start without its image; this is a manual step for a human.")
        if "CrashLoopBackOff" in reasons:
            act("Roll the deployment back to its previous revision",
                ("kubectl", "-n", namespace, "rollout", "undo", "deployment/%s" % deployment), True,
                "Only appropriate if the crashes began right after the latest rollout; confirm that first.")
        elif dep_degraded and not any_waiting:
            act("Restart the deployment's pods",
                ("kubectl", "-n", namespace, "rollout", "restart", "deployment/%s" % deployment), True,
                "Replicas are not ready but no clear cause was found; a restart is a low-information remedy.")
        bad = [w for w in d["warnings"] if w["reason"] in ("Failed", "BackOff", "Unhealthy", "FailedScheduling")]
        if bad:
            findings.append(Finding("Warning events: %s." % "; ".join("%s (%s)" % (w["reason"], w["object"]) for w in bad[:3]),
                                    OBSERVED, [dep.id], "medium"))

    # --- docker ---------------------------------------------------------------------
    docker = usable("docker")
    if docker:
        containers = docker.data["containers"]
        if not containers:
            findings.append(Finding("No Docker container matched the requested name.", OBSERVED, [docker.id], "high"))
            unknowns.append("Without a matching container, Docker-level health is unknown.")
        for c in containers:
            status = c["status"]
            if not status.startswith("Up"):
                failure_signals.append("docker")
                findings.append(Finding("Container %s is not running (status: %s)." % (c["name"], status),
                                        OBSERVED, [docker.id], "high"))
                act("Read the last logs of container %s" % c["name"], ("docker", "logs", "--tail", "100", c["name"]),
                    False, "The final log lines usually show why it stopped.")
            elif "unhealthy" in status.lower():
                failure_signals.append("docker")
                findings.append(Finding("Container %s is running but reports unhealthy." % c["name"],
                                        OBSERVED, [docker.id], "high"))
                act("Inspect the health-check results of container %s" % c["name"],
                    ("docker", "inspect", c["name"]), False, "Shows the recent health probe output.")

    # --- correlations (always labelled) ---------------------------------------------
    if health_failing and dep_degraded:
        findings.append(Finding("The failing health endpoint is probably explained by pods that are not ready.",
                                INFERRED, [health.id, dep.id], "medium",
                                "Health is failing and %s of %s replicas are ready at the same time. The timing "
                                "matches, but no evidence proves one caused the other." % (dep.data["ready"], dep.data["desired"])))
    if health and not health_failing and ci_failed:
        findings.append(Finding("The running version is probably not the one that failed CI.", ASSUMED, [], "low",
                                "No evidence links the deployed image to the failed CI run."))
        unknowns.append("Which commit the running image was built from is unknown.")
    if health_failing and dep is None:
        unknowns.append("The health endpoint is failing but there is no deployment evidence to say why.")

    # --- status ---------------------------------------------------------------------
    usable_sources = [s for s in expected if usable(s)]
    if failure_signals:
        status = "DEGRADED"
    elif health and len(usable_sources) >= 2:
        status = "HEALTHY"
    else:
        status = "INDETERMINATE"
    counts = {k: sum(1 for f in findings if f.kind == k) for k in (OBSERVED, INFERRED, ASSUMED)}
    summary = "%s. Failure signals: %s. %d observed, %d inferred, %d assumed findings; %d unknowns." % (
        status, ", ".join(sorted(set(failure_signals))) or "none", counts[OBSERVED], counts[INFERRED],
        counts[ASSUMED], len(unknowns))
    return Diagnosis(status, summary, findings, unknowns, actions, list(evidence))
