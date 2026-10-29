"""Read-only evidence collectors.

Every collector takes its data source as an injected callable, so tests use fakes and
the real systems (HTTP, GitHub API, kubectl, docker) plug in through the default
callables below. Collectors never raise: a failure becomes Evidence with `error` set,
which the analyzer reports as an unknown, never as a conclusion.
"""
import json
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request

from .models import Evidence
from .redact import redact

# ---- the read-only guard ----------------------------------------------------------

_KUBECTL_READ = {"get", "describe", "logs"}
_DOCKER_READ = {"logs", "inspect", "ps"}


def _kubectl_verb(args):
    """Skip -n/--namespace (and other global flags) to find the verb and what follows."""
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-n", "--namespace", "--context"):
            i += 2
        elif a.startswith("-"):
            i += 1
        else:
            return a, args[i + 1:]
    return "", []


def assert_read_only(argv):
    """Raise PermissionError unless argv is a known read-only kubectl/docker command."""
    argv = [str(a) for a in argv]
    if not argv:
        raise PermissionError("empty command")
    tool, rest = argv[0], argv[1:]
    if tool == "kubectl":
        verb, after = _kubectl_verb(rest)
        if verb in _KUBECTL_READ:
            return
        if verb == "rollout" and after[:1] == ["status"]:
            return
    elif tool == "docker":
        if rest and rest[0] in _DOCKER_READ:
            return
    raise PermissionError("not a read-only command: %s" % " ".join(argv))


# ---- default (real) data sources --------------------------------------------------

def http_get(url, timeout=3.0):
    """Plain GET. Returns (status, body, error). Only http(s) URLs are allowed."""
    if urllib.parse.urlparse(url).scheme not in ("http", "https"):
        return None, "", "only http/https URLs are allowed"
    req = urllib.request.Request(url, headers={"User-Agent": "incident-agent/0.1"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(65536).decode("utf-8", "replace"), ""
    except urllib.error.HTTPError as exc:
        return exc.code, "", "HTTP %d" % exc.code
    except Exception as exc:  # unreachable, refused, timeout, DNS ...
        return None, "", "%s: %s" % (type(exc).__name__, exc)


def http_get_json(url, timeout=10.0):
    status, body, err = http_get(url, timeout)
    if err:
        raise RuntimeError(err)
    return json.loads(body)


def read_only_runner(argv, timeout=20):
    """Runs a command only if it passes the read-only guard. No shell is used."""
    assert_read_only(argv)
    proc = subprocess.run(list(argv), capture_output=True, text=True, timeout=timeout)
    return proc.returncode, proc.stdout if proc.returncode == 0 else (proc.stderr or proc.stdout)


# ---- collectors -------------------------------------------------------------------

class HealthCollector:
    def __init__(self, url, fetch=http_get):
        self.url, self.fetch = url, fetch

    def collect(self):
        status, body, err = self.fetch(self.url, 3.0)
        ok = status == 200
        if ok:
            summary = "GET %s returned 200" % self.url
        else:
            summary = "GET %s failed: %s" % (self.url, err or "status %s" % status)
        return [Evidence("health", summary, excerpt=redact(body[:200]),
                         data={"ok": ok, "status": status, "error": err, "url": self.url})]


class LogCollector:
    """Parses the nginx JSON access log (one object per line) plus plain error lines."""

    def __init__(self, read_lines):
        self.read_lines = read_lines

    def collect(self):
        try:
            lines = list(self.read_lines())
        except Exception as exc:
            return [Evidence("logs", "Could not read logs: %s" % exc, error=str(exc))]
        total = s4 = s5 = unparsed = 0
        slowest = 0.0
        samples, error_lines = [], []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                unparsed += 1
                if re.search(r"\[(error|emerg|crit|alert)\]", line):
                    error_lines.append(redact(line)[:300])
                continue
            if not isinstance(rec, dict) or "status" not in rec:
                unparsed += 1
                continue
            total += 1
            try:
                status = int(rec["status"])
                slowest = max(slowest, float(rec.get("duration_s", 0)))
            except (TypeError, ValueError):
                unparsed += 1
                continue
            if status >= 500:
                s5 += 1
                if len(samples) < 3:
                    samples.append(redact(json.dumps(rec, sort_keys=True))[:300])
            elif status >= 400:
                s4 += 1
        summary = "%d request records: %d client errors (4xx), %d server errors (5xx), slowest %.3fs" % (
            total, s4, s5, slowest)
        if unparsed:
            summary += "; %d lines not in the JSON format" % unparsed
        return [Evidence("logs", summary, excerpt="\n".join(samples + error_lines[:3]),
                         data={"total": total, "s4xx": s4, "s5xx": s5, "unparsed": unparsed,
                               "slowest_s": slowest, "error_lines": error_lines[:5]})]


class CICollector:
    _REPO = re.compile(r"^[\w.-]+/[\w.-]+$")

    def __init__(self, repo, branch, get_json=http_get_json):
        if not self._REPO.match(repo):
            raise ValueError("repo must look like owner/name")
        self.repo, self.branch, self.get_json = repo, branch, get_json

    def collect(self):
        base = "https://api.github.com/repos/%s/actions/runs" % self.repo
        try:
            runs = self.get_json("%s?branch=%s&per_page=1" % (base, urllib.parse.quote(self.branch, safe="")))
            items = runs.get("workflow_runs", [])
            if not items:
                return [Evidence("ci", "No CI runs found for branch %s" % self.branch,
                                 data={"conclusion": None, "status": "none", "failed": []})]
            run = items[0]
            failed = []
            if run.get("conclusion") == "failure":
                jobs = self.get_json("%s/%s/jobs" % (base, run["id"])).get("jobs", [])
                for job in jobs:
                    if job.get("conclusion") == "failure":
                        step = next((s["name"] for s in job.get("steps", [])
                                     if s.get("conclusion") == "failure"), "unknown step")
                        failed.append({"job": job.get("name", "?"), "step": step})
        except Exception as exc:
            return [Evidence("ci", "Could not read CI status: %s" % exc, error=str(exc))]
        text = "CI run '%s' on %s: status=%s conclusion=%s" % (
            run.get("name"), self.branch, run.get("status"), run.get("conclusion"))
        return [Evidence("ci", text, excerpt=run.get("html_url", ""),
                         data={"status": run.get("status"), "conclusion": run.get("conclusion"),
                               "url": run.get("html_url", ""), "sha": run.get("head_sha", ""),
                               "failed": failed})]


class DeploymentCollector:
    def __init__(self, namespace, deployment, run=read_only_runner):
        self.ns, self.name, self.run = namespace, deployment, run

    def _json(self, *args):
        argv = ["kubectl", "-n", self.ns] + list(args) + ["-o", "json"]
        assert_read_only(argv)                  # defence in depth, whatever `run` is
        rc, out = self.run(argv)
        if rc != 0:
            raise RuntimeError(redact(out).strip()[:200] or "kubectl exited %s" % rc)
        return json.loads(out)

    def collect(self):
        try:
            dep = self._json("get", "deployment", self.name)
            pods = self._json("get", "pods", "-l", "app.kubernetes.io/name=%s" % self.name)
            events = self._json("get", "events")
        except Exception as exc:
            return [Evidence("deployment", "Could not read deployment status: %s" % exc, error=str(exc))]
        desired = dep.get("spec", {}).get("replicas", 0)
        ready = dep.get("status", {}).get("readyReplicas", 0)
        pod_info = []
        for pod in pods.get("items", []):
            statuses = pod.get("status", {}).get("containerStatuses", [{}]) or [{}]
            cs = statuses[0]
            waiting = (cs.get("state", {}) or {}).get("waiting", {}) or {}
            pod_info.append({"name": pod.get("metadata", {}).get("name", "?"),
                             "ready": bool(cs.get("ready")), "restarts": cs.get("restartCount", 0),
                             "waiting_reason": waiting.get("reason", "")})
        warnings = [{"reason": e.get("reason", ""), "object": e.get("involvedObject", {}).get("name", ""),
                     "message": redact(e.get("message", ""))[:200]}
                    for e in events.get("items", []) if e.get("type") == "Warning"][:10]
        summary = "Deployment %s/%s: %s of %s replicas ready; %d warning events" % (
            self.ns, self.name, ready, desired, len(warnings))
        return [Evidence("deployment", summary,
                         excerpt="; ".join("%s %s" % (w["reason"], w["message"]) for w in warnings[:3]),
                         data={"namespace": self.ns, "name": self.name, "desired": desired,
                               "ready": ready, "pods": pod_info, "warnings": warnings})]


_NAME_OK = re.compile(r"^[\w.-]+$")


def merged_runner(argv, timeout=20):
    """Read-only runner that returns stdout + stderr (nginx writes its error log to stderr)."""
    assert_read_only(argv)
    proc = subprocess.run(list(argv), capture_output=True, text=True, timeout=timeout)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def docker_log_lines(container, run=merged_runner):
    if not _NAME_OK.match(container):
        raise ValueError("invalid container name")
    rc, out = run(["docker", "logs", "--tail", "200", container])
    if rc != 0:
        raise RuntimeError(redact(out).strip()[:200] or "docker logs exited %s" % rc)
    return out.splitlines()


def kube_log_lines(namespace, deployment, run=merged_runner):
    rc, out = run(["kubectl", "-n", namespace, "logs", "-l", "app.kubernetes.io/name=%s" % deployment,
                   "--tail=100"])
    if rc != 0:
        raise RuntimeError(redact(out).strip()[:200] or "kubectl logs exited %s" % rc)
    return out.splitlines()


class DockerCollector:
    """Container state from `docker ps -a`, filtered by name."""

    def __init__(self, name_filter, run=read_only_runner):
        if not _NAME_OK.match(name_filter):
            raise ValueError("invalid container name filter")
        self.name_filter, self.run = name_filter, run

    def collect(self):
        argv = ["docker", "ps", "-a", "--filter", "name=%s" % self.name_filter, "--format", "{{json .}}"]
        assert_read_only(argv)
        try:
            rc, out = self.run(argv)
            if rc != 0:
                raise RuntimeError(redact(out).strip()[:200] or "docker exited %s" % rc)
            containers = []
            for line in out.splitlines():
                if line.strip():
                    rec = json.loads(line)
                    containers.append({"name": rec.get("Names", "?"), "image": rec.get("Image", "?"),
                                       "status": rec.get("Status", "?")})
        except Exception as exc:
            return [Evidence("docker", "Could not read Docker status: %s" % exc, error=str(exc))]
        summary = "Docker containers matching '%s': %s" % (
            self.name_filter, "; ".join("%s (%s)" % (c["name"], c["status"]) for c in containers) or "none found")
        return [Evidence("docker", summary, data={"containers": containers})]
