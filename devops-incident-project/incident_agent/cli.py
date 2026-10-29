"""Command line: collect evidence, print the diagnosis, optionally add a local-LLM analysis,
and optionally offer each suggested command for explicit human approval."""
import argparse
import json
import subprocess
import sys

from . import collectors as c
from .analyzer import SOURCES, diagnose
from .approval import ApprovalGate, ApprovalRequired, Executor, PolicyViolation
from .audit import AuditLog
from .llm.ollama_client import DEFAULT_MODEL, OllamaClient, OllamaError
from .llm.prompt import build_messages
from .llm.validate import ValidationError, validate
from .models import assign_ids
from .report import render, render_llm

# which evidence sources each subcommand collects
WANT = {
    "health": ("health",),
    "docker": ("docker", "logs"),
    "ci": ("ci",),
    "k8s": ("deployment", "logs"),
    "diagnose": ("health", "docker", "logs", "ci", "deployment"),
}


def _real_runner(argv):
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    return proc.returncode, (proc.stdout or proc.stderr)


def build_collectors(args, cmd):
    """Returns (collectors, expected_sources). A --bundle JSON file replaces the live systems."""
    want, cols, built = WANT[cmd], [], []
    bundle = None
    if args.bundle:
        with open(args.bundle, encoding="utf-8") as fh:
            bundle = json.load(fh)

    def add(source, collector):
        cols.append(collector)
        built.append(source)

    if "health" in want:
        if bundle and "health" in bundle:
            h = bundle["health"]
            add("health", c.HealthCollector(args.health_url or "http://bundle/healthz",
                                            lambda url, timeout=3.0: (h.get("status"), h.get("body", ""), h.get("error", ""))))
        elif not bundle and args.health_url:
            add("health", c.HealthCollector(args.health_url))
    if "docker" in want:
        if bundle and "docker" in bundle:
            lines = "\n".join(json.dumps(x) for x in bundle["docker"])
            add("docker", c.DockerCollector(args.docker_container or "bundle", lambda argv: (0, lines)))
        elif not bundle and args.docker_container:
            add("docker", c.DockerCollector(args.docker_container))
    if "logs" in want:
        if bundle and "logs" in bundle:
            add("logs", c.LogCollector(lambda: bundle["logs"]))
        elif not bundle and args.logs_file:
            add("logs", c.LogCollector(lambda: open(args.logs_file, encoding="utf-8", errors="replace").read().splitlines()))
        elif not bundle and args.docker_container and cmd in ("docker", "diagnose"):
            add("logs", c.LogCollector(lambda: c.docker_log_lines(args.docker_container)))
        elif not bundle and cmd == "k8s":
            add("logs", c.LogCollector(lambda: c.kube_log_lines(args.namespace, args.deployment)))
    if "ci" in want:
        if bundle and "ci" in bundle:
            ci = bundle["ci"]
            add("ci", c.CICollector(args.ci_repo or "owner/repo", args.ci_branch,
                                    lambda url: ci["jobs"] if "/jobs" in url else {"workflow_runs": [ci["run"]]}))
        elif not bundle and args.ci_repo:
            add("ci", c.CICollector(args.ci_repo, args.ci_branch))
    if "deployment" in want:
        if bundle and "deployment" in bundle:
            dep = bundle["deployment"]

            def run(argv):
                for key in ("deployment", "pods", "events"):
                    if key in argv:
                        return 0, json.dumps(dep[key])
                return 1, "unsupported in bundle"
            add("deployment", c.DeploymentCollector(args.namespace, args.deployment, run))
        elif not bundle:
            add("deployment", c.DeploymentCollector(args.namespace, args.deployment))
    expected = tuple(built) if cmd != "diagnose" else tuple(dict.fromkeys(SOURCES + tuple(built)))
    return cols, expected


def _add_common(p):
    p.add_argument("--health-url")
    p.add_argument("--logs-file")
    p.add_argument("--docker-container", help="container name (or part of it)")
    p.add_argument("--ci-repo", help="owner/name on GitHub")
    p.add_argument("--ci-branch", default="master")
    p.add_argument("--namespace", default="food-delivery")
    p.add_argument("--deployment", default="food-delivery-ui")
    p.add_argument("--bundle", help="offline JSON file used instead of live systems")
    p.add_argument("--llm", action="store_true", help="add an analysis from a local Ollama model")
    p.add_argument("--model", default=None, help="Ollama model (default: $OLLAMA_MODEL or %s)" % DEFAULT_MODEL)
    p.add_argument("--ollama-url", default=None, help="must be localhost (default http://127.0.0.1:11434)")
    p.add_argument("--interactive", action="store_true", help="offer each suggested command for approval")
    p.add_argument("--approver", default="operator")
    p.add_argument("--audit-log", default="incident-audit.jsonl")


def run_llm(diag, client, out):
    try:
        system, user = build_messages(diag.evidence)
        raw = client.generate_json(system, user)
        analysis = validate(raw, {e.id for e in diag.evidence})
    except (OllamaError, ValidationError) as exc:
        out("\nAI analysis unavailable: %s\nThe rule-based diagnosis above is unaffected." % exc)
        return
    out(render_llm(analysis, client.model))


def main(argv=None, ask=input, out=print, runner=_real_runner, llm_client=None):
    p = argparse.ArgumentParser(prog="incident_agent")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, text in (("k8s", "Kubernetes pods, events and logs"), ("ci", "GitHub Actions result"),
                       ("docker", "Docker container status and logs"), ("health", "application /healthz check"),
                       ("diagnose", "everything that is configured")):
        _add_common(sub.add_parser(name, help=text))
    chk = sub.add_parser("llm-check", help="check that Ollama is running locally and the model is installed")
    chk.add_argument("--model")
    chk.add_argument("--ollama-url")
    args = p.parse_args(argv)

    if args.cmd == "llm-check":
        try:
            client = llm_client or OllamaClient(args.ollama_url, args.model)
            names = client.models()
        except OllamaError as exc:
            out("NOT READY: %s" % exc)
            return 1
        ok = any(n == client.model or (":" not in client.model and n.split(":")[0] == client.model) for n in names)
        out("Ollama is running locally. Installed models: %s" % (", ".join(names) or "none"))
        out("Model '%s': %s" % (client.model, "installed" if ok else "NOT installed (run: ollama pull %s)" % client.model))
        return 0 if ok else 1

    cols, expected = build_collectors(args, args.cmd)
    evidence = []
    for col in cols:
        evidence.extend(col.collect())
    diag = diagnose(assign_ids(evidence), args.namespace, args.deployment, expected)
    out(render(diag))

    if args.llm:
        try:
            client = llm_client or OllamaClient(args.ollama_url, args.model)
        except OllamaError as exc:
            out("\nAI analysis unavailable: %s" % exc)
        else:
            run_llm(diag, client, out)

    runnable = [a for a in diag.actions if a.command]
    if not args.interactive:
        out("\nNo action was executed. Re-run with --interactive to review actions one by one.")
        return 0
    audit = AuditLog(args.audit_log)
    gate = ApprovalGate(ask, args.approver, audit)
    executor = Executor(runner, audit)
    for action in runnable:
        out("\n%s: %s\n  command: %s" % (action.id, action.description, " ".join(action.command)))
        if action.changes_environment:
            out("  WARNING: this changes the environment.")
        approval = gate.request(action)
        if approval is None:
            out("  Not approved - skipped.")
            continue
        try:
            rc, output = executor.execute(action, approval)
            out("  exit code %s\n%s" % (rc, output))
        except (ApprovalRequired, PolicyViolation) as exc:
            out("  Blocked: %s" % exc)
    return 0


if __name__ == "__main__":
    sys.exit(main())
