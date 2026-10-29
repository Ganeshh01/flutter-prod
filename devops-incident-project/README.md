# devops-incident-project

An incident-diagnosis agent for the food-delivery UI deployment. It reads health checks,
application logs, CI status and Kubernetes deployment status, then prints an
evidence-labelled diagnosis and a remediation plan. **It never changes anything without
a human typing an explicit approval for that exact action.**

Python 3.9+, standard library only (nothing to install).

## Run it

```powershell
# Diagnose (read-only; executes nothing)
py -3 -m incident_agent diagnose `
  --health-url http://127.0.0.1:18085/healthz `
  --docker-container food-delivery-ui-test `
  --ci-repo Ganeshh01/flutter-prod --ci-branch feature/devops-ci-pipeline `
  --namespace food-delivery --deployment food-delivery-ui

# Same, but offer each suggested command for approval one at a time
py -3 -m incident_agent diagnose ... --interactive
```

Any source can be omitted; a missing or unreadable source is reported as an *unknown*,
never guessed. `--logs-file <path>` reads a saved log instead of Docker. `--bundle <json>`
replaces all live systems with a saved file (used for demos and tests).

## Local AI analysis (Ollama, optional)

Add `--llm` to `k8s`, `ci`, `docker`, `health` or `diagnose` to get an analysis from a **local**
open-source model (default `phi3.5`, MIT licensed). Evidence is sanitized first and sent to
`127.0.0.1` only. The model's answer is validated (facts must cite real evidence ids, anything else is
labelled unsupported or an assumption), and its commands are never run. Full setup: [docs/SETUP.md](docs/SETUP.md).

```powershell
py -3 -m incident_agent llm-check
py -3 -m incident_agent k8s --llm
py -3 -m incident_agent k8s --bundle examples\crashloop.json --llm     # safe demo on a broken example
```

## Run the tests (mocks only: no cluster, network or Docker)

```powershell
py -3 -I -m unittest discover -s tests -t . -v
```

## How to read a report

| Section | Meaning |
|---|---|
| OBSERVED | Stated directly by collected evidence; cites evidence ids (E1, E2 ...). |
| INFERRED | Reasoned from evidence; the reasoning is printed; not proven. |
| ASSUMED | No evidence either way; always low confidence. |
| UNKNOWNS | What could not be determined, and why. |
| REMEDIATION PLAN | Suggestions only. Each is tagged read-only, manual, or CHANGES ENVIRONMENT. |

## Safety model

1. **Collectors are read-only.** Only `kubectl get/describe/logs/rollout status` and
   `docker logs/inspect/ps` pass the guard (`collectors.assert_read_only`); anything else raises.
2. **The agent only proposes.** A `ProposedAction` is plain data.
3. **Execution needs an `Approval`.** It can only be created by `ApprovalGate` after a human
   types `yes <action id>`. It is bound to that exact command, expires after 5 minutes, and
   works once. An empty answer or end-of-input counts as a rejection.
4. **Policy still applies after approval.** Environment-changing commands must match
   `kubectl -n <ns> rollout restart|undo deployment/<name>` and nothing else. An action labelled
   read-only that is not read-only is blocked.
5. **Everything is audited** to `incident-audit.jsonl` (proposed, approved, rejected, blocked,
   executed), with secrets redacted.
6. **Log text is data.** It is quoted as evidence and can never create an action.

## Layout

```
incident_agent/  models.py  collectors.py  analyzer.py  approval.py  audit.py  redact.py  report.py  cli.py
tests/           test_agent.py   (28 tests)
ci/              container-smoke-test.sh
```

## Pointing it at another application

Change the arguments only: health URL, container or log file, `owner/repo` and branch,
namespace and deployment name. The Kubernetes pod selector assumes the label
`app.kubernetes.io/name=<deployment>`; change it in `DeploymentCollector.collect` if yours differs.

## Known limits

- Rules are deterministic and cover: health failing, 5xx/error-log lines, CI failures, pods not
  ready (ImagePullBackOff, CrashLoopBackOff, config errors), restarts, warning events.
  An LLM could be added behind the same evidence schema, but it is not part of this version.
- GitHub CI status uses the public API, so it works for public repos only (private repos return an error,
  reported as an unknown).
- CI failures are classified from the step name; the step's own log is not read.
