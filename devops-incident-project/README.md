# AI-Powered DevOps Incident Diagnosis Agent

An AI-assisted DevOps incident diagnosis agent that collects operational evidence from application health checks, logs, CI pipelines, Docker containers and Kubernetes deployments.

It combines deterministic rule-based diagnosis with optional Google Gemini analysis to identify incident symptoms, distinguish observed facts from inferences, and recommend remediation steps.

**Safety first:** The agent is read-only by default. Environment-changing actions require explicit human approval and are subject to command policy checks.

## Problem Statement

During production incidents, DevOps engineers often need to investigate multiple sources independently, including application health, container logs, CI/CD pipelines and Kubernetes workloads.

This project automates evidence collection and organizes the findings into an understandable incident report. AI assistance helps interpret the collected evidence while preserving traceability and human control over remediation.

## Architecture

```text
Operational Sources
       |
       v
Evidence Collectors
       |
       v
Evidence Sanitization
       |
       v
Rule-Based Diagnosis
       |
       v
Optional Gemini AI Analysis
       |
       v
AI Response Validation
       |
       v
Incident Report
       |
       v
Proposed Remediation
       |
       v
Human Approval
       |
       v
Policy Check + Audit Log
```

## Features

- Health endpoint monitoring
- Docker container inspection
- Kubernetes deployment and pod status collection
- Application log analysis
- GitHub Actions CI status collection
- Evidence-based incident diagnosis
- Observed, inferred, assumed and unknown findings
- Optional Google Gemini-powered analysis
- Evidence citation validation for AI findings
- Secret and sensitive-data sanitization
- Human approval before permitted environment-changing actions
- Audit logging with redaction
- Offline incident simulation using JSON evidence bundles

## Technology Stack

- Python
- Google Gemini API (`google-genai`)
- Docker
- Kubernetes
- GitHub Actions
- PowerShell
- Python unittest

## Project Setup

Run these commands from the `devops-incident-project` directory.

### 1. Create and activate a virtual environment

```powershell
python -m venv .venv
.\\.venv\\Scripts\\Activate.ps1
```

### 2. Install Gemini dependencies

```powershell
python -m pip install -r requirements-gemini.txt
```

### 3. Configure the Gemini API key

```powershell
$env:GEMINI_API_KEY = Read-Host "Enter Gemini API key"
$env:GEMINI_MODEL = "gemini-3.5-flash-lite"
```

Never commit API keys or expose them in source code.

## Run the Agent

### Offline incident diagnosis

```powershell
python -m incident_agent diagnose --bundle .\\examples\\crashloop.json
```

### Gemini-powered incident diagnosis

```powershell
python -m incident_agent diagnose --bundle .\\examples\\crashloop.json --llm --provider gemini
```

### Kubernetes diagnosis

```powershell
python -m incident_agent k8s --llm --provider gemini
```

The Kubernetes command requires a configured and accessible Kubernetes context.

### Interactive approval mode

```powershell
python -m incident_agent diagnose --bundle .\\examples\\crashloop.json --interactive
```

Interactive mode presents proposed actions for review. Only actions explicitly approved by the human and allowed by the execution policy can run.

## Diagnosis Report

The report separates findings into:

| Section | Description |
|---|---|
| OBSERVED | Directly supported by collected evidence |
| INFERRED | Reasoned from evidence but not proven |
| ASSUMED | Not supported or contradicted by available evidence |
| UNKNOWNS | Information that could not be collected or determined |
| REMEDIATION PLAN | Suggested investigation and recovery steps |

AI-generated findings are validated against evidence identifiers before being displayed as a diagnosis.

## Safety and Security

1. Collectors issue read-only commands.
2. Evidence is sanitized before being sent to the external Gemini API.
3. AI-generated commands are never automatically executed.
4. Human approval is required for permitted environment-changing actions.
5. Approval is bound to the exact action, expires after five minutes and can only be used once.
6. Command policy checks remain active even after approval.
7. Audit events are recorded with sensitive values redacted.
8. Log content is treated as untrusted evidence, not as executable instructions.

**Note:** Sanitization reduces sensitive-data exposure but does not guarantee that all confidential information is removed. Use appropriate test evidence when demonstrating the hosted AI integration.

## Run Tests

```powershell
python -I -m unittest discover -s tests -t . -v
```

The current automated test suite contains 63 tests covering diagnosis, evidence handling, sanitization, Gemini client behavior, approval workflows and command safety.

## Project Structure

```text
devops-incident-project/
|
|-- incident_agent/
|   |-- llm/
|   |   |-- gemini_client.py
|   |   |-- ollama_client.py
|   |   |-- prompt.py
|   |   |-- validate.py
|   |
|   |-- analyzer.py
|   |-- approval.py
|   |-- audit.py
|   |-- cli.py
|   |-- collectors.py
|   |-- models.py
|   |-- redact.py
|   |-- report.py
|
|-- examples/
|   |-- crashloop.json
|
|-- tests/
|   |-- test_agent.py
|   |-- test_gemini.py
|   |-- test_llm.py
|
|-- docs/
|-- requirements-gemini.txt
|-- README.md
```

## Known Limitations

- The sample incident bundle is simulated evidence, not a live production incident.
- The Gemini service requires internet access and an available API quota.
- AI analysis is advisory and must be reviewed by an engineer.
- CI failure classification may rely on the failed step name when detailed logs are unavailable.
- Private GitHub repository access may require additional authentication configuration.

## Future Improvements

- FastAPI-based incident diagnosis endpoint
- Additional cloud and Kubernetes collectors
- Rich incident dashboards
- More automated incident scenarios
- Expanded integration testing

## Author

Ganesh Gorantala

AI-Powered DevOps Incident Diagnosis Agent — demonstrating evidence-based troubleshooting, AI-assisted analysis and human-controlled remediation.
