# OpsPilot AI Dashboard

Separate React/Vite frontend for the existing FastAPI + Gemini incident agent.

## Run
Requirements: Node.js 18+ and the Python FastAPI backend running at `127.0.0.1:8000`.

```powershell
npm install
npm run dev
```

Open the Vite URL (usually http://127.0.0.1:5173).

## Current API integration
- `GET /health`
- `POST /ask` with JSON `{ "question": "..." }`

Vite proxies `/api/*` to FastAPI and strips the `/api` prefix.

## Planned endpoint
The overview cards optionally request `GET /cluster/overview`. Your current backend does not yet expose this route, so the dashboard intentionally displays placeholders rather than fabricated values. Implement structured live collection for Pods, Deployments, CPU/memory and alerts before showing those metrics.

Keep Gemini keys on the backend. Keep collectors read-only. Put any remediation execution behind an authenticated approval gate, a strict command allowlist, and audit/verification logging.
