"""Minimal Ollama client (standard library only) that can only talk to this machine.

Hosted AI APIs are impossible by construction: any host other than 127.0.0.1, localhost
or ::1 is refused before a connection is made, and redirects are never followed.
"""
import json
import os
import urllib.error
import urllib.parse
import urllib.request

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
DEFAULT_URL = "http://127.0.0.1:11434"
DEFAULT_MODEL = "phi3.5"

# Constrains the model's answer shape (Ollama structured outputs).
SCHEMA = {
    "type": "object",
    "properties": {
        "root_causes": {"type": "array", "items": {
            "type": "object",
            "properties": {
                "claim": {"type": "string"},
                "type": {"type": "string", "enum": ["fact", "assumption"]},
                "evidence_ids": {"type": "array", "items": {"type": "string"}},
                "confidence": {"type": "string", "enum": ["low", "medium", "high"]}},
            "required": ["claim", "type", "evidence_ids", "confidence"]}},
        "suggested_fixes": {"type": "array", "items": {
            "type": "object",
            "properties": {"description": {"type": "string"}, "command": {"type": "string"}},
            "required": ["description"]}},
        "verification_commands": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["root_causes", "suggested_fixes", "verification_commands"],
}


class OllamaError(Exception):
    """Ollama is unreachable, refused, or returned something unusable."""


def check_local(url):
    parts = urllib.parse.urlparse(url)
    if parts.scheme != "http" or (parts.hostname or "").lower() not in LOCAL_HOSTS:
        raise OllamaError("refusing to send data to %r: only http://127.0.0.1, localhost or ::1 is allowed" % url)
    return url.rstrip("/")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def _http(method, url, payload=None, timeout=300):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with _opener.open(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")[:300]
        exc.close()
        if exc.code in (301, 302, 303, 307, 308):
            raise OllamaError("Ollama tried to redirect the request; refusing to follow it")
        raise OllamaError("Ollama returned HTTP %d: %s" % (exc.code, body))
    except urllib.error.URLError as exc:
        raise OllamaError("Ollama is not reachable at %s (%s). Start it with 'ollama serve'." % (url, exc.reason))
    except (TimeoutError, OSError) as exc:
        raise OllamaError("Ollama request failed or timed out: %s" % exc)
    except ValueError:
        raise OllamaError("Ollama returned a response that is not valid JSON")


class OllamaClient:
    def __init__(self, base_url=None, model=None, timeout=300, http=_http):
        self.base_url = check_local(base_url or os.environ.get("OLLAMA_HOST_URL") or DEFAULT_URL)
        self.model = model or os.environ.get("OLLAMA_MODEL") or DEFAULT_MODEL
        self.timeout, self._http = timeout, http

    def models(self):
        reply = self._http("GET", self.base_url + "/api/tags", None, 10)
        return [m.get("name", "") for m in reply.get("models", [])]

    def generate_json(self, system, user):
        """Returns the model's raw text answer. Caller must validate it."""
        names = self.models()
        if not any(n == self.model or n.split(":")[0] == self.model.split(":")[0] and ":" not in self.model
                   for n in names):
            raise OllamaError("model %r is not installed. Run: ollama pull %s" % (self.model, self.model))
        payload = {"model": self.model, "stream": False, "format": SCHEMA,
                   "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                   "options": {"temperature": 0, "num_ctx": 4096}}
        reply = self._http("POST", self.base_url + "/api/chat", payload, self.timeout)
        content = (reply.get("message") or {}).get("content")
        if not isinstance(content, str) or not content.strip():
            raise OllamaError("Ollama returned an empty answer")
        return content
