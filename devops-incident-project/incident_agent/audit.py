"""Append-only audit trail of every proposal, approval, rejection, block and execution."""
import json
import os
import time

from .redact import redact


class AuditLog:
    def __init__(self, path=None, clock=time.time):
        self.path = path
        self.clock = clock
        self.entries = []          # kept in memory too, so tests can inspect it

    def record(self, event, **fields):
        entry = {"ts": round(self.clock(), 3), "event": event}
        entry.update({k: redact(v) if isinstance(v, str) else v for k, v in fields.items()})
        self.entries.append(entry)
        if self.path:
            folder = os.path.dirname(os.path.abspath(self.path))
            os.makedirs(folder, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as fh:   # append only
                fh.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry
