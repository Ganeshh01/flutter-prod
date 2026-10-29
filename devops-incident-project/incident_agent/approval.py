"""Human approval and execution control.

The agent can only *propose* actions (ProposedAction is plain data). The Executor will
run a command only when it is handed an Approval that:
  * was issued by an ApprovalGate (a human typed `yes <action id>`; no other way to make one),
  * is bound to this exact action (digest of id + command),
  * has not expired and has not been used before,
and the command itself passes policy: read-only commands must pass the read-only guard,
and environment-changing commands must match a narrow allowlist. Every step is audited.
"""
import hashlib
import json
import re
import time
from dataclasses import dataclass, field

from .collectors import assert_read_only
from .redact import redact

_NAME = r"[a-z0-9]([-a-z0-9]*[a-z0-9])?"
_MUTATING_ALLOWLIST = [
    # kubectl -n <ns> rollout restart|undo deployment/<name>   -- nothing else may change the environment
    re.compile(r"^kubectl -n %s rollout (restart|undo) deployment/%s$" % (_NAME, _NAME)),
]


class ApprovalRequired(Exception):
    """No valid human approval was presented."""


class PolicyViolation(Exception):
    """The command is not permitted, even with an approval."""


def action_digest(action):
    payload = json.dumps([action.id, list(action.command), action.changes_environment])
    return hashlib.sha256(payload.encode()).hexdigest()


_ISSUER = object()   # only ApprovalGate holds this


@dataclass
class Approval:
    action_id: str
    digest: str
    approver: str
    expires_at: float
    used: bool = False
    _issuer: object = field(default=None, repr=False, compare=False)

    def __post_init__(self):
        if self._issuer is not _ISSUER:
            raise ApprovalRequired("approvals can only be issued by an ApprovalGate")


class ApprovalGate:
    def __init__(self, ask, approver, audit, clock=time.time, ttl_seconds=300):
        self.ask, self.approver, self.audit = ask, approver, audit
        self.clock, self.ttl = clock, ttl_seconds

    def request(self, action):
        """Show the action and ask a human. Returns an Approval, or None if not approved."""
        self.audit.record("proposed", action=action.id, command=" ".join(action.command),
                          changes_environment=action.changes_environment)
        phrase = "yes %s" % action.id
        try:
            answer = self.ask("Type '%s' to approve, anything else to reject: " % phrase)
        except EOFError:
            answer = ""
        if answer.strip() != phrase:
            self.audit.record("rejected", action=action.id, approver=self.approver)
            return None
        self.audit.record("approved", action=action.id, approver=self.approver)
        return Approval(action.id, action_digest(action), self.approver,
                        self.clock() + self.ttl, _issuer=_ISSUER)


class Executor:
    def __init__(self, runner, audit, clock=time.time):
        self.runner, self.audit, self.clock = runner, audit, clock

    def _block(self, action, why, exc=PolicyViolation):
        self.audit.record("blocked", action=action.id, command=" ".join(action.command), reason=why)
        raise exc(why)

    def execute(self, action, approval):
        if not action.command:
            self._block(action, "this is a manual step; there is no command to run")
        if not isinstance(approval, Approval):
            self._block(action, "no approval presented", ApprovalRequired)
        if approval.action_id != action.id or approval.digest != action_digest(action):
            self._block(action, "approval does not match this action", ApprovalRequired)
        if approval.used:
            self._block(action, "approval was already used", ApprovalRequired)
        if self.clock() > approval.expires_at:
            self._block(action, "approval expired", ApprovalRequired)
        # Policy applies even to approved actions.
        if action.changes_environment:
            if not any(p.match(" ".join(action.command)) for p in _MUTATING_ALLOWLIST):
                self._block(action, "command is not on the allowlist for environment changes")
        else:
            try:
                assert_read_only(action.command)
            except PermissionError as exc:
                self._block(action, "action is labelled read-only but is not: %s" % exc)
        approval.used = True                       # single use
        self.audit.record("executing", action=action.id, command=" ".join(action.command),
                          approver=approval.approver)
        rc, out = self.runner(list(action.command))
        self.audit.record("executed", action=action.id, returncode=rc, output=redact(out)[:500])
        return rc, out
