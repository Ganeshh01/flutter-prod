"""Evidence and diagnosis schema. Standard library only."""
from dataclasses import dataclass, field

OBSERVED = "OBSERVED"  # stated directly by collected evidence
INFERRED = "INFERRED"  # derived from evidence; the reasoning must be written down
ASSUMED = "ASSUMED"    # no evidence either way; always low confidence

CONFIDENCE = ("low", "medium", "high")


@dataclass
class Evidence:
    """One thing a read-only collector saw. `id` is assigned by assign_ids()."""
    source: str                 # health | logs | ci | deployment
    summary: str
    excerpt: str = ""           # short, redacted quote of the raw data
    data: dict = field(default_factory=dict)   # structured facts the rules read
    error: str = ""             # set when the source could not be read
    id: str = ""


@dataclass
class Finding:
    claim: str
    kind: str
    evidence_ids: list = field(default_factory=list)
    confidence: str = "medium"
    reasoning: str = ""

    def __post_init__(self):
        if self.kind not in (OBSERVED, INFERRED, ASSUMED):
            raise ValueError("unknown finding kind: %r" % self.kind)
        if self.confidence not in CONFIDENCE:
            raise ValueError("unknown confidence: %r" % self.confidence)
        if self.kind in (OBSERVED, INFERRED) and not self.evidence_ids:
            raise ValueError("%s finding must cite evidence: %s" % (self.kind, self.claim))
        if self.kind == INFERRED and not self.reasoning:
            raise ValueError("INFERRED finding must state its reasoning: %s" % self.claim)
        if self.kind == ASSUMED:
            self.confidence = "low"


@dataclass(frozen=True)
class ProposedAction:
    """A suggestion. It is data only: nothing runs until an Approval is presented."""
    id: str
    description: str
    command: tuple = ()               # argv list; empty = manual step for a human
    changes_environment: bool = False
    rationale: str = ""


@dataclass
class Diagnosis:
    status: str                       # HEALTHY | DEGRADED | INDETERMINATE
    summary: str
    findings: list
    unknowns: list
    actions: list
    evidence: list


def assign_ids(evidence):
    for n, ev in enumerate(evidence, 1):
        ev.id = "E%d" % n
    return evidence
