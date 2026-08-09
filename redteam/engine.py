"""
Red-team engine for provekit-mcp.

The discipline is the same one used in redteam-loop (github.com/Th3Circle-app/
redteam-loop): state an attack, fire it at the running service, and TRIAGE the
response into one of a few honest outcomes, never a bare pass/fail. The outcome
that matters most is `inconclusive`: if the server did not answer (crash,
timeout, garbled frame) we do NOT score that as "secure", we flag it as
unverified so a cold-start or a hang can never masquerade as a control holding.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# outcomes
HELD = "HELD"                 # an attack was correctly refused  (good)
BREACH = "BREACH"             # an attack succeeded              (bad, critical)
OK = "OK"                     # a legitimate call worked          (good)
REGRESSION = "REGRESSION"     # a legitimate call was wrongly refused (bad)
INCONCLUSIVE = "INCONCLUSIVE" # no usable response                (unverified)


@dataclass
class Result:
    name: str
    kind: str                 # "attack" or "control"
    outcome: str
    detail: str
    evidence: str = ""

    @property
    def bad(self) -> bool:
        return self.outcome in (BREACH, REGRESSION)


@dataclass
class Report:
    results: list[Result] = field(default_factory=list)

    def add(self, r: Result) -> Result:
        self.results.append(r)
        return r

    def counts(self) -> dict:
        c = {HELD: 0, BREACH: 0, OK: 0, REGRESSION: 0, INCONCLUSIVE: 0}
        for r in self.results:
            c[r.outcome] += 1
        return c

    @property
    def clean(self) -> bool:
        """Clean means: zero breaches, zero regressions, zero inconclusive.
        An inconclusive result is not a pass; the run is not clean until every
        control has actually been verified."""
        return not any(r.outcome in (BREACH, REGRESSION, INCONCLUSIVE)
                       for r in self.results)

    def render(self) -> str:
        c = self.counts()
        icon = {HELD: "✓", BREACH: "✗", OK: "✓",
                REGRESSION: "✗", INCONCLUSIVE: "?"}
        lines = ["", "=" * 68, "  provekit-mcp red-team report", "=" * 68]
        for r in self.results:
            lines.append(f"  [{icon[r.outcome]}] {r.outcome:<12} {r.name}")
            lines.append(f"        {r.detail}")
            if r.evidence:
                lines.append(f"        evidence: {r.evidence}")
        lines += [
            "-" * 68,
            f"  attacks held: {c[HELD]}   breaches: {c[BREACH]}   "
            f"controls OK: {c[OK]}   regressions: {c[REGRESSION]}   "
            f"inconclusive: {c[INCONCLUSIVE]}",
            f"  VERDICT: {'ALL CONTROLS HELD AND VERIFIED' if self.clean else 'ATTENTION REQUIRED'}",
            "=" * 68, "",
        ]
        return "\n".join(lines)
