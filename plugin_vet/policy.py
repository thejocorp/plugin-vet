"""Severity policy: how serious each kind of finding is, and what makes a scan fail.

The scanner only reports what it sees. This decides how loud each finding is and, given a
threshold, whether the whole scan passes. The defaults are deliberately strict; override any
of them with a JSON file passed to the CLI (--policy), mapping a category to a severity.
"""
from __future__ import annotations

import json

LEVELS = ["info", "low", "medium", "high"]

DEFAULT_SEVERITY = {
    "committed-secret": "high",        # a real credential shipped in the repo
    "prompt-injection": "high",        # text that tries to steer an agent or reach secrets
    "pipe-to-shell": "high",           # install by piping a download into a shell
    "program-file": "high",            # a binary a reviewer cannot read
    "every-call-hook": "medium",       # sees every tool call
    "background-service": "medium",    # keeps running after setup
    "telemetry": "medium",             # phones home with usage
    "unpinned-fetch": "medium",        # pulls its newest version at every start
    "skill-contains-code": "medium",   # a "skill" that is really code
    "install-script": "low",           # runs scripts on npm install
}
UNKNOWN_SEVERITY = "low"


class Policy:
    def __init__(self, overrides: dict | None = None):
        self.severity_map = dict(DEFAULT_SEVERITY)
        if overrides:
            for cat, sev in overrides.items():
                if sev not in LEVELS:
                    raise ValueError(f"severity for {cat!r} must be one of {LEVELS}, got {sev!r}")
                self.severity_map[cat] = sev

    @classmethod
    def from_file(cls, path: str) -> "Policy":
        with open(path) as f:
            data = json.load(f)
        return cls(data.get("severity", data))

    def severity(self, category: str) -> str:
        return self.severity_map.get(category, UNKNOWN_SEVERITY)

    def rank(self, severity: str) -> int:
        return LEVELS.index(severity) if severity in LEVELS else 0

    def worst(self, findings) -> str | None:
        if not findings:
            return None
        return max((self.severity(f.category) for f in findings), key=self.rank)

    def fails(self, findings, fail_on: str) -> bool:
        if fail_on not in LEVELS:
            raise ValueError(f"--fail-on must be one of {LEVELS}")
        threshold = self.rank(fail_on)
        return any(self.rank(self.severity(f.category)) >= threshold for f in findings)
