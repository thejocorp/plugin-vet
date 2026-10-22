"""Command line: scan a local path or a git URL and report what a reviewer should know.

    plugin-vet ./some-plugin
    plugin-vet https://github.com/owner/repo
    plugin-vet ./x --json
    plugin-vet ./x --fail-on medium        # exit 1 if a medium-or-worse finding exists
    plugin-vet ./x --policy my-policy.json

A git URL is cloned shallow into a temporary directory and removed afterwards. The clone is
never built, installed or run; only its files are read.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from . import __version__
from .policy import LEVELS, Policy
from .scan import scan

ICON = {"high": "[HIGH]", "medium": "[MED ]", "low": "[LOW ]", "info": "[INFO]"}


def _is_url(target: str) -> bool:
    return target.startswith(("http://", "https://", "git@", "ssh://"))


def _clone(url: str, into: Path) -> Path:
    dest = into / "repo"
    subprocess.run(
        ["git", "clone", "--depth", "1", "--quiet", url, str(dest)],
        check=True,
        env={"GIT_TERMINAL_PROMPT": "0", "PATH": "/usr/bin:/bin:/usr/local/bin"},
        timeout=600,
    )
    return dest


def render(result, policy: Policy) -> str:
    lines = [f"plugin-vet {__version__}", f"target: {result.target}", f"kind:   {result.kind}", ""]
    if not result.findings:
        lines.append("No findings. Nothing in the checklist tripped. Still read the code before trusting it.")
        return "\n".join(lines)
    ordered = sorted(result.findings, key=lambda f: -policy.rank(policy.severity(f.category)))
    lines.append(f"{len(ordered)} finding(s):")
    for f in ordered:
        lines.append(f"  {ICON.get(policy.severity(f.category), '[    ]')} {f.category}: {f.detail}")
    worst = policy.worst(result.findings)
    lines.append("")
    lines.append(f"worst severity: {worst}")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="plugin-vet", description=__doc__.strip().splitlines()[0])
    ap.add_argument("target", help="a local directory, or a git URL to clone and scan")
    ap.add_argument("--json", action="store_true", help="print the full result as JSON")
    ap.add_argument("--policy", help="a JSON file overriding finding severities")
    ap.add_argument("--fail-on", default="high", choices=LEVELS,
                    help="exit non-zero when a finding at this severity or worse exists (default: high)")
    ap.add_argument("--version", action="version", version=f"plugin-vet {__version__}")
    a = ap.parse_args(argv)

    policy = Policy.from_file(a.policy) if a.policy else Policy()

    tmp = None
    try:
        if _is_url(a.target):
            tmp = Path(tempfile.mkdtemp(prefix="plugin-vet-"))
            path = _clone(a.target, tmp)
        else:
            path = Path(a.target)
        result = scan(path)
        result.target = a.target
    except subprocess.CalledProcessError:
        print(f"could not clone {a.target}", file=sys.stderr)
        return 2
    except (NotADirectoryError, FileNotFoundError) as e:
        print(str(e), file=sys.stderr)
        return 2
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)

    if a.json:
        out = {
            "target": result.target,
            "kind": result.kind,
            "facts": result.facts,
            "findings": [
                {"category": f.category, "severity": policy.severity(f.category), "detail": f.detail, "path": f.path}
                for f in result.findings
            ],
            "worst_severity": policy.worst(result.findings),
        }
        print(json.dumps(out, indent=2))
    else:
        print(render(result, policy))

    return 1 if policy.fails(result.findings, a.fail_on) else 0


def _run():
    try:
        return main()
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except Exception:
            pass
        return 0
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(_run())
