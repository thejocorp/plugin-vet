"""Static checks on a coding-agent add-on: a plugin, a skill pack, or an MCP server.

The scanner reads files only. Nothing in the target is ever executed, imported or installed,
so a hostile add-on cannot act while it is being checked. Each rule looks for one concrete,
checkable thing and records a Finding; see the README for the full list and the reasoning.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

# --- what the rules look for -------------------------------------------------------------

# Compiled programs and archives: things a reviewer cannot read, shipped inside a repo.
PROGRAM_FILE = re.compile(
    r"\.(exe|dll|so|dylib|apk|msi|dmg|appimage|deb|rpm|pkg|bin|jar|whl|zip|7z|rar|gz|xz|bz2)$", re.I
)
# Build-tool launchers that many Java/Android projects legitimately carry.
PROGRAM_OK = re.compile(
    r"(^|/)(gradle/wrapper/gradle-wrapper|\.mvn/wrapper/maven-wrapper)\.jar$", re.I
)
# Folders whose contents are expected to be non-code (do not flag binaries there).
SAMPLE_DIR = re.compile(r"(^|/)(tests?|fixtures?|testdata|examples?|samples?|docs?|__tests__)/", re.I)
# Co-located test files (Go, JS/TS, Ruby, pytest): expected to hold fake keys and sample text.
TEST_FILE = re.compile(r"(_test\.(go|py|rb)$|\.test\.[cm]?[jt]sx?$|\.spec\.[cm]?[jt]sx?$|(^|/)test_[^/]*\.py$)", re.I)
# Source files worth reading for telemetry/secret markers.
CODE_FILE = re.compile(r"\.(js|mjs|cjs|ts|tsx|jsx|py|go|rs|rb|php|java|cs|toml|json|ya?ml|sh)$", re.I)
SKIP_DIR = {".git", "node_modules", "dist", "build", "vendor", ".venv", "venv", "__pycache__"}

# Hook events that run on *every* model turn or tool call: an add-on that registers one sees
# everything you do, so it deserves an explicit look.
EVERY_CALL_HOOKS = ("PreToolUse", "PostToolUse", "UserPromptSubmit")

TELEMETRY = re.compile(
    r"posthog|mixpanel|amplitude|segment\.(?:io|com)|@sentry/|sentry_sdk|\bumami\b|plausible\.io|"
    r"@opentelemetry/|go\.opentelemetry\.io|opentelemetry-|analytics\.(?:track|identify|page)\b", re.I
)
# A background process that keeps running after setup.
SERVICE = re.compile(r"(^|/)[^/]+\.service$|\.plist$|(^|/)crontab$|systemctl\s+enable", re.I)
# An installer that pipes a download straight into a shell.
PIPE_TO_SHELL = re.compile(
    r"(?:curl|wget)\s[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b"
    r"|iwr\s[^\n|]*\|\s*iex\b|Invoke-WebRequest[^\n|]*\|\s*Invoke-Expression",
    re.I,
)
# Text aimed at an AI agent reading the repo, or an attempt to reach credentials / exfiltrate.
AGENT_DIRECTED = re.compile(
    r"ignore (?:all )?previous instructions|disregard (?:all )?prior|you are now|"
    r"\.ssh/|id_rsa|id_ed25519|\.aws/credentials|\.env\b|webhook\.site|ngrok\.io|"
    r"base64\s+-d|exfiltrat", re.I
)
# A committed value that looks like a real secret.
SECRET_VALUE = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "an AWS access key id"),
    (re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----"), "a private key"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "a GitHub token"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "a Slack token"),
    (re.compile(r"sk-[A-Za-z0-9]{32,}"), "an API secret key"),
    (re.compile(r"AIza[0-9A-Za-z_\-]{35}"), "a Google API key"),
]
SECRET_FILE_NAME = re.compile(r"(^|/)(id_rsa|id_ed25519|.*\.pem|.*\.pfx|.*\.p12)$", re.I)
# Text files a skill may legitimately contain (everything else in a skill folder is code).
SKILL_TEXT = re.compile(r"\.(md|markdown|txt|rst|json|ya?ml|csv|png|jpe?g|gif|svg|webp|pdf)$", re.I)
# An add-on that fetches whatever version is newest each time it starts (not pinned).
UNPINNED_CMD = {"npx", "bunx", "uvx", "pnpm", "yarn", "pipx"}

READ_LIMIT = 400_000


@dataclass
class Finding:
    category: str          # stable slug, e.g. "every-call-hook"
    detail: str            # one human sentence
    path: str = ""         # file it was found in, relative to the target


@dataclass
class ScanResult:
    target: str
    kind: str              # claude-plugin | skill | mcp-server | npm-cli | pip-cli | unknown
    findings: list = field(default_factory=list)
    facts: dict = field(default_factory=dict)


def _read(p: Path, limit: int = READ_LIMIT) -> str:
    try:
        if p.is_file() and not p.is_symlink():
            return p.read_text("utf-8", "replace")[:limit]
    except OSError:
        pass
    return ""


def _iter_files(root: Path):
    for p in root.rglob("*"):
        rel = p.relative_to(root)
        if any(part in SKIP_DIR for part in rel.parts):
            continue
        if p.is_file():
            yield rel, p


def _unpinned_servers(text: str):
    """MCP servers started through npx/uvx/... with no pinned version, from a JSON config."""
    try:
        conf = json.loads(text)
    except ValueError:
        return []
    servers = conf.get("mcpServers") if isinstance(conf, dict) else None
    out = []
    if isinstance(servers, dict):
        for name, spec in servers.items():
            if not isinstance(spec, dict):
                continue
            cmd = Path(str(spec.get("command", ""))).name
            if cmd not in UNPINNED_CMD:
                continue
            args = [a for a in spec.get("args", []) if isinstance(a, str) and not a.startswith("-") and a != "dlx"]
            pkg = args[0] if args else ""
            if pkg and (pkg.endswith("@latest") or not re.search(r"[@=]\d", pkg)):
                out.append(f"{name}: {cmd} {pkg}")
    return out


def _detect_kind(root: Path, facts: dict) -> str:
    if (root / ".claude-plugin" / "marketplace.json").is_file() or (root / ".claude-plugin" / "plugin.json").is_file():
        return "claude-plugin"
    if facts.get("mcp_configs"):
        return "mcp-server"
    if facts.get("skills"):
        return "skill"
    if facts.get("npm"):
        return "npm-cli"
    if facts.get("pip"):
        return "pip-cli"
    return "unknown"


def scan(path) -> ScanResult:
    """Scan a local directory and return a ScanResult. Does not clone or run anything."""
    root = Path(path)
    if not root.is_dir():
        raise NotADirectoryError(f"not a directory: {root}")
    findings: list[Finding] = []
    facts: dict = {"files": 0, "skills": [], "plugins": [], "mcp_configs": [], "npm": None, "pip": None}
    skill_dirs: list[str] = []
    telem_hits: list = []

    for rel, p in _iter_files(root):
        facts["files"] += 1
        s = str(rel)

        if PROGRAM_FILE.search(s) and not PROGRAM_OK.search(s) and not SAMPLE_DIR.search(s):
            findings.append(Finding("program-file", f"a compiled or archived file is committed: {s}", s))

        if SERVICE.search(s):
            findings.append(Finding("background-service", f"sets up a background service: {s}", s))

        if SECRET_FILE_NAME.search(s) and not SAMPLE_DIR.search(s):
            findings.append(Finding("committed-secret", f"a credential file is committed: {s}", s))

        if rel.name.lower() == "skill.md":
            skill_dirs.append(str(rel.parent))

        if rel.name in ("hooks.json", "plugin.json", "settings.json") or s.endswith(".claude/settings.json"):
            text = _read(p)
            for ev in EVERY_CALL_HOOKS:
                if f'"{ev}"' in text:
                    findings.append(Finding("every-call-hook", f"registers a {ev} hook (runs on every tool call): {s}", s))

        if rel.name == ".mcp.json" or (rel.name in ("plugin.json", "config.json") and '"mcpServers"' in _read(p, 2000)):
            facts["mcp_configs"].append(s)
            for u in _unpinned_servers(_read(p)):
                findings.append(Finding("unpinned-fetch", f"starts an MCP server at its newest version, unpinned: {u}", s))

        if CODE_FILE.search(rel.name) and not SAMPLE_DIR.search(s) and not TEST_FILE.search(s):
            text = _read(p)
            m = TELEMETRY.search(text)
            if m:
                telem_hits.append((s, m.group(0)))
            for rx, what in SECRET_VALUE:
                if rx.search(text):
                    findings.append(Finding("committed-secret", f"contains {what}: {s}", s))
                    break

        low = rel.name.lower()
        # Only the add-on's OWN install path: a root README or an install script. Deep docs,
        # examples and tests often show a "curl | sh" for other tools; those are not findings.
        is_installer = low in ("install.sh", "setup.sh", "install.ps1", "bootstrap.sh") and not SAMPLE_DIR.search(s)
        is_root_readme = low == "readme.md" and len(rel.parts) == 1
        if is_installer or is_root_readme:
            if PIPE_TO_SHELL.search(_read(p)):
                findings.append(Finding("pipe-to-shell", f"the install instructions pipe a download into a shell: {s}", s))

    if telem_hits:
        path0, sdk0 = telem_hits[0]
        extra = f" (and {len(telem_hits) - 1} more file(s))" if len(telem_hits) > 1 else ""
        findings.append(Finding("telemetry", f"uses a usage/analytics or tracing library ({sdk0}){extra}: {path0}", path0))

    # Claude plugin marketplace
    mk = _read(root / ".claude-plugin" / "marketplace.json")
    if mk:
        try:
            facts["plugins"] = [pl["name"] for pl in json.loads(mk).get("plugins", []) if isinstance(pl, dict) and pl.get("name")]
        except ValueError:
            pass

    # Skills: flag any that carry code or an agent-directed instruction.
    facts["skills"] = sorted(set(skill_dirs))
    for folder in facts["skills"]:
        for p in (root / folder).rglob("*"):
            if not p.is_file():
                continue
            rel = p.relative_to(root)
            if not SKILL_TEXT.search(p.name):
                findings.append(Finding("skill-contains-code", f"skill '{folder}' ships a non-text file: {rel}", str(rel)))
            elif p.suffix.lower() in (".md", ".markdown", ".txt"):
                m = AGENT_DIRECTED.search(_read(p))
                if m:
                    findings.append(Finding("prompt-injection", f"skill '{folder}' has an agent-directed or exfil line ({m.group(0)}): {rel}", str(rel)))

    # npm / pip packaging
    pj = _read(root / "package.json")
    if pj:
        try:
            p = json.loads(pj)
            scripts = p.get("scripts") or {}
            life = [k for k in ("preinstall", "install", "postinstall") if k in scripts]
            if p.get("bin"):
                facts["npm"] = {"name": p.get("name"), "version": p.get("version"), "lifecycle": life}
            if life:
                findings.append(Finding("install-script", f"runs {', '.join(life)} script(s) on npm install", "package.json"))
        except ValueError:
            pass
    pp = _read(root / "pyproject.toml")
    if pp and re.search(r"^\[project\.scripts\]", pp, re.M):
        name = re.search(r'^name\s*=\s*"([^"]+)"', pp, re.M)
        ver = re.search(r'^version\s*=\s*"([^"]+)"', pp, re.M)
        facts["pip"] = {"name": name.group(1) if name else None, "version": ver.group(1) if ver else None}

    return ScanResult(target=str(root), kind=_detect_kind(root, facts), findings=findings, facts=facts)
