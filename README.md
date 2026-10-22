# plugin-vet

Static safety checks for the plugins, skills and MCP servers you install into a coding agent.

An agent add-on runs with your agent's reach: your shell, your files, your tokens. Most are
fine. Some register a hook on every tool call, phone home with telemetry, pull their newest
version at every start, carry a committed secret, or tell the agent reading them to go fetch
and run something. `plugin-vet` reads an add-on's files and tells you which of those it found,
before you install it. It never builds, installs or runs the thing it checks, so looking is
always safe.

```
$ plugin-vet https://github.com/someone/handy-mcp
plugin-vet 0.1.0
target: https://github.com/someone/handy-mcp
kind:   mcp-server

3 finding(s):
  [HIGH] committed-secret: contains an AWS access key id: src/config.ts
  [MED ] unpinned-fetch: starts an MCP server at its newest version, unpinned: handy: npx handy-mcp@latest
  [MED ] telemetry: looks like it reports usage (posthog): src/analytics.ts

worst severity: high
```

## Why

Installing a community plugin or MCP server is running someone else's code with your
permissions. The npm and PyPI supply chain is a known target, and the agent ecosystem adds new
ways to be surprised: a `PreToolUse` hook sees everything you do, a `postinstall` script runs
on `npm install`, an `npx ...@latest` server fetches fresh code every launch, and a `SKILL.md`
can carry instructions aimed at the agent that reads it. None of that is visible from a star
count. `plugin-vet` makes it visible in one command.

## What it checks

| Finding | Default severity | What it means |
|---|---|---|
| `committed-secret` | high | a real-looking key, token or private key is in the repo |
| `prompt-injection` | high | a skill carries agent-directed text ("ignore previous instructions", paths to `.ssh`, exfil hints) |
| `pipe-to-shell` | high | the install instructions pipe a download straight into a shell |
| `program-file` | high | a compiled binary or archive a reviewer cannot read is committed |
| `every-call-hook` | medium | registers a `PreToolUse` / `PostToolUse` / `UserPromptSubmit` hook (sees every tool call) |
| `background-service` | medium | installs a service, cron job or launch agent that keeps running |
| `telemetry` | medium | ships a usage/analytics SDK (PostHog, Sentry, Segment, Umami, ...) |
| `unpinned-fetch` | medium | starts an MCP server via `npx`/`uvx`/`bunx` at an unpinned version |
| `skill-contains-code` | medium | a "skill" folder ships executable files, not just text |
| `install-script` | low | runs `preinstall` / `install` / `postinstall` scripts on `npm install` |

A finding is a thing to look at, not a verdict. Clear output and a clean report both mean
"now read the code", not "trusted".

## Install

```sh
pipx install plugin-vet       # recommended
# or
pip install plugin-vet
```

Pure Python standard library, no dependencies. Python 3.9+.

## Use

```sh
plugin-vet ./my-plugin                 # a local folder
plugin-vet https://github.com/o/repo   # a git URL (cloned shallow to a temp dir, then removed)
plugin-vet ./x --json                  # machine-readable output
plugin-vet ./x --fail-on medium        # exit 1 on a medium-or-worse finding (for CI)
plugin-vet ./x --policy team.json      # your own severities
```

Exit code: `0` clean (below the `--fail-on` threshold, default `high`), `1` a finding at or
above it, `2` the target could not be read or cloned.

### Your own policy

Raise, lower or silence any check with a JSON file:

```json
{ "severity": { "telemetry": "high", "install-script": "info" } }
```

```sh
plugin-vet ./x --policy team.json --fail-on medium
```

### In CI

```yaml
- run: pipx install plugin-vet
- run: plugin-vet . --fail-on high
```

## What it does not do

- It does not run, build or install the target. It reads files. That is the point: checking is
  safe even for a hostile add-on.
- It is not a sandbox and not a guarantee. A determined author can hide intent from a static
  read. A clean report means nothing tripped, not that the code is safe. Read it.
- It does not judge quality or usefulness, only these specific risk signals.

## How it works

It walks the files once, skipping `.git`, `node_modules` and build output, and matches each
against the rules above. It recognises a Claude plugin (`.claude-plugin/`), a skill
(`SKILL.md`), an MCP server (`mcpServers` config), and an npm or Python command, and reports
the kind alongside the findings. The whole scanner is a few hundred lines of standard-library
Python in [`plugin_vet/scan.py`](plugin_vet/scan.py).

## Contributing

Issues and pull requests welcome. New rules should look for one concrete, checkable thing and
come with a tiny fixture under `tests/fixtures/`. Run the suite with `pytest`.

## License

MIT. See [LICENSE](LICENSE).
