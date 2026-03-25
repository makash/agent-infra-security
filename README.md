# agent-infra-security

Security skills for AI coding agents. Detect compromised packages, triage supply chain attacks, rotate credentials, and hunt for IOCs — using Claude Code, Codex, Cursor, or standalone scripts.

## The problem

**You installed a package. It got backdoored. Now what?**

If you're building with LLMs, your dependency tree is deep and largely unaudited. Packages like LiteLLM route API keys for dozens of providers and get pulled in transitively by frameworks like CrewAI, DSPy, and Browser-Use. When one gets compromised, most teams don't have a playbook.

Here's what actually goes wrong:

**You're exposed and don't know it.** You never ran `pip install litellm`. But `dspy` depends on it, so it's in your environment. `pipdeptree -r` would have shown you — but you've never run it.

**The malware runs before your code does.** Modern PyPI attacks drop `.pth` files in `site-packages/`. Python executes these at interpreter startup — not at import time. Running `pip`, launching your IDE, or even `python -c "print('hello')"` triggers the payload.

**Your credentials are already gone.** The payload swept `~/.aws/credentials`, `~/.ssh/id_rsa`, `~/.kube/config`, every `.env` file, and your git tokens. It POST'd them to a lookalike domain. Rotating "the API key" isn't enough — everything on that machine is burned.

**There's no playbook at 2am.** The advisory drops, Slack lights up, and your team is grepping StackOverflow. These skills encode the triage process a security engineer would walk you through.

## What's in this repo

### Skill: [pypi-supply-chain-response](skills/pypi-supply-chain-response/)

Deep triage for a compromised Python package. Six-phase incident response: exposure check (including transitive dependencies), version confirmation, IOC hunting, containment, credential rotation, and prevention.

Three output modes — interactive triage checklist (walks you through step by step), full incident response runbook (shareable markdown), or automated shell script with `--dry-run`.

**Standalone tools included:**
- [`check_compromise_template.sh`](skills/pypi-supply-chain-response/scripts/check_compromise_template.sh) — color-coded automated checker with confirmation prompts before any destructive action
- [`ioc-patterns.md`](skills/pypi-supply-chain-response/references/ioc-patterns.md) — IOC pattern library covering .pth attacks, persistence mechanisms, credential harvesting targets, exfiltration patterns, and Kubernetes lateral movement
- [`manual-investigation-playbook.md`](skills/pypi-supply-chain-response/references/manual-investigation-playbook.md) — cross-platform manual investigation playbook with full **Windows (PowerShell)**, macOS, and Linux coverage

### Skill: [supply-chain-security-check](skills/supply-chain-security-check/)

Multi-ecosystem blast radius scan. Works for PyPI, npm, crates.io, RubyGems, Maven, NuGet, Go modules, and Docker Hub. Seven-step workflow: confirm incident facts, search source and lockfiles across ecosystems, check installed environments for transitive use, hunt for IOCs, classify impact (five severity levels), recommend containment with per-class credential rotation, and prevent future incidents.

**Use both together:** `supply-chain-security-check` for the initial "are we affected anywhere?" scan across your whole stack, then `pypi-supply-chain-response` for deep Python-specific investigation.

## Install and use

### Claude Code

```bash
# Install via plugin marketplace
/plugin marketplace add makash/agent-infra-security
/plugin install supply-chain-skills@agent-infra-security

# Or install a specific skill directly
claude skill add ./skills/pypi-supply-chain-response
```

Then just talk to it:

```
You: litellm got backdoored — versions 1.82.7 and 1.82.8. Am I affected?

You: we use dspy in production and I'm worried about transitive deps. check everything.

You: generate a full incident response runbook for the litellm compromise and save it as a markdown file

You: give me a check_compromise.sh script with --dry-run that I can share with my team
```

### Codex

```bash
# Point Codex at the skill
codex --skill ./skills/supply-chain-security-check
```

Sample prompt:

```
Check if this project uses litellm anywhere — directly or as a transitive
dependency. Versions 1.82.7 and 1.82.8 are compromised. Check all Python
environments, Docker images, and CI logs. If found, classify the impact,
list what credentials need rotation, and give me exact commands to contain it.
```

### No agent — just the commands

If a package just got reported as compromised and you need to check right now:

```bash
# Is it installed? What version?
pip show <PACKAGE> | grep -E "^(Name|Version|Location)"

# What pulled it in? (the step most people miss)
pip install pipdeptree && pipdeptree -r -p <PACKAGE>

# Other environments on this machine?
find / -path "*/site-packages/<PACKAGE>" -type d 2>/dev/null

# Malicious .pth startup hooks?
SITE=$(python -c "import site; print(site.getsitepackages()[0])")
find "$SITE" -name "*.pth" -exec grep -l "base64\|subprocess\|exec\|eval\|compile" {} \;

# Cached wheels that could reinstall the bad version?
pip cache list <PACKAGE>
```

For the full manual playbook covering **Windows, macOS, and Linux**, see [`manual-investigation-playbook.md`](skills/pypi-supply-chain-response/references/manual-investigation-playbook.md).

## Repo structure

```
agent-infra-security/
├── skills/
│   ├── pypi-supply-chain-response/          # PyPI-specific deep triage
│   │   ├── SKILL.md                         # Agent skill instructions
│   │   ├── README.md
│   │   ├── references/
│   │   │   ├── ioc-patterns.md              # IOC pattern library
│   │   │   └── manual-investigation-playbook.md  # Windows/macOS/Linux playbook
│   │   └── scripts/
│   │       └── check_compromise_template.sh # Standalone automated checker
│   └── supply-chain-security-check/         # Multi-ecosystem blast radius scan
│       ├── SKILL.md                         # Agent skill instructions
│       └── README.md
├── CATALOG.md                               # Skill index with trigger phrases
└── LICENSE                                  # MIT
```

## Contributing

New skills are curated by the maintainer. If you have a playbook idea, [open an issue](../../issues) to discuss.

## License

MIT
