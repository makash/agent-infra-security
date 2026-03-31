# agent-infra-security

Security skills for AI coding agents. Detect compromised packages, triage supply chain attacks, rotate credentials, and hunt for IOCs — using Claude Code, Codex, Cursor, or standalone scripts.

![demo](assets/demo.gif)

## The problem

**You installed a package. It got backdoored. Now what?**

If you're building with LLMs, your dependency tree is deep and largely unaudited. Packages like LiteLLM route API keys for dozens of providers and get pulled in transitively by frameworks like CrewAI, DSPy, and Browser-Use. When one gets compromised, most teams don't have a playbook.

Here's what actually goes wrong:

**You're exposed and don't know it.** You never ran `pip install litellm`. But `dspy` depends on it, so it's in your environment. `pipdeptree -r` would have shown you — but you've never run it.

**The malware runs before your code does.** Modern PyPI attacks drop `.pth` files in `site-packages/`. Python executes these at interpreter startup — not at import time. npm attacks use `postinstall` scripts that run during `npm install`. Both fire with the installing user's full permissions.

**Your credentials are already gone.** The payload swept `~/.aws/credentials`, `~/.ssh/id_rsa`, `~/.kube/config`, every `.env` file, and your git tokens. It POST'd them to a lookalike domain. Rotating "the API key" isn't enough — everything on that machine is burned.

**There's no playbook at 2am.** The advisory drops, Slack lights up, and your team is grepping StackOverflow. These skills encode the triage process a security engineer would walk you through.

## What's in this repo

### Skill: [npm-supply-chain-response](skills/npm-supply-chain-response/)

Deep triage for a compromised npm package. Built around the Axios supply chain attack (March 31, 2026) — account compromise, typosquatted dependency injection (`plain-crypto-js`), multi-platform backdoors, anti-forensics.

Six-phase incident response: exposure check (lockfiles, node_modules, npm cache), version confirmation, IOC hunting, containment, credential rotation (via handoff), prevention.

**Standalone tools included:**
- [`check_npm_compromise.sh`](skills/npm-supply-chain-response/scripts/check_npm_compromise.sh) — automated checker with `--dry-run` support
- [`ioc-patterns.md`](skills/npm-supply-chain-response/references/ioc-patterns.md) — Axios-specific and generic npm IOC patterns

### Skill: [pypi-supply-chain-response](skills/pypi-supply-chain-response/)

Deep triage for a compromised Python package. Six-phase incident response: exposure check (including transitive dependencies via `pipdeptree -r`), version confirmation, IOC hunting, containment, credential rotation (via handoff), prevention.

**Standalone tools included:**
- [`check_compromise_template.sh`](skills/pypi-supply-chain-response/scripts/check_compromise_template.sh) — color-coded automated checker
- [`ioc-patterns.md`](skills/pypi-supply-chain-response/references/ioc-patterns.md) — IOC pattern library covering .pth attacks, persistence, credential harvesting
- [`manual-investigation-playbook.md`](skills/pypi-supply-chain-response/references/manual-investigation-playbook.md) — cross-platform manual playbook (Windows PowerShell, macOS, Linux)

### Skill: [github-actions-supply-chain-response](skills/github-actions-supply-chain-response/)

Incident response for compromised GitHub Actions — tag overwriting attacks where the action's code is replaced with a credential stealer. Built around the TeamPCP cascading campaign: **Trivy** -> **KICS** -> **LiteLLM**.

**Standalone tools included:**
- [`check_gha_compromise.sh`](skills/github-actions-supply-chain-response/scripts/check_gha_compromise.sh) — scans your GitHub org for affected action references
- [`ioc-patterns.md`](skills/github-actions-supply-chain-response/references/ioc-patterns.md) — C2 domains, malicious commit SHAs, persistence paths

### Skill: [credential-exfiltration-response](skills/credential-exfiltration-response/)

Full credential lifecycle after a security incident — detection through rotation and verification. Six-phase workflow: scope credentials at risk, check cloud audit trails (AWS CloudTrail, GCP Audit Logs, Azure Activity Log, GitHub, Kubernetes), detect lateral movement, scope rotation requirements, rotate per credential class (13 credential types with detect/rotate/verify), verify completeness.

All ecosystem skills hand off to this skill for credential rotation.

**Standalone tools included:**
- [`cloud-audit-queries.md`](skills/credential-exfiltration-response/references/cloud-audit-queries.md) — ready-to-run queries for each cloud provider
- [`credential-scope-checklist.md`](skills/credential-exfiltration-response/references/credential-scope-checklist.md) — complete credential type checklist

### Skill: [supply-chain-security-check](skills/supply-chain-security-check/)

Generic fallback for ecosystems without a dedicated skill (Go, Rust, Ruby, Java, .NET, Docker). Multi-ecosystem command tables for dependency checking, transitive discovery, and version pinning. Routes to ecosystem-specific skills when available.

### Skill: [supply-chain-best-practices](skills/supply-chain-best-practices/)

Proactive dependency hardening. Nine-category audit: version pinning, lockfile integrity, install hooks, vulnerability scanning, provenance/signing, CI secret scoping, SBOM generation, update strategy, package manager hardening. Produces PASS/WARN/FAIL checklist report.

## Install and use

### Claude Code

```bash
# Install via plugin marketplace
/plugin marketplace add makash/agent-infra-security
/plugin install agent-infra-security@agent-infra-security

# Or install a specific skill directly
claude skill add ./skills/pypi-supply-chain-response
```

Then just talk to it:

```
You: axios got compromised — versions 1.14.1 and 0.30.4. Am I affected?

You: litellm got backdoored — versions 1.82.7 and 1.82.8. Am I affected?

You: the trivy github action got compromised. scan our org for any workflows that used it.

You: after the incident, check if any of our stolen credentials were actually used.

You: audit this project's dependency security — show me what needs hardening.
```

### Codex

```bash
# Point Codex at the skill
codex --skill ./skills/supply-chain-security-check
```

### No agent — just the commands

If a package just got reported as compromised and you need to check right now:

```bash
# npm
npm ls <PACKAGE> 2>/dev/null
grep "<PACKAGE>" package-lock.json yarn.lock pnpm-lock.yaml 2>/dev/null

# Python
pip show <PACKAGE> | grep -E "^(Name|Version|Location)"
pipdeptree -r -p <PACKAGE>

# Any ecosystem — find it anywhere on this machine
find / -path "*/<PACKAGE>*" -type d 2>/dev/null | head -20
```

**Platform coverage:**

| Platform | Quick checks above | Full manual playbook | Automated shell script |
|----------|-------------------|---------------------|----------------------|
| Linux | Yes | Yes (bash) | Yes |
| macOS | Yes | Yes (bash) | Yes |
| Windows | No | Yes (PowerShell) | No |

## Repo structure

```
agent-infra-security/
├── skills/
│   ├── npm-supply-chain-response/                # npm/Node.js deep triage
│   ├── pypi-supply-chain-response/               # PyPI/Python deep triage
│   ├── github-actions-supply-chain-response/     # GitHub Actions tag tampering response
│   ├── credential-exfiltration-response/         # Credential detection + rotation lifecycle
│   ├── supply-chain-security-check/              # Generic multi-ecosystem fallback
│   └── supply-chain-best-practices/              # Proactive dependency hardening
├── .claude-plugin/                                # Plugin manifests
└── LICENSE                                        # MIT
```

## Contributing

New skills are curated by the maintainer. If you have a playbook idea, [open an issue](../../issues) to discuss.

## License

MIT
