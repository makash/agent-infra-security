# agent-infra-security

Security skills for AI coding agents. When your dependencies get compromised, these skills are the incident response playbook your agent follows.

![demo](assets/demo.gif)

## Three supply chain attacks in ten days

**March 19, 2026 — Trivy.** Attackers compromise 76 of 77 tags on `aquasecurity/trivy-action`. Every GitHub Actions workflow using a tag reference runs attacker-controlled code. CI secrets — cloud credentials, deploy keys, package registry tokens — are exfiltrated via dead-drop repos.

**March 23, 2026 — KICS.** Using credentials stolen from the Trivy attack, attackers pivot to Checkmarx KICS, overwriting 35 tags on `checkmarx/kics-github-action`. The cascade continues.

**March 24, 2026 — LiteLLM.** Credentials stolen from the KICS compromise are used to publish backdoored versions of LiteLLM on PyPI (1.82.7, 1.82.8). The malware drops a `.pth` file in `site-packages/` — Python executes it on every interpreter startup, before your code even imports. SSH keys, AWS credentials, `.env` files, everything is swept and exfiltrated. Most affected developers never directly installed LiteLLM — it was pulled in transitively by CrewAI, DSPy, and Browser-Use.

**March 31, 2026 — Axios.** The npm maintainer account `jasonsaayman` is compromised. Malicious versions `axios@1.14.1` and `axios@0.30.4` are published, injecting a typosquatted dependency `plain-crypto-js` that deploys platform-specific backdoors: a disguised binary on macOS (`/Library/Caches/com.apple.act.mond`), a renamed PowerShell on Windows (`wt.exe`), a Python script on Linux (`/tmp/ld.py`). The payload self-deletes its installer and swaps `package.json` to cover its tracks. Axios has 80 million weekly downloads.

**One compromised account cascaded across three ecosystems in ten days.** GitHub Actions → PyPI → npm. Each attack used credentials stolen from the previous one.

## Why agents need security skills

AI coding agents run `pip install`, `npm install`, and GitHub Actions workflows on your behalf. They pull dependencies, build containers, and deploy code. When a supply chain attack hits, the agent that installed the compromised package is also the fastest path to triage:

- It already knows your dependency tree
- It can search lockfiles, caches, and environments faster than you can type commands
- It can walk through a structured incident response instead of you grepping StackOverflow at 2am

But agents don't know incident response by default. These skills teach them.

## What's in this repo

Six skills organized in layers:

### Ecosystem-specific incident response

**[npm-supply-chain-response](skills/npm-supply-chain-response/)** — Deep triage for compromised npm packages. Built around the Axios attack: typosquatted dependency injection, multi-platform backdoors, anti-forensics (self-deleting `setup.js`, `package.md` swap). Six-phase workflow with three output modes (interactive checklist, runbook, automated script).

**[pypi-supply-chain-response](skills/pypi-supply-chain-response/)** — Deep triage for compromised PyPI packages. Built around the LiteLLM attack: `.pth` startup hooks, transitive dependency exposure via `pipdeptree -r`, credential harvesting. Cross-platform manual playbook (Windows PowerShell, macOS, Linux).

**[github-actions-supply-chain-response](skills/github-actions-supply-chain-response/)** — Incident response for tag overwriting attacks. Built around the Trivy → KICS cascade: org-wide workflow scanning, run window confirmation, IOC hunting in CI logs, dead-drop repo detection.

### Credential lifecycle

**[credential-exfiltration-response](skills/credential-exfiltration-response/)** — Full detection-to-rotation lifecycle. All ecosystem skills hand off here. Covers 13 credential classes (SSH, AWS with STS session invalidation, GCP, Azure, GitHub, npm, PyPI, Docker, Kubernetes, databases, `.env` secrets, CI/CD secrets, crypto wallets). Includes audit trail queries for every major cloud provider.

### Generic fallback

**[supply-chain-security-check](skills/supply-chain-security-check/)** — Multi-ecosystem fallback for Go, Rust, Ruby, Java, .NET, Docker, and incidents that span multiple ecosystems. Routes to ecosystem-specific skills when available.

### Proactive hardening

**[supply-chain-best-practices](skills/supply-chain-best-practices/)** — Nine-category dependency audit: version pinning, lockfile integrity, install hooks, vulnerability scanning, provenance verification, CI secret scoping, SBOM generation, update strategy, package manager hardening. Produces a PASS/WARN/FAIL checklist. Use this before an incident, not during one.

## Install and use

### Claude Code — from your terminal

```bash
claude "/plugin marketplace add makash/agent-infra-security"
claude "/plugin install agent-infra-security@agent-infra-security"
```

### Claude Code — from inside the REPL

```
/plugin marketplace add makash/agent-infra-security
/plugin install agent-infra-security@agent-infra-security
```

Then just talk:

```
You: axios got compromised — 1.14.1 and 0.30.4 are backdoored. Am I affected?

You: litellm got backdoored. I use dspy in production — check transitive deps.

You: the trivy github action was compromised. scan our org for affected workflows.

You: we confirmed we ran the bad version. rotate everything.

You: audit this project's dependency security before we ship.
```

### Codex

```bash
codex --skill ./skills/supply-chain-security-check
```

### No agent — standalone scripts

Every ecosystem skill ships a shell script that works without any AI agent:

```bash
# npm — check for Axios compromise
./skills/npm-supply-chain-response/scripts/check_npm_compromise.sh axios --dry-run

# PyPI — check for any compromised package
./skills/pypi-supply-chain-response/scripts/check_compromise_template.sh

# GitHub Actions — scan org for compromised action references
./skills/github-actions-supply-chain-response/scripts/check_gha_compromise.sh
```

### No agent — just the commands

```bash
# npm: is the bad version installed?
grep "axios" package-lock.json yarn.lock pnpm-lock.yaml 2>/dev/null
ls node_modules/plain-crypto-js 2>/dev/null  # malicious dependency = confirmed compromise

# Python: what pulled in litellm?
pip show litellm | grep Version
pipdeptree -r -p litellm  # shows dspy, crewai, browser-use as parents

# GitHub Actions: who's using mutable tags?
grep -rn 'uses:.*@v' .github/workflows/
```

## Repo structure

```
agent-infra-security/
├── skills/
│   ├── npm-supply-chain-response/                # Axios, and any future npm compromise
│   ├── pypi-supply-chain-response/               # LiteLLM, and any future PyPI compromise
│   ├── github-actions-supply-chain-response/     # Trivy/KICS, and any future GHA compromise
│   ├── credential-exfiltration-response/         # Detection + rotation for 13 credential classes
│   ├── supply-chain-security-check/              # Generic fallback (Go, Rust, Ruby, Java, .NET)
│   └── supply-chain-best-practices/              # Proactive hardening audit
├── .claude-plugin/                                # Plugin manifests for marketplace
├── CATALOG.md                                     # Skill index with trigger phrases
└── LICENSE                                        # MIT
```

## Contributing

New skills are curated by the maintainer. If you have a playbook idea or an incident that needs coverage, [open an issue](../../issues).

## License

MIT
