# Skill Catalog

Index of all skills in this repo. Each skill works as an agent skill and ships standalone tools.

## Architecture

Skills are organized in layers:

1. **Ecosystem-specific skills** (npm, pypi, github-actions) — trigger first for their ecosystem, deep IOC libraries, tailored forensics
2. **Generic fallback** (supply-chain-security-check) — covers Go, Rust, Ruby, Java, .NET, Docker, multi-ecosystem incidents
3. **Credential lifecycle** (credential-exfiltration-response) — all ecosystem skills hand off here for rotation
4. **Proactive hardening** (supply-chain-best-practices) — preventive audits, not incident response

---

## npm-supply-chain-response

**Path:** `skills/npm-supply-chain-response/`

**Trigger phrases:** compromised npm package, npm supply chain attack, malicious dependency in node_modules, credential-stealing malware from npm install, postinstall backdoor, typosquatted npm package, IOC hunting after npm install, axios compromised, "package got pwned"

**What it does:** Six-phase incident response for any compromised npm package: exposure check (lockfiles, node_modules, npm cache), version confirmation, IOC hunting (anti-forensics detection, platform-specific persistence, network IOCs), containment, credential rotation (handoff to credential-exfiltration-response), prevention (--ignore-scripts, npm audit signatures, Corepack, lockfile-lint, npm provenance). Three output modes: interactive checklist, runbook, or automated shell script.

**Standalone tools:**
- `scripts/check_npm_compromise.sh` — Automated checker with `--dry-run` and color-coded output
- `references/ioc-patterns.md` — Axios-specific and generic npm IOC patterns

**Created:** March 2026, in response to the Axios supply chain attack.

---

## pypi-supply-chain-response

**Path:** `skills/pypi-supply-chain-response/`

**Trigger phrases:** compromised Python package, PyPI supply chain attack, malicious dependency, credential-stealing malware in pip, "am I affected by" a package compromise, transitive dependency audit, IOC hunting for pip install

**What it does:** Six-phase incident response for any compromised PyPI package: exposure check (including transitive dependencies via pipdeptree -r), version confirmation, IOC hunting (.pth files, persistence, credential harvesting), containment, credential rotation (handoff to credential-exfiltration-response), prevention.

**Standalone tools:**
- `scripts/check_compromise_template.sh` — Automated checker with color-coded output and `--dry-run`
- `references/ioc-patterns.md` — IOC pattern library covering .pth attacks, persistence, credential harvesting
- `references/manual-investigation-playbook.md` — Cross-platform manual playbook (Windows PowerShell, macOS, Linux)

**Created:** March 2026, in response to the LiteLLM/TeamPCP supply chain attack.

---

## github-actions-supply-chain-response

**Path:** `skills/github-actions-supply-chain-response/`

**Trigger phrases:** compromised GitHub Action, poisoned action tags, Trivy action compromise, KICS compromise, CI secrets exfiltrated, GitHub Actions backdoored, tag overwriting attack, TeamPCP

**What it does:** Six-phase incident response for compromised GitHub Actions (tag overwriting attacks): exposure check across org, run window confirmation, IOC hunting in workflow logs, containment (pin to safe SHAs, cancel runs), credential rotation (handoff to credential-exfiltration-response), prevention.

**Standalone tools:**
- `scripts/check_gha_compromise.sh` — Automated checker using gh CLI
- `references/ioc-patterns.md` — IOC library covering Trivy and KICS attacks

**Created:** March 2026, in response to the TeamPCP cascading campaign.

---

## credential-exfiltration-response

**Path:** `skills/credential-exfiltration-response/`

**Trigger phrases:** were my credentials stolen, rotate credentials after compromise, check if credentials were used, cloud audit log after breach, detect unauthorized credential use, lateral movement detection, verify credential rotation, "use the credential-exfiltration-response skill"

**What it does:** Full credential lifecycle after a security incident. Six-phase workflow: scope credentials at risk, check cloud audit trails (AWS CloudTrail, GCP Audit Logs, Azure Activity Log, GitHub, Kubernetes), detect lateral movement, scope rotation requirements (prioritization framework), rotate per credential class (13 types: SSH, AWS with STS session invalidation, GCP, Azure, GitHub, npm, PyPI, Docker, Kubernetes, databases, .env secrets, CI/CD, crypto wallets), verify rotation completeness (provider-specific delay table).

**Standalone tools:**
- `references/cloud-audit-queries.md` — Ready-to-run queries for each cloud provider
- `references/credential-scope-checklist.md` — Complete credential type checklist

**Created:** March 2026

---

## supply-chain-security-check

**Path:** `skills/supply-chain-security-check/`

**Trigger phrases:** compromised Go/Rust/Ruby/Java/.NET package, supply chain incident (non-npm non-Python non-GitHub-Actions), "do we use this package", blast radius scan, multi-ecosystem dependency compromise

**What it does:** Generic fallback for ecosystems without a dedicated skill. Multi-ecosystem command tables for dependency checking, transitive discovery, and version pinning across Go, Rust, Ruby, Java, .NET, Docker. Seven-phase workflow. Routes to ecosystem-specific skills when available.

**Created:** March 2026

---

## supply-chain-best-practices

**Path:** `skills/supply-chain-best-practices/`

**Trigger phrases:** secure my dependencies, harden CI/CD pipeline, audit lockfiles, dependency pinning audit, SBOM generation, dependency signing, provenance verification, prevent supply chain attack, dependency hygiene

**What it does:** Proactive dependency hardening (not incident response). Nine-category audit: version pinning, lockfile integrity, install hooks, vulnerability scanning, provenance/signing, CI secret scoping, SBOM generation, update strategy, package manager hardening. Multi-ecosystem. Produces PASS/WARN/FAIL checklist report.

**Created:** March 2026

---

*New skills get added here as they're built. Format: name, path, trigger phrases, what it does, standalone tools, date.*
