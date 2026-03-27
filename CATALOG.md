# Skill Catalog

Index of all skills in this repo. Each skill works as an agent skill and ships standalone tools.

---

## pypi-supply-chain-response

**Path:** `skills/pypi-supply-chain-response/`

**Trigger phrases:** compromised Python package, PyPI supply chain attack, malicious dependency, credential-stealing malware in pip, "am I affected by" a package compromise, rotate credentials after Python incident, transitive dependency audit, IOC hunting for pip install

**What it does:** Walks through a six-phase incident response for any compromised PyPI package: exposure check (including transitive dependencies), version confirmation, IOC hunting, containment, credential rotation, and prevention. Produces an interactive triage checklist, a full runbook, or an automated shell script depending on what the user needs.

**Standalone tools:**
- `scripts/check_compromise_template.sh` — Automated checker with color-coded output, `--dry-run`, and confirmation prompts
- `references/ioc-patterns.md` — IOC pattern library covering .pth attacks, persistence mechanisms, credential harvesting targets, exfiltration patterns, and Kubernetes lateral movement

**Created:** March 2026, in response to the LiteLLM/TeamPCP supply chain attack.

---

## supply-chain-security-check

**Path:** `skills/supply-chain-security-check/`

**Trigger phrases:** compromised dependency, supply chain incident, "do we use this package", blast radius scan, dependency compromise investigation, transitive dependency audit, "am I affected" by a package compromise, compromised npm package, compromised crate, compromised gem

**What it does:** Multi-ecosystem blast radius scan for any compromised dependency — PyPI, npm, crates.io, RubyGems, Maven, NuGet, Go modules, Docker Hub. Seven-step workflow: confirm incident facts, search source and lockfiles across ecosystems, check installed environments for transitive use, hunt for IOCs (generic .pth detection, persistence mechanisms, K8s lateral movement), classify impact across five severity levels, recommend containment with per-class credential rotation, and prevent future incidents (SBOM, pip-audit, hashed lockfiles, Trusted Publishing). Produces a structured incident report.

**Standalone tools:**
- Investigation commands in SKILL.md work without any agent — copy the relevant sections for your ecosystem

**Created:** March 2026

---

## github-actions-supply-chain-response

**Path:** `skills/github-actions-supply-chain-response/`

**Trigger phrases:** compromised GitHub Action, poisoned action tags, Trivy action compromise, Checkmarx KICS compromise, CI secrets exfiltrated, GitHub Actions backdoored, workflow secrets leaked, "are our GitHub Actions safe", tag overwriting attack, TeamPCP

**What it does:** Six-phase incident response for compromised GitHub Actions (tag overwriting attacks): exposure check across org workflows, run window confirmation, IOC hunting in workflow logs, containment (pin to safe SHAs, cancel runs), credential rotation for all CI secrets, and prevention (SHA pinning, allow-lists, Harden-Runner). Built around the Trivy (76/77 tags, Mar 19 2026) and Checkmarx KICS (35 tags, Mar 23 2026) incidents. Three output modes: interactive checklist, runbook, or automated shell script.

**Standalone tools:**
- `scripts/check_gha_compromise.sh` — Automated checker using gh CLI with `--dry-run` and color-coded output
- `references/ioc-patterns.md` — IOC library covering both Trivy and KICS attacks: C2 domains, file hashes, malicious commit SHAs, persistence paths, Docker image digests

**Created:** March 2026, in response to the TeamPCP cascading campaign (Trivy → KICS → LiteLLM).

---

## credential-exfiltration-detection

**Path:** `skills/credential-exfiltration-detection/`

**Trigger phrases:** were my credentials stolen, check if credentials were used, cloud audit log after compromise, detect unauthorized credential use, lateral movement from stolen tokens, API key abuse detection, verify credential rotation, post-incident credential audit, CloudTrail check after breach

**What it does:** Post-incident detection skill: determines whether stolen credentials were actually used by attackers. Four-phase workflow: scope credentials at risk, check cloud audit trails (AWS CloudTrail, GCP Audit Logs, Azure Activity Log, GitHub audit log, Kubernetes), detect lateral movement, and verify rotation completeness. Works as a follow-up to any incident response skill.

**Standalone tools:**
- `references/cloud-audit-queries.md` — Ready-to-run queries for AWS, GCP, Azure, GitHub, and Kubernetes with expected output examples and false positive guidance
- `references/credential-scope-checklist.md` — Complete checklist of credential types and storage locations across all platforms

**Created:** March 2026

---

*New skills get added here as they're built. Format: name, path, trigger phrases, what it does, standalone tools, date.*
