# Skill Catalog

Index of all skills in this repo. Each skill works as a Claude skill and ships standalone tools.

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

*New skills get added here as they're built. Format: name, path, trigger phrases, what it does, standalone tools, date.*
