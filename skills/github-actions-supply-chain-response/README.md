# github-actions-supply-chain-response

Triage, investigate, and recover from a compromised GitHub Action where tags have been overwritten with malicious code.

Built in response to the [Trivy supply chain attack](https://www.aquasec.com/blog/trivy-action-supply-chain-attack/) (March 19, 2026) and the [Checkmarx KICS attack](https://checkmarx.com/blog/kics-github-action-supply-chain-attack/) (March 23, 2026). These attacks demonstrated the cascading nature of GitHub Actions compromises: stolen Trivy CI credentials were used to compromise KICS, and stolen KICS credentials were used to backdoor LiteLLM on PyPI.

## What it does

Six-phase incident response: exposure check, run window confirmation, IOC hunting, containment, credential rotation, prevention.

Three output modes: interactive triage checklist (default), full incident response runbook (markdown), or automated shell script with `--dry-run` support.

## Install as a Claude skill

Point your Claude skill path at this directory, or download the `.skill` bundle from [Releases](../../releases).

## Use the shell script standalone

No Claude required. Edit the configuration variables at the top for your incident, then run:

```bash
export COMPROMISED_ACTION="aquasecurity/trivy-action"
export ATTACK_WINDOW_START="2026-03-19T17:43:00Z"
export ATTACK_WINDOW_END="2026-03-20T05:40:00Z"
export C2_DOMAINS="scan.aquasecurtiy.org 45.148.10.212"
export SAFE_SHA="57a97c7e7821a5776cebc9bb87c984fa69cba8f1"

./scripts/check_gha_compromise.sh myorg aquasecurity/trivy-action
./scripts/check_gha_compromise.sh myorg aquasecurity/trivy-action --dry-run
```

## Quick manual check

```bash
# Do any workflows reference the action?
grep -rn "ACTION_NAME" .github/workflows/

# Are references tag-based (vulnerable) or SHA-pinned?
grep -rn "uses: ACTION_NAME@v" .github/workflows/

# Search across your org
gh search code "uses: ACTION_NAME" --owner YOUR_ORG

# List runs during the attack window
gh api "/repos/ORG/REPO/actions/runs?created=START..END" \
  --jq '.workflow_runs[] | "\(.id) \(.created_at) \(.conclusion)"'

# Check for exfiltration dead drop repos
gh api "/orgs/ORG/repos" --jq '.[] | select(.name | test("tpcp|docs-tpcp")) | .full_name'
```

## Contents

```
github-actions-supply-chain-response/
├── SKILL.md                            # Claude skill instructions
├── README.md                           # This file
├── references/
│   └── ioc-patterns.md                 # IOC pattern library
└── scripts/
    └── check_gha_compromise.sh         # Standalone bash checker
```

## References

- [Trivy GitHub Action supply chain attack analysis](https://www.aquasec.com/blog/trivy-action-supply-chain-attack/)
- [Checkmarx KICS GitHub Action compromise](https://checkmarx.com/blog/kics-github-action-supply-chain-attack/)
- [StepSecurity blog on Trivy/KICS cascade](https://www.stepsecurity.io/blog/trivy-kics-supply-chain-attack)
- [GitHub advisory: CVE-2026-33634](https://github.com/advisories/GHSA-trivy-action-compromise)
- [Pinning GitHub Actions to SHAs](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions)
