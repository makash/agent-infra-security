# credential-exfiltration-response

Detect whether stolen credentials were used, then rotate every compromised credential class with verification.

## What This Skill Does

Full credential lifecycle response after a security incident — from scoping what was exposed through rotation and verification:

1. **Scope credentials at risk** — enumerate every credential accessible on the compromised system.
2. **Check cloud audit trails** — query CloudTrail, GCP Audit Logs, Azure Activity Log, GitHub Audit Log, and Kubernetes audit logs for unauthorized use.
3. **Check for lateral movement** — identify whether attackers accessed additional systems, escalated privileges, or provisioned new resources.
4. **Scope rotation requirements** — prioritize credentials by confirmed abuse, likely exposed, and possibly exposed.
5. **Credential rotation** — per-credential-class detect/rotate/verify for SSH, AWS (with STS session invalidation), GCP, Azure, GitHub, npm, PyPI, Docker, Kubernetes, databases, .env secrets, CI/CD secrets, and crypto wallets.
6. **Verify rotation completeness** — confirm old credentials are truly invalidated, accounting for provider-specific delays (e.g., AWS STS sessions survive key deletion for up to 36 hours).

## When to Use

- After any supply chain incident (malicious package, compromised CI/CD pipeline, etc.)
- When credentials may have been exposed in a breach or leak
- As a follow-up to `npm-supply-chain-response`, `pypi-supply-chain-response`, `github-actions-supply-chain-response`, or `supply-chain-security-check`
- When another skill says "use the credential-exfiltration-response skill"
- During periodic security audits to verify credential hygiene

## Quick Commands by Provider

**AWS:**
```bash
aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIA... --start-time "YYYY-MM-DDTHH:MM:SSZ" --max-results 50
```

**GCP:**
```bash
gcloud logging read 'protoPayload.authenticationInfo.principalEmail="SA@PROJECT.iam.gserviceaccount.com"' --limit 50 --format json
```

**Azure:**
```bash
az monitor activity-log list --start-time "YYYY-MM-DDTHH:MM:SSZ" --caller "SERVICE_PRINCIPAL_ID"
```

**GitHub:**
```bash
gh api "/orgs/ORG/audit-log" --method GET -F phrase="actor:USERNAME" -F per_page=50
```

**Kubernetes:**
```bash
kubectl get clusterrolebindings --sort-by=.metadata.creationTimestamp | tail -20
```

## Contents

```
credential-exfiltration-response/
  SKILL.md                                    # Main skill workflow (six phases)
  README.md                                   # This file
  references/
    cloud-audit-queries.md                    # Expanded audit queries with examples
    credential-scope-checklist.md             # Complete credential type checklist
```

## Prerequisites

Install only the CLIs relevant to your environment:

- `aws` — AWS CLI for CloudTrail queries
- `gcloud` — Google Cloud CLI for audit log queries
- `az` — Azure CLI for activity log queries
- `gh` — GitHub CLI for audit log and API queries
- `kubectl` — Kubernetes CLI for cluster audit queries

## License

MIT
