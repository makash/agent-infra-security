# credential-exfiltration-detection

Detect whether stolen credentials were actually used by attackers after a supply chain attack or security incident.

## What This Skill Does

This skill guides you through a four-phase investigation to determine if exfiltrated credentials were abused:

1. **Scope credentials at risk** -- enumerate every credential that was accessible on the compromised system.
2. **Check cloud audit trails** -- query CloudTrail, GCP Audit Logs, Azure Activity Log, GitHub Audit Log, and Kubernetes audit logs for evidence of unauthorized use.
3. **Check for lateral movement** -- identify whether attackers used stolen credentials to access additional systems, escalate privileges, or provision new resources.
4. **Verify rotation completeness** -- confirm that all compromised credentials were rotated and old ones are truly invalidated.

## When to Use

- After any supply chain incident (malicious package, compromised CI/CD pipeline, etc.)
- When credentials may have been exposed in a breach or leak
- As a follow-up to incident response skills like `pypi-supply-chain-response`, `github-actions-supply-chain-response`, or `supply-chain-security-check`
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
credential-exfiltration-detection/
  SKILL.md                                    # Main skill workflow (four phases)
  README.md                                   # This file
  references/
    cloud-audit-queries.md                    # Expanded audit queries with examples
    credential-scope-checklist.md             # Complete credential type checklist
```

## Prerequisites

Install only the CLIs relevant to your environment:

- `aws` -- AWS CLI for CloudTrail queries
- `gcloud` -- Google Cloud CLI for audit log queries
- `az` -- Azure CLI for activity log queries
- `gh` -- GitHub CLI for audit log and API queries
- `kubectl` -- Kubernetes CLI for cluster audit queries

## License

MIT
