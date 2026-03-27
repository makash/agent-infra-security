---
name: credential-exfiltration-detection
description: Detect whether stolen credentials were actually used after a supply chain attack or security incident. Use this skill when credentials may have been exfiltrated and the user needs to determine if they were abused. Trigger when users ask about checking cloud audit logs after a compromise, detecting unauthorized credential use, finding lateral movement from stolen tokens, auditing API key usage after an incident, or verifying that credential rotation was complete. Works as a follow-up to any incident response skill.
license: MIT
compatibility: Optional depending on cloud provider: aws CLI, gcloud CLI, az CLI, gh CLI, kubectl.
---

# Credential Exfiltration Detection

Determine whether stolen credentials were actually used by attackers after a security incident. This skill walks through a four-phase investigation: scoping what was at risk, checking audit trails, identifying lateral movement, and verifying that rotation was complete.

---

## Phase 1: Scope Credentials at Risk

Enumerate what was accessible on the compromised system, runner, or container. Walk through each credential class below and record every credential that could have been exposed.

### CI/CD Secrets

```bash
# GitHub Actions — repository-level secrets
gh api "/repos/ORG/REPO/actions/secrets" --jq '.secrets[].name'

# GitHub Actions — organization-level secrets
gh api "/orgs/ORG/actions/secrets" --jq '.secrets[].name'

# GitHub Actions — environment-level secrets
gh api "/repos/ORG/REPO/environments" --jq '.environments[].name' | while read env; do
  echo "=== $env ===" && gh api "/repos/ORG/REPO/environments/$env/secrets" --jq '.secrets[].name'
done
```

### Cloud Credentials

**AWS:**
- `~/.aws/credentials` and `~/.aws/config`
- Environment variables: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`
- IAM role credentials on EC2 (instance metadata at `http://169.254.169.254/latest/meta-data/iam/security-credentials/`)
- ECS task role credentials (from `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`)

**GCP:**
- `~/.config/gcloud/application_default_credentials.json`
- Service account key JSON files (search for files containing `"type": "service_account"`)
- Workload identity tokens
- Metadata server at `http://metadata.google.internal/computeMetadata/v1/`

**Azure:**
- `~/.azure/accessTokens.json`
- Service principal secrets in environment variables: `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`
- Managed identity tokens via IMDS at `http://169.254.169.254/metadata/identity/oauth2/token`

### SSH Keys

- `~/.ssh/id_rsa`, `~/.ssh/id_ed25519`, `~/.ssh/id_ecdsa`, and other `~/.ssh/id_*` files
- Check `~/.ssh/config` for hosts that reference these keys

### Git Credentials

- `~/.git-credentials` (plaintext credentials)
- Personal access tokens stored in credential helpers
- Deploy keys registered with repositories
- GitHub App installation tokens
- `GITHUB_TOKEN` in CI environments

### Package Registry Tokens

- PyPI: `~/.pypirc`
- npm: `~/.npmrc` (look for `_authToken`)
- Docker Hub: `~/.docker/config.json`
- GitHub Packages: tokens in `.npmrc` or environment variables

### Kubernetes

- `~/.kube/config` (may contain multiple cluster credentials)
- In-cluster service account token at `/var/run/secrets/kubernetes.io/serviceaccount/token`
- Service account certificates

### Database Credentials

- Connection strings in `.env` files, config files, or environment variables
- `~/.pgpass` (PostgreSQL)
- `~/.my.cnf` (MySQL)

### .env Files

Search for all keys containing sensitive patterns:

```bash
# Find .env files and extract sensitive variable names
find . -name '.env*' -type f 2>/dev/null | while read f; do
  echo "=== $f ===" && grep -iE '(KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|API_KEY|AUTH)=' "$f" | sed 's/=.*/=<REDACTED>/'
done
```

---

## Phase 2: Check Cloud Audit Trails

Run the queries below for each provider relevant to the incident. Replace placeholder values (access key IDs, service account emails, timestamps) with actual values from Phase 1.

### AWS CloudTrail

```bash
# Check API calls from a specific access key after suspected compromise time
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIA... \
  --start-time "2026-03-19T00:00:00Z" \
  --max-results 50 \
  --query 'Events[].{Time:EventTime,Name:EventName,Source:EventSource,IP:sourceIPAddress}'

# Check for new IAM users created
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateUser \
  --start-time "2026-03-19T00:00:00Z"

# Check for new access keys created
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey \
  --start-time "2026-03-19T00:00:00Z"

# Check for unusual source IPs
aws cloudtrail lookup-events \
  --start-time "2026-03-19T00:00:00Z" \
  --query 'Events[?sourceIPAddress!=`amazonaws.com`].{Time:EventTime,Name:EventName,IP:sourceIPAddress}' \
  --max-results 100
```

### GCP Audit Logs

```bash
# Check recent admin activity for a service account
gcloud logging read 'protoPayload.authenticationInfo.principalEmail="SA@PROJECT.iam.gserviceaccount.com"' \
  --limit 50 --format json

# Check for new service account key creation
gcloud logging read 'protoPayload.methodName="google.iam.admin.v1.CreateServiceAccountKey"' \
  --limit 20

# Check for unusual API calls
gcloud logging read 'protoPayload.authenticationInfo.principalEmail="SA@PROJECT.iam.gserviceaccount.com" AND severity>=WARNING' \
  --limit 50
```

### Azure Activity Log

```bash
# Check recent activity for a service principal
az monitor activity-log list \
  --start-time "2026-03-19T00:00:00Z" \
  --caller "SERVICE_PRINCIPAL_ID" \
  --query "[].{Time:eventTimestamp,Operation:operationName.value,Status:status.value}"

# Check for role assignments
az monitor activity-log list \
  --start-time "2026-03-19T00:00:00Z" \
  --resource-provider "Microsoft.Authorization" \
  --query "[?contains(operationName.value, 'roleAssignments')]"
```

### GitHub Audit Log

```bash
# Check org audit log for a specific actor
gh api "/orgs/ORG/audit-log" --method GET -F phrase="actor:USERNAME" -F per_page=50

# Check for new PATs or deploy keys created
gh api "/orgs/ORG/audit-log" --method GET -F phrase="action:personal_access_token" -F per_page=50
gh api "/orgs/ORG/audit-log" --method GET -F phrase="action:deploy_key" -F per_page=50

# Check for new repo creation (exfiltration dead drops)
gh api "/orgs/ORG/audit-log" --method GET -F phrase="action:repo.create" -F per_page=50
```

### Kubernetes

```bash
# Check audit logs for service account usage
kubectl logs -n kube-system -l component=kube-apiserver --since=72h | grep "SERVICE_ACCOUNT"

# Check for new cluster role bindings
kubectl get clusterrolebindings --sort-by=.metadata.creationTimestamp | tail -20

# Check for new secrets created
kubectl get secrets --all-namespaces --sort-by=.metadata.creationTimestamp | tail -20
```

---

## Phase 3: Check for Lateral Movement

After reviewing audit logs, determine whether stolen credentials were used to move beyond the initially compromised system. Investigate each of these questions:

- Were stolen credentials used to access other systems?
- Were new users, tokens, or access keys created?
- Were privileges escalated?
- Were new resources provisioned (VMs, containers, storage buckets)?
- Were other repositories or packages modified?
- Were deployment pipelines triggered?

### Patterns to Look For

**Unusual source IPs or regions:** Compare the IPs in audit log entries against known infrastructure IPs. Attacker usage typically originates from VPN exit nodes, cloud VMs, or Tor nodes rather than your corporate IP ranges.

**Activity outside normal business hours:** Credential use at 3 AM in your timezone when the compromised service normally runs 9-5 is suspicious.

**New IAM entities created:** New users, service accounts, roles, or access keys that were not created through your normal provisioning process.

**Permission escalation:** New role bindings, policy attachments, or group memberships that grant broader access than the compromised credential originally had.

**Data access to unusual resources:** API calls to S3 buckets, databases, or services that the compromised credential does not normally access.

**New SSH keys added:** Check `~/.ssh/authorized_keys` on remote hosts for keys that were added during the compromise window.

**Modified repositories or packages:** Check git logs and package registry histories for pushes or publishes that occurred during the compromise window.

**Triggered deployments:** Check CI/CD pipeline histories for runs that were triggered using the compromised credentials.

---

## Phase 4: Verify Rotation Completeness

After credentials have been rotated (handled by incident-specific skills), confirm that the rotation was thorough and effective.

### Confirm Old Credentials Are Invalidated

```bash
# AWS — check for old access keys still active
aws iam list-access-keys --user-name USER \
  --query 'AccessKeyMetadata[?CreateDate<`2026-03-19`]'

# GCP — check for old service account keys
gcloud iam service-accounts keys list \
  --iam-account SA@PROJECT.iam.gserviceaccount.com --format json

# GitHub — check for old PATs (user must check via Settings > Developer settings)
```

### Verify No Stale Keys Remain

- Confirm that old credentials return authentication errors when used (test in a safe, isolated way).
- Check that new credentials are the only ones active for each identity.
- Ensure temporary/session tokens from the old credentials have expired (AWS STS session tokens can last up to 36 hours).

### Re-run Phase 1 Scope Check

Run the credential enumeration from Phase 1 again on the remediated system to confirm:
- No credentials from before the compromise window remain on disk.
- Environment variables have been updated.
- CI/CD secret values have been changed (not just new secrets added alongside old ones).
- Credential helpers and cached tokens have been cleared.

---

## Important Notes

- **This skill does NOT include credential rotation steps.** Rotation is handled by incident-specific skills such as `pypi-supply-chain-response`, `github-actions-supply-chain-response`, and `supply-chain-security-check`.
- **"No findings" does not mean credentials were not stolen.** Audit logs have retention limits and sophisticated attackers may have cleaned traces.
- **Check audit log retention periods** for each provider before concluding "no evidence of abuse":
  - AWS CloudTrail: 90 days (free tier lookup), longer with S3/CloudWatch
  - GCP Audit Logs: 400 days (Admin Activity), 30 days (Data Access)
  - Azure Activity Log: 90 days
  - GitHub Audit Log: 180 days (Enterprise), 7 days (non-Enterprise via API)
- **Some credential abuse does not appear in audit logs.** For example, reading files over SSH does not generate API audit entries, and cloning a public repo with a stolen PAT may not log distinctly.
