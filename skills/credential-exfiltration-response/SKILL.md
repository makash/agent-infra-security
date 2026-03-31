---
name: credential-exfiltration-response
description: Detect whether stolen credentials were used and rotate them after a supply chain attack or security incident. Use this skill when credentials may have been exfiltrated and the user needs to determine if they were abused, rotate compromised credentials, or verify rotation completeness. Trigger when users ask about checking cloud audit logs after a compromise, detecting unauthorized credential use, finding lateral movement from stolen tokens, rotating credentials after an incident, auditing API key usage, or verifying that credential rotation was complete. Also trigger when an ecosystem-specific skill (pypi-supply-chain-response, npm-supply-chain-response, github-actions-supply-chain-response) hands off credential rotation to this skill. Works as a follow-up to any incident response skill or standalone for credential-focused incidents.
license: MIT
compatibility: Optional depending on cloud provider: aws CLI, gcloud CLI, az CLI, gh CLI, kubectl, npm.
---

# Credential Exfiltration Response

Detect whether stolen credentials were used by attackers, rotate compromised credentials, and verify rotation completeness. This skill handles the full credential lifecycle across six phases.

## Dual Entry Point

This skill supports two entry points:

1. **Start from scratch** (Phases 1-6) — The user doesn't know what's compromised yet. Start with Phase 1 to scope credentials at risk, then proceed through detection, lateral movement, rotation, and verification.

2. **Skip to rotation** (Phases 5-6) — The user already completed an ecosystem-specific skill's investigation (pypi, npm, github-actions) and knows which credentials were exposed. Skip directly to Phase 5 for rotation.

**At the start, ask the user:** "Do you already know which credentials were exposed (e.g., from completing an incident response investigation), or do you need to scope and detect first?"

If they know what's exposed, ask them to list the credential types and skip to Phase 5.

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

## Phase 4: Scope Rotation Requirements

Based on findings from Phases 1-3, determine which credentials need immediate rotation. Prioritize by:

1. **Confirmed abuse** — credentials with audit log evidence of attacker use → rotate immediately
2. **Likely exposed** — credentials present on compromised system with no audit trail evidence → rotate (absence of evidence is not evidence of absence)
3. **Possibly exposed** — credentials that might have been accessible → rotate if practical, monitor if not

Create a rotation checklist before proceeding to Phase 5. For each credential, record:
- Credential type (SSH key, AWS access key, npm token, etc.)
- Identity (which user/service account)
- Evidence of abuse (from Phases 2-3)
- Rotation priority (immediate / soon / monitor)

---

## Phase 5: Credential Rotation

Walk through each credential class below. For each class that applies, follow the three-step pattern: detect → rotate → verify.

### SSH Keys

**Detect:**
```bash
ls -la ~/.ssh/id_*
cat ~/.ssh/config | grep -i identityfile
```

**Rotate:**
```bash
# Generate new key pair
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_new -C "rotated-$(date +%Y%m%d)"

# Update authorized_keys on all remote hosts
# Then rename: mv ~/.ssh/id_ed25519_new ~/.ssh/id_ed25519
```

**Verify:**
```bash
# Test old key fails
ssh -i ~/.ssh/id_ed25519_old user@host 2>&1 | grep -i "denied\|refused"
```

### AWS

**Detect:**
```bash
aws iam list-access-keys --user-name $(aws iam get-user --query User.UserName --output text)
```

**Rotate:**
```bash
# Create new key
aws iam create-access-key --user-name $USER

# Disable old key (don't delete yet — verify first)
aws iam update-access-key --access-key-id $OLD_KEY --status Inactive --user-name $USER
```

**CRITICAL — Kill existing STS sessions (they survive key deletion for up to 36 hours):**
```bash
# Attach inline deny-all policy with date condition
aws iam put-user-policy --user-name $USER --policy-name RevokeOldSessions \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "DateLessThan": {
          "aws:TokenIssueTime": "COMPROMISE_TIMESTAMP"
        }
      }
    }]
  }'
# Remove this policy after 36 hours
```

**Verify:**
```bash
# Test old key fails
AWS_ACCESS_KEY_ID=$OLD_KEY AWS_SECRET_ACCESS_KEY=$OLD_SECRET aws sts get-caller-identity 2>&1 | grep -i "invalid\|expired"

# Then delete old key
aws iam delete-access-key --access-key-id $OLD_KEY --user-name $USER
```

### GCP

**Detect:**
```bash
gcloud iam service-accounts keys list --iam-account=$SA_EMAIL
```

**Rotate:**
```bash
# Delete old key (GCP deletion is immediate — no delayed invalidation)
gcloud iam service-accounts keys delete $KEY_ID --iam-account=$SA_EMAIL

# Create new key
gcloud iam service-accounts keys create new-key.json --iam-account=$SA_EMAIL

# Revoke application default credentials
gcloud auth revoke --all
gcloud auth application-default revoke
```

**Verify:**
```bash
# Test old key fails (if you saved a copy)
gcloud auth activate-service-account --key-file=old-key.json 2>&1 | grep -i "invalid\|error"
```

**Post-incident:** Migrate to Workload Identity Federation to eliminate static keys entirely.

### Azure

**Detect:**
```bash
az ad sp credential list --id $SERVICE_PRINCIPAL_ID
```

**Rotate:**
```bash
az account clear
# Rotate via Azure portal — regenerate service principal secrets
az ad sp credential reset --id $SERVICE_PRINCIPAL_ID
```

**Verify:**
```bash
# Test old credentials fail
az login --service-principal -u $CLIENT_ID -p $OLD_SECRET --tenant $TENANT_ID 2>&1 | grep -i "invalid\|unauthorized"
```

### GitHub Tokens

**Detect:**
```bash
# List deploy keys
gh api /repos/OWNER/REPO/keys --jq '.[].id'

# Check for PATs (must also check via Settings > Developer settings in browser)
gh auth status
```

**Rotate:**
```bash
# Revoke deploy keys
gh api -X DELETE /repos/OWNER/REPO/keys/$KEY_ID

# Revoke cached git credentials
git credential reject <<CRED
protocol=https
host=github.com
CRED

# Generate new PAT via github.com/settings/tokens
```

**Verify:**
```bash
# Test old token fails
curl -H "Authorization: token $OLD_TOKEN" https://api.github.com/user 2>&1 | grep -i "401\|Bad credentials"
```

Note: `GITHUB_TOKEN` (Actions) is scoped per workflow run and expires when the job ends — no rotation needed. GitHub App installation tokens expire in 1 hour.

### npm Registry Tokens

**Detect:**
```bash
cat ~/.npmrc 2>/dev/null | grep "_authToken"
npm token list
```

**Rotate:**
```bash
# Revoke old token (immediate effect)
npm token revoke $TOKEN_ID

# Create new token
npm token create --read-only  # or --publish for publish access
```

**Verify:**
```bash
# Test old token fails
NPM_TOKEN=$OLD_TOKEN npm whoami 2>&1 | grep -i "401\|ENEEDAUTH"
```

### PyPI Tokens

**Detect:**
```bash
cat ~/.pypirc 2>/dev/null | grep -i "password\|token"
```

**Rotate:**
Revoke and regenerate at pypi.org/manage/account/token/. Migrate to Trusted Publishing (OIDC) to eliminate static tokens.

### Docker Registry Credentials

**Detect:**
```bash
cat ~/.docker/config.json 2>/dev/null | jq '.auths | keys'
```

**Rotate:**
```bash
docker logout
# Re-authenticate with new credentials
docker login
```

### Kubernetes

**Detect:**
```bash
kubectl config get-contexts
kubectl config view --minify --flatten
```

**Rotate:**
```bash
kubectl config delete-context $CONTEXT
# Re-authenticate via your provider (EKS, GKE, AKS)
```

Rotate in-cluster service account tokens by deleting and recreating the service account.

### Database Passwords

**Detect:**
```bash
# Find connection strings
find . -name ".env*" -type f -exec grep -iE '(DATABASE_URL|DB_PASSWORD|PGPASSWORD|MYSQL_PWD)' {} \;
cat ~/.pgpass 2>/dev/null
cat ~/.my.cnf 2>/dev/null | grep password
```

**Rotate:** Change passwords directly in the database system. Update all application configuration and `.env` files with the new password.

### .env File Secrets

**Detect:**
```bash
find . -name '.env*' -type f 2>/dev/null | while read f; do
  echo "=== $f ===" && grep -iE '(KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|API_KEY|AUTH)=' "$f" | sed 's/=.*/=<REDACTED>/'
done
```

**Rotate:** For each key found, go to the respective provider's dashboard and regenerate. Update the `.env` file with the new value. Never reuse the old secret.

### CI/CD Secrets

**Detect:**
```bash
# GitHub Actions
gh api "/repos/ORG/REPO/actions/secrets" --jq '.secrets[].name'
gh api "/orgs/ORG/actions/secrets" --jq '.secrets[].name'
```

**Rotate:** Update each secret value via `gh secret set` or the provider's UI. The old value is immediately replaced — there is no "revoke" step for CI secrets, only overwrite.

```bash
gh secret set SECRET_NAME --body "new-value" --repo ORG/REPO
```

### Crypto Wallets

If wallet private keys or seed phrases were accessible on the compromised system, transfer all funds to a new wallet immediately. Old wallet should be considered permanently compromised.

---

## Phase 6: Verify Rotation Completeness

After rotating credentials in Phase 5, confirm that the rotation was thorough and effective.

### Confirm Old Credentials Are Invalidated

```bash
# AWS — check for old access keys still active
aws iam list-access-keys --user-name USER \
  --query 'AccessKeyMetadata[?CreateDate<`COMPROMISE_DATE`]'

# GCP — check for old service account keys
gcloud iam service-accounts keys list \
  --iam-account SA@PROJECT.iam.gserviceaccount.com --format json

# GitHub — check for old PATs (user must check via Settings > Developer settings)

# npm — verify old tokens are gone
npm token list
```

### Provider-Specific Invalidation Delays

| Provider | Delay After Rotation | Mitigation |
|----------|---------------------|------------|
| AWS STS | Up to 36 hours | Deploy deny policy with `aws:TokenIssueTime` condition (see Phase 5) |
| GCP | None — immediate | Key deletion takes effect instantly |
| GitHub | PATs immediate; App tokens up to 1 hour | Wait for expiry window |
| npm | None — immediate | Token revocation takes effect instantly |
| Azure | Service principal secrets immediate | Cached tokens may persist briefly |

### Verify No Stale Keys Remain

- Confirm that old credentials return authentication errors when used (test in a safe, isolated way).
- Check that new credentials are the only ones active for each identity.
- For AWS: verify the deny policy is in place for STS session invalidation. Remove it after 36 hours.

### Re-run Phase 1 Scope Check

Run the credential enumeration from Phase 1 again on the remediated system to confirm:
- No credentials from before the compromise window remain on disk.
- Environment variables have been updated.
- CI/CD secret values have been changed (not just new secrets added alongside old ones).
- Credential helpers and cached tokens have been cleared.

---

## Important Notes

- **This skill handles the full credential lifecycle:** detection, lateral movement analysis, rotation, and verification.
- **"No findings" does not mean credentials were not stolen.** Audit logs have retention limits and sophisticated attackers may have cleaned traces.
- **Check audit log retention periods** for each provider before concluding "no evidence of abuse":
  - AWS CloudTrail: 90 days (free tier lookup), longer with S3/CloudWatch
  - GCP Audit Logs: 400 days (Admin Activity), 30 days (Data Access)
  - Azure Activity Log: 90 days
  - GitHub Audit Log: 180 days (Enterprise), 7 days (non-Enterprise via API)
- **Some credential abuse does not appear in audit logs.** For example, reading files over SSH does not generate API audit entries, and cloning a public repo with a stolen PAT may not log distinctly.
- **AWS STS sessions survive key deletion.** This is the most commonly missed step. Always deploy the deny policy with `aws:TokenIssueTime` condition. Without it, an attacker with an existing session token can continue operating for up to 36 hours after you delete the access key.
