# Credential Rotation Playbook: Axios Supply Chain Compromise

A step-by-step incident response guide for teams affected by the Axios npm supply chain attack (March 31, 2026) — or any future npm compromise that results in credential exposure.

## What happened

The npm maintainer account for axios (`jasonsaayman`) was compromised. The attacker published two malicious versions — `axios@1.14.1` and `axios@0.30.4` — that injected `plain-crypto-js@4.2.1`, a dependency that ran a postinstall RAT dropper targeting macOS, Windows, and Linux. Within two seconds of `npm install`, the malware was beaconing to `sfrclak[.]com:8000`.

Google's Threat Intelligence Group attributed the attack to **UNC1069**, a financially motivated North Korean threat actor. Their pattern is: compromise, harvest credentials, monetize — fast.

**Affected versions:** `axios@1.14.1`, `axios@0.30.4`, `plain-crypto-js@4.2.0`, `plain-crypto-js@4.2.1`
**Safe versions:** `axios@1.14.0`, `axios@0.30.3`

Sources: [StepSecurity](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan), [Elastic Security Labs](https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all), [Google Threat Intelligence](https://thehackernews.com/2026/03/axios-supply-chain-attack-pushes-cross.html)

---

## Why "rotate your credentials" is not enough

Every advisory ends with "rotate your credentials." That skips three critical questions:

1. **Which credentials?** A developer workstation typically has SSH keys, cloud credentials (AWS/GCP/Azure), npm tokens, GitHub PATs, database passwords, .env secrets, and Kubernetes configs — all accessible to a RAT with the user's permissions.

2. **Were they already used?** With a financially motivated actor, operate on the assumption that stolen credentials have already been tested. Rotation without abuse detection is incomplete.

3. **Did the rotation actually work?** Some providers have invalidation delays. AWS STS sessions survive access key deletion for up to 36 hours.

---

## Step 1: Scope what was accessible

If you use Claude Code with [agent-infra-security](https://github.com/makash/agent-infra-security) installed, you can skip the manual steps below. Just say: *"axios got compromised, versions 1.14.1 and 0.30.4 are backdoored. Am I affected?"* — the `npm-supply-chain-response` skill will run exposure checks, version confirmation, and IOC hunting automatically.

Before rotating anything, inventory what was on the compromised machine. If the file exists or the environment variable is set, the credential was accessible to the RAT.

**Package registry tokens** (rotate these first — an attacker with your npm publish token can push malicious versions of YOUR packages):
```bash
cat ~/.npmrc 2>/dev/null | grep "_authToken"
npm token list
cat ~/.pypirc 2>/dev/null | grep -i "password\|token"
cat ~/.docker/config.json 2>/dev/null | jq '.auths | keys'
```

**Cloud credentials:**
```bash
# AWS
cat ~/.aws/credentials 2>/dev/null | grep -E '^\[|aws_access_key_id'
env | grep -i ^AWS_

# GCP
ls ~/.config/gcloud/application_default_credentials.json 2>/dev/null

# Azure
env | grep -i ^AZURE_
```

On EC2/ECS/Lambda, role credentials are available from the instance metadata service automatically. On GKE, workload identity tokens. These are also exposed.

**SSH keys:**
```bash
ls -la ~/.ssh/id_*
ssh-add -l 2>/dev/null
```

**GitHub tokens and git credentials:**
```bash
gh auth status
cat ~/.git-credentials 2>/dev/null
```

**CI/CD secrets** (GitHub Actions):
```bash
gh api "/repos/ORG/REPO/actions/secrets" --jq '.secrets[].name'
```

**Everything else** (.env files, database credentials, Kubernetes configs):
```bash
find . ~ -name '.env*' -type f 2>/dev/null | while read f; do
  echo "=== $f ===" && grep -iE '(KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|API_KEY|AUTH)=' "$f" | sed 's/=.*/=<REDACTED>/'
done
```

---

## Step 2: Check if credentials were already used

This is the step most teams skip. Before rotating, query your cloud audit logs to determine if the attacker already used your credentials.

### AWS CloudTrail

```bash
# API calls from a specific access key after the compromise
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIA... \
  --start-time "2026-03-31T00:00:00Z" \
  --max-results 50 \
  --query 'Events[].{Time:EventTime,Name:EventName,Source:EventSource,IP:sourceIPAddress}'
```

**Red flags to look for:**
- `CreateAccessKey` or `CreateUser` — attacker creating persistence
- `AssumeRole` — lateral movement to other accounts
- `RunInstances` — EC2 for cryptomining or C2
- `GetObject` on S3 — data exfiltration
- Any activity from unfamiliar source IPs or outside business hours

### GCP Audit Logs

```bash
gcloud logging read \
  'protoPayload.authenticationInfo.principalEmail="SA@PROJECT.iam.gserviceaccount.com"' \
  --limit 50 --format json
```

### GitHub Audit Log

```bash
gh api "/orgs/ORG/audit-log" --method GET -F phrase="actor:USERNAME" -F per_page=50
```

Look for new PATs, deploy keys, or repo creation (exfiltration dead drops).

### What "no findings" means

It does not mean credentials were not stolen. It means:
- The attacker may not have used them yet
- Some credential use does not generate audit logs (reading files over SSH, cloning a public repo)
- Audit log retention may not cover the window (GitHub non-Enterprise: 7 days via API)

Proceed with rotation regardless.

---

## Step 3: Rotate in priority order

If you use Claude Code with agent-infra-security, say: *"we confirmed we ran the bad version. rotate everything."* — the `credential-exfiltration-response` skill walks through all 13 credential classes with detect → rotate → verify for each.

Priority order matters. Rotate the credentials most likely to cause cascading damage first.

### Priority 1: Package registry tokens

An attacker with your npm publish token can turn your compromise into a supply chain attack against your users.

```bash
npm token list
npm token revoke $TOKEN_ID
npm token create --read-only  # or --publish
```

Verify: `NPM_TOKEN=$OLD_TOKEN npm whoami 2>&1` should return 401.

### Priority 2: Cloud credentials

**AWS — the STS session trap:**

Deleting an AWS access key does not kill active STS sessions. The attacker can keep operating for up to 36 hours.

```bash
# Create new key, disable old key
aws iam create-access-key --user-name $USER
aws iam update-access-key --access-key-id $OLD_KEY --status Inactive --user-name $USER
```

**Then deploy a deny policy to kill existing sessions:**

```bash
aws iam put-user-policy --user-name $USER --policy-name RevokeOldSessions \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "DateLessThan": {
          "aws:TokenIssueTime": "2026-03-31T00:00:00Z"
        }
      }
    }]
  }'
```

Remove this policy after 36 hours, then delete the old key.

**GCP** — key deletion is immediate:
```bash
gcloud iam service-accounts keys delete $KEY_ID --iam-account=$SA_EMAIL
gcloud iam service-accounts keys create new-key.json --iam-account=$SA_EMAIL
gcloud auth revoke --all
```

**Azure:**
```bash
az ad sp credential reset --id $SERVICE_PRINCIPAL_ID
az account clear
```

### Priority 3: SSH keys

```bash
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_new -C "rotated-$(date +%Y%m%d)"
```

Update `authorized_keys` on all remote hosts. Check for attacker-added keys.

### Priority 4: GitHub tokens

```bash
gh api -X DELETE /repos/OWNER/REPO/keys/$KEY_ID
git credential reject <<CRED
protocol=https
host=github.com
CRED
```

Generate new PATs at github.com/settings/tokens.

### Priority 5: CI/CD secrets

```bash
gh secret set SECRET_NAME --body "new-value" --repo ORG/REPO
```

CI secrets have no "revoke" — you overwrite with the new value.

### Priority 6: Database passwords, Kubernetes, .env secrets

Change passwords directly in the database system. For Kubernetes, delete and recreate the service account. For .env secrets, regenerate at each provider's dashboard.

---

## Step 4: Verify rotation

Rotation is not done until you confirm old credentials are actually dead.

**Test old credentials fail:**
```bash
# AWS
AWS_ACCESS_KEY_ID=$OLD_KEY AWS_SECRET_ACCESS_KEY=$OLD_SECRET aws sts get-caller-identity 2>&1

# npm
NPM_TOKEN=$OLD_TOKEN npm whoami 2>&1

# GitHub
curl -H "Authorization: token $OLD_TOKEN" https://api.github.com/user 2>&1
```

**Account for provider-specific invalidation delays:**

| Provider | Delay After Rotation | Action Required |
|----------|---------------------|-----------------|
| AWS STS | Up to **36 hours** | Deploy deny policy with `aws:TokenIssueTime`. Do not remove for 36h. |
| GCP | **Immediate** | Key deletion is instant. |
| npm | **Immediate** | Token revocation is instant. |
| GitHub PATs | **Immediate** | App tokens may persist up to 1 hour. |
| Azure | **Immediate** | Cached tokens may persist briefly. |

---

## Step 5: Prevent the next one

For a full audit of your project's dependency security, say: *"audit this project's dependency security before we ship."* — the `supply-chain-best-practices` skill produces a PASS/WARN/FAIL checklist across nine categories.

**Pin exact versions:**
```bash
npm install axios@1.14.0 --save-exact
```
The Axios attack landed because `^1.14.0` resolved to `1.14.1`.

**Use `npm ci` in CI, not `npm install`.** `npm ci` respects the lockfile exactly.

**Disable postinstall scripts:**
```ini
# .npmrc
ignore-scripts=true
```
Then selectively rebuild trusted native deps: `npm rebuild sharp esbuild`.

**Scope CI secrets to step-level, not workflow-level:**

```yaml
# BAD — npm ci runs with your cloud creds in the environment
env:
  AWS_ACCESS_KEY_ID: ${{ secrets.AWS_KEY }}
steps:
  - run: npm ci

# GOOD — only the deploy step has cloud creds
steps:
  - run: npm ci
  - run: npm run deploy
    env:
      AWS_ACCESS_KEY_ID: ${{ secrets.AWS_KEY }}
```

**Use OIDC instead of long-lived credentials in CI.** Short-lived tokens expire even if exfiltrated.

**Delay adoption of new versions by 48-72 hours.** The Axios malicious versions were live for 2-3 hours. A 48-hour delay policy would have protected you entirely.

**Verify package provenance:**
```bash
npm audit signatures
```
The legitimate `axios@1.14.0` had SLSA provenance via GitHub Actions OIDC. The malicious `1.14.1` was published directly via CLI — no provenance attestation.

**Generate SBOMs:**
```bash
npx @cyclonedx/cyclonedx-npm --output-file sbom.json
```
When the next advisory drops, grep the SBOM instead of auditing every environment.

---

## Open-source tooling

I maintain open-source tooling for automating parts of this workflow — detecting compromised package versions, hunting for IoCs, and walking through credential rotation per provider.

**github.com/makash/agent-infra-security**

It includes:
- `npm-supply-chain-response` — six-phase incident response with automated detection script
- `credential-exfiltration-response` — cloud audit log queries and provider-specific rotation for 13 credential types
- `supply-chain-best-practices` — preventive audit checklist (version pinning, lockfiles, provenance, CI secret scoping)

Works as a standalone guide or as skills for Claude Code.

---

*Written by Akash Mahajan. This playbook is extracted from the [agent-infra-security](https://github.com/makash/agent-infra-security) project.*
