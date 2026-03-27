# Credential Scope Checklist

Complete checklist of credential types, their storage locations, and how to check whether they were present on a compromised system. Use this during Phase 1 (Scope Credentials at Risk) to ensure nothing is missed.

---

## SSH Keys

**Storage locations:**
- `~/.ssh/id_rsa` (RSA private key)
- `~/.ssh/id_ed25519` (Ed25519 private key)
- `~/.ssh/id_ecdsa` (ECDSA private key)
- `~/.ssh/id_dsa` (DSA private key, legacy)
- Custom key paths referenced in `~/.ssh/config`
- Agent-forwarded keys via `SSH_AUTH_SOCK`

**How to list:**
```bash
# List all private keys
ls -la ~/.ssh/id_*

# Check SSH config for key references
grep -i "IdentityFile" ~/.ssh/config 2>/dev/null

# Check if SSH agent has loaded keys
ssh-add -l 2>/dev/null

# Check authorized_keys on remote hosts for attacker-added keys
cat ~/.ssh/authorized_keys
```

**How to check access times:**
```bash
# Check last access time of key files (macOS)
stat -f "%Sa %N" ~/.ssh/id_* 2>/dev/null

# Check last access time of key files (Linux)
stat -c "%x %n" ~/.ssh/id_* 2>/dev/null
```

**Risk notes:** If SSH agent forwarding was enabled, the attacker could have used forwarded keys to access remote hosts without ever touching the key files on disk.

---

## AWS Credentials

**Storage locations:**
- `~/.aws/credentials` (long-lived access keys)
- `~/.aws/config` (may reference SSO sessions, role ARNs)
- `~/.aws/cli/cache/` (cached STS session tokens)
- `~/.aws/sso/cache/` (SSO access tokens)

**Environment variables:**
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_SESSION_TOKEN`
- `AWS_PROFILE`
- `AWS_SHARED_CREDENTIALS_FILE` (custom credentials file path)
- `AWS_CONFIG_FILE` (custom config file path)

**Instance/container metadata:**
- EC2 instance metadata: `http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME`
- ECS task role: `http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`
- Lambda execution role: automatically available via environment
- EKS IRSA: token at path specified by `AWS_WEB_IDENTITY_TOKEN_FILE`

**How to enumerate:**
```bash
# Check credentials file
cat ~/.aws/credentials 2>/dev/null | grep -E '^\[|aws_access_key_id'

# Check for environment variables
env | grep -i ^AWS_

# Check EC2 instance metadata (from within EC2)
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null

# Check ECS task role (from within ECS)
curl -s "http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI" 2>/dev/null

# Check cached SSO tokens
ls -la ~/.aws/sso/cache/ 2>/dev/null

# List all configured profiles
aws configure list-profiles 2>/dev/null
```

**Risk notes:** Temporary credentials from instance metadata and ECS task roles expire (typically 1-6 hours for metadata, up to 36 hours for assumed roles). However, if the attacker was able to call `sts:AssumeRole` or `sts:GetSessionToken`, they may have obtained longer-lived tokens.

---

## GCP Credentials

**Storage locations:**
- `~/.config/gcloud/application_default_credentials.json` (ADC)
- `~/.config/gcloud/credentials.db` (user account tokens)
- `~/.config/gcloud/properties` (active configuration)
- `~/.config/gcloud/access_tokens.db` (cached access tokens)
- Service account key JSON files (anywhere on disk)

**Environment variables:**
- `GOOGLE_APPLICATION_CREDENTIALS` (path to service account key JSON)
- `GOOGLE_CLOUD_PROJECT` or `GCLOUD_PROJECT`
- `CLOUDSDK_CONFIG` (custom gcloud config directory)
- `CLOUDSDK_CORE_PROJECT`

**Metadata server (from within GCP):**
- `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`
- `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email`

**How to enumerate:**
```bash
# Check ADC
cat ~/.config/gcloud/application_default_credentials.json 2>/dev/null | head -5

# Check for environment variables
env | grep -iE '^(GOOGLE_|GCLOUD_|CLOUDSDK_)'

# Find service account key files
find / -name "*.json" -exec grep -l '"type": "service_account"' {} \; 2>/dev/null

# Check active gcloud configuration
gcloud config list 2>/dev/null

# Check metadata server (from within GCP)
curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email 2>/dev/null

# List all gcloud configurations
gcloud config configurations list 2>/dev/null
```

**Risk notes:** Service account key JSON files do not expire and remain valid until explicitly deleted. Access tokens from the metadata server expire after 1 hour but can be continuously refreshed while the attacker has access.

---

## Azure Credentials

**Storage locations:**
- `~/.azure/accessTokens.json` (cached access tokens, deprecated but may still exist)
- `~/.azure/msal_token_cache.json` (MSAL token cache)
- `~/.azure/azureProfile.json` (subscription information)
- `~/.azure/clouds.config` (cloud configuration)
- `~/.azure/service_principal_entries.json` (service principal credentials)

**Environment variables:**
- `AZURE_CLIENT_ID` (service principal app ID)
- `AZURE_CLIENT_SECRET` (service principal secret)
- `AZURE_TENANT_ID` (Azure AD tenant)
- `AZURE_SUBSCRIPTION_ID`
- `AZURE_CLIENT_CERTIFICATE_PATH`
- `AZURE_AUTHORITY_HOST`
- `MSI_ENDPOINT` and `MSI_SECRET` (managed identity on App Service)

**Managed Identity (IMDS):**
- `http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/`

**How to enumerate:**
```bash
# Check token cache
ls -la ~/.azure/ 2>/dev/null
cat ~/.azure/msal_token_cache.json 2>/dev/null | head -10

# Check for environment variables
env | grep -i ^AZURE_
env | grep -i ^MSI_

# Check managed identity (from within Azure VM)
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" 2>/dev/null

# Check active Azure CLI account
az account show 2>/dev/null
az account list 2>/dev/null
```

**Risk notes:** Service principal secrets have configurable expiry (default 2 years). Managed identity tokens expire after 24 hours. Cached MSAL tokens include refresh tokens that may remain valid for extended periods.

---

## Kubernetes Credentials

**Storage locations:**
- `~/.kube/config` (kubeconfig with cluster credentials)
- `$KUBECONFIG` (custom kubeconfig path, may specify multiple files)
- In-cluster service account token: `/var/run/secrets/kubernetes.io/serviceaccount/token`
- In-cluster CA certificate: `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`
- In-cluster namespace: `/var/run/secrets/kubernetes.io/serviceaccount/namespace`

**Environment variables:**
- `KUBECONFIG`
- `KUBERNETES_SERVICE_HOST` and `KUBERNETES_SERVICE_PORT` (in-cluster)

**How to enumerate:**
```bash
# Check kubeconfig
cat ~/.kube/config 2>/dev/null | grep -E '(server:|name:|user:)'

# Check KUBECONFIG env var
echo $KUBECONFIG

# Check for multiple kubeconfig files
ls -la ~/.kube/ 2>/dev/null

# Check in-cluster token (from within a pod)
cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null

# List accessible contexts
kubectl config get-contexts 2>/dev/null

# Check current permissions
kubectl auth can-i --list 2>/dev/null
```

**Risk notes:** In-cluster service account tokens in older Kubernetes versions (before 1.24) are long-lived. Newer versions use bound service account tokens that expire. Kubeconfig files may contain client certificates or bearer tokens that provide cluster-admin access.

---

## GitHub Credentials

**Storage locations:**
- `~/.git-credentials` (plaintext username:token pairs)
- `~/.gitconfig` (may reference credential helpers)
- macOS Keychain (via `git credential-osxkeychain`)
- Linux credential store (via `git credential-store`)
- Windows Credential Manager (via `git credential-manager`)

**Token types:**
- Personal access tokens (classic): `ghp_` prefix
- Fine-grained personal access tokens: `github_pat_` prefix
- OAuth access tokens: `gho_` prefix
- GitHub App installation tokens: `ghs_` prefix
- GitHub App user-to-server tokens: `ghu_` prefix
- `GITHUB_TOKEN` in Actions: `ghs_` prefix, scoped to the workflow run

**Deploy keys:** SSH keys registered with specific repositories (check `gh api "/repos/ORG/REPO/keys"`)

**Environment variables:**
- `GITHUB_TOKEN`
- `GH_TOKEN`
- `GITHUB_PAT`

**How to enumerate:**
```bash
# Check git-credentials file
cat ~/.git-credentials 2>/dev/null

# Check git credential helper
git config --global credential.helper 2>/dev/null

# Check for GitHub tokens in environment
env | grep -iE '^(GITHUB_|GH_)'

# List deploy keys for a repo
gh api "/repos/ORG/REPO/keys" --jq '.[].title' 2>/dev/null

# Check macOS keychain for GitHub entries
security find-internet-password -s github.com 2>/dev/null
```

**Risk notes:** Classic PATs do not expire unless configured to. Fine-grained PATs have mandatory expiration. `GITHUB_TOKEN` in Actions is scoped to the current repository and expires when the workflow completes (but may have been exfiltrated during the run). Deploy keys provide access to a single repository.

---

## Package Registry Tokens

### PyPI

**Storage locations:**
- `~/.pypirc` (upload credentials)
- Environment variables: `TWINE_USERNAME`, `TWINE_PASSWORD`
- API tokens: prefix `pypi-`

```bash
cat ~/.pypirc 2>/dev/null
env | grep -i ^TWINE_
```

### npm

**Storage locations:**
- `~/.npmrc` (global config)
- `.npmrc` in project directories
- Environment variables: `NPM_TOKEN`, `NPM_AUTH_TOKEN`

```bash
cat ~/.npmrc 2>/dev/null | grep -i auth
find . -name ".npmrc" -exec grep -l "authToken\|_auth" {} \; 2>/dev/null
env | grep -i ^NPM_
```

### Docker Hub / Container Registries

**Storage locations:**
- `~/.docker/config.json` (registry auth, may be base64-encoded or use credential helpers)
- Environment variables: `DOCKER_USERNAME`, `DOCKER_PASSWORD`, `DOCKER_AUTH_CONFIG`

```bash
cat ~/.docker/config.json 2>/dev/null | grep -E '(auths|credHelpers)'
env | grep -i ^DOCKER_
```

### RubyGems

**Storage locations:**
- `~/.gem/credentials` (API key)
- Environment variables: `GEM_HOST_API_KEY`

```bash
cat ~/.gem/credentials 2>/dev/null
env | grep -i ^GEM_
```

### NuGet

**Storage locations:**
- `~/.nuget/NuGet/NuGet.Config` (API keys in config)
- Environment variables: `NUGET_API_KEY`

```bash
cat ~/.nuget/NuGet/NuGet.Config 2>/dev/null | grep -i apikey
env | grep -i ^NUGET_
```

**Risk notes:** Package registry tokens typically grant publish access. A compromised PyPI or npm token can be used to publish malicious versions of packages, turning a single compromise into a supply chain attack.

---

## Database Credentials

**Storage locations:**
- `.env` files in project directories
- `~/.pgpass` (PostgreSQL)
- `~/.my.cnf` or `~/.mylogin.cnf` (MySQL)
- `~/.mongorc.js` (MongoDB)
- `~/.sqliterc` (SQLite)
- Application config files (e.g., `config/database.yml`, `settings.py`, `appsettings.json`)

**Environment variables (common patterns):**
- `DATABASE_URL`
- `DB_HOST`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`
- `PGHOST`, `PGUSER`, `PGPASSWORD`, `PGDATABASE`
- `MYSQL_HOST`, `MYSQL_USER`, `MYSQL_PASSWORD`
- `MONGO_URI`, `MONGODB_URI`
- `REDIS_URL`, `REDIS_PASSWORD`

**How to enumerate:**
```bash
# Check PostgreSQL credentials
cat ~/.pgpass 2>/dev/null

# Check MySQL credentials
cat ~/.my.cnf 2>/dev/null | grep -i password

# Check for database connection strings in environment
env | grep -iE '(DATABASE|DB_|PG|MYSQL|MONGO|REDIS)'

# Find .env files with database credentials
find . -name '.env*' -type f -exec grep -liE '(DATABASE_URL|DB_PASSWORD|PGPASSWORD|MYSQL_PASSWORD|MONGO)' {} \; 2>/dev/null
```

**Risk notes:** Database credentials often provide direct access to production data. Unlike cloud API tokens, database access typically does not generate cloud-level audit logs (though database-level audit logging may exist if configured).

---

## .env Files

**Common locations:**
- `.env` in project root directories
- `.env.local`, `.env.production`, `.env.staging`
- `.env.development`
- `docker-compose.env`
- `.env` files in subdirectories

**Sensitive patterns to search for:**
```bash
# Find all .env files
find / -name '.env*' -type f 2>/dev/null

# Extract sensitive variable names (without values)
find . -name '.env*' -type f -exec sh -c '
  echo "=== $1 ===" && grep -iE "(KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|API_KEY|AUTH|PRIVATE)" "$1" | sed "s/=.*/=<REDACTED>/"
' _ {} \; 2>/dev/null
```

**Risk notes:** `.env` files are often a single point of failure -- one file may contain credentials for multiple services (database, cloud provider, payment processor, email service, etc.). They are also frequently committed to version control accidentally.

---

## Browser-Based Credentials (Developer Machines)

**Applicable only when a developer workstation was compromised (not CI/CD runners).**

**Storage locations:**
- Browser cookies: `~/Library/Application Support/Google/Chrome/Default/Cookies` (macOS)
- Browser localStorage: stored per-origin in browser profile directories
- Browser password managers: built into browser profile data
- Session tokens in browser DevTools or extensions

**What to check:**
- Active sessions on cloud consoles (AWS, GCP, Azure, GitHub)
- OAuth tokens stored in browser
- SSO session cookies
- Saved passwords in browser password managers

**How to enumerate:**
```bash
# Check for Chrome profiles (macOS)
ls ~/Library/Application\ Support/Google/Chrome/*/Cookies 2>/dev/null

# Check for Firefox profiles (macOS)
ls ~/Library/Application\ Support/Firefox/Profiles/*/cookies.sqlite 2>/dev/null

# Note: Browser credential extraction requires specialized tools and
# is typically handled by forensic analysis, not command-line enumeration
```

**Risk notes:** Browser cookies can provide authenticated sessions to cloud consoles and internal tools without needing passwords or MFA. Session cookies may remain valid for hours to days depending on the service's session policy.

---

## CI/CD Platform-Specific Credentials

### GitHub Actions

**Secret types:**
- Repository secrets
- Organization secrets
- Environment secrets
- `GITHUB_TOKEN` (automatic, scoped per workflow run)

**How to enumerate:**
```bash
# Repository secrets (names only, values are masked)
gh api "/repos/ORG/REPO/actions/secrets" --jq '.secrets[].name'

# Organization secrets
gh api "/orgs/ORG/actions/secrets" --jq '.secrets[].name'

# Environment secrets
gh api "/repos/ORG/REPO/environments" --jq '.environments[].name' | while read env; do
  echo "=== $env ===" && gh api "/repos/ORG/REPO/environments/$env/secrets" --jq '.secrets[].name'
done

# OIDC tokens (if configured for cloud auth)
# Available at runtime via ACTIONS_ID_TOKEN_REQUEST_URL
```

### GitLab CI

**Secret types:**
- Project CI/CD variables
- Group CI/CD variables
- Instance CI/CD variables
- Protected and masked variables

**How to enumerate (via API):**
```bash
# Project variables (requires Maintainer role)
curl --header "PRIVATE-TOKEN: $GITLAB_TOKEN" "https://gitlab.com/api/v4/projects/PROJECT_ID/variables"

# Group variables
curl --header "PRIVATE-TOKEN: $GITLAB_TOKEN" "https://gitlab.com/api/v4/groups/GROUP_ID/variables"
```

### Jenkins

**Secret types:**
- Credentials (stored in Jenkins credential store)
- Environment variables in job configuration
- Pipeline parameters

**Storage locations:**
- `$JENKINS_HOME/credentials.xml`
- `$JENKINS_HOME/secrets/`
- Job config files in `$JENKINS_HOME/jobs/*/config.xml`

### CircleCI

**Secret types:**
- Project environment variables
- Contexts (shared environment variable groups)

**How to enumerate (via API):**
```bash
# Project environment variables
curl -H "Circle-Token: $CIRCLECI_TOKEN" "https://circleci.com/api/v2/project/gh/ORG/REPO/envvar"

# Contexts
curl -H "Circle-Token: $CIRCLECI_TOKEN" "https://circleci.com/api/v2/context?owner-slug=gh/ORG"
```

**Risk notes:** CI/CD secrets are exposed as environment variables during pipeline execution. A compromised build step or malicious dependency can read all environment variables and exfiltrate them. Some CI/CD platforms mask secrets in logs, but this does not prevent programmatic access to the values.
