# IOC Pattern Library for GitHub Actions Supply Chain Attacks

This reference contains indicators of compromise from known GitHub Actions tag-overwriting attacks. Use these when triaging a suspected compromise or when attack-specific IOCs are not yet available from an advisory.

## Trivy (aquasecurity/trivy-action) — March 19, 2026

**CVE:** CVE-2026-33634 (CVSS 9.4)

**Attack window:** ~12 hours (March 19, 17:43 UTC - March 20, ~05:40 UTC)

**Second wave:** March 22, malicious Docker Hub images v0.69.5 and v0.69.6 (~10 hours)

**Tags compromised:** 76 of 77 tags on trivy-action overwritten. All 7 tags on setup-trivy overwritten.

**Safe versions:**
- trivy-action: 0.35.0 only (commit `57a97c7e7821a5776cebc9bb87c984fa69cba8f1`)
- setup-trivy: v0.2.6 only (commit `3fb12ec`)

**C2 infrastructure:**
- Primary C2: `scan[.]aquasecurtiy[.]org` (typosquat — note the misspelling "securtiy" instead of "security")
- C2 IP: `45.148.10.212`
- Blockchain C2: `tdtqy-oyaaa-aaaae-af2dq-cai[.]raw[.]icp0[.]io`

**File hashes:**
- Malicious entrypoint.sh SHA256: `18a24f83e807479438dcab7a1804c51a00dafc1d526698a66e0640d1e5dd671a`
- Clean entrypoint.sh SHA256: `07500e81693c06ef7ac6bf210cff9c882bcc11db5f16b5bded161218353ba4da`
- Malicious trivy binary (v0.69.4) SHA256: `385d498d18a3a7c67878ca7322716f9da25683eb1a4bf9e9592da0d5f2ab09f6`

**Malicious Docker image digests:**
- v0.69.4: `sha256:27f446230c60bbf0b70e008db798bd4f33b7826f9f76f756606f5417100beef3`
- v0.69.5: `sha256:5aaa1d7cfa9ca4649d6ffad165435c519dc836fa6e21b729a2174ad10b057d2b`
- v0.69.6: `sha256:425cd3e1a2846ac73944e891250377d2b03653e6f028833e30fc00c1abbc6d33`

**Persistence paths (self-hosted runners):**
- `~/.config/sysmon/sysmon.py`
- `~/.local/share/pgmon/service.py`
- `~/.config/systemd/user/pgmon.service`
- `/var/lib/svc_internal/runner.py`
- `/etc/systemd/system/internal-monitor.service`
- `/var/lib/pgmon/pgmon.py`

**Exfiltration method:**
- Dead drop: public repo named `tpcp-docs` created via victim's GITHUB_TOKEN
- Artifact: `tpcp.tar.gz`

**5-stage payload:**
1. PID discovery — locate the Runner.Worker process
2. Credential theft — GitHub-hosted: `/proc/mem` reading of Runner.Worker process memory; self-hosted: sweep 50+ filesystem paths for credentials
3. Encryption — AES-256-CBC encryption with RSA-4096 key wrapping
4. Dual exfiltration — HTTPS POST to C2 domain + GitHub repo creation as dead drop
5. Cleanup + legitimate scan — remove traces and execute the real Trivy scan to avoid suspicion

## Checkmarx KICS (checkmarx/kics-github-action) — March 23, 2026

**Attack window:** March 23, 12:58-16:50 UTC (~4 hours)

**Tags compromised:** 35 tags hijacked across kics-github-action and ast-github-action.

**Safe versions:**
- ast-github-action: v2.3.33
- kics-github-action: v2.1.20

**C2 infrastructure:**
- Primary C2: `checkmarx[.]zone`
- C2 IP: `83.142.209.11`

**Exfiltration method:**
- Artifact: `tpcp.tar.gz` sent to `checkmarx[.]zone`
- Fallback dead drop: repo named `docs-tpcp` created via victim's GITHUB_TOKEN

**Also compromised:**
- VS Code extensions on OpenVSX: ast-results v2.53.0, cx-dev-assist v1.7.0

**Root cause:** Compromised via stolen Trivy CI credentials (cx-plugins-releases service account).

**Cascade impact:** Stolen KICS CI PyPI credentials were used on March 24 to publish backdoored LiteLLM on PyPI. This demonstrates the critical cascading nature of these attacks.

## Generic GitHub Actions attack patterns

### Tag overwriting

The core attack technique. Attackers with write access to an action repository force-push tags to point at malicious commits. Since most workflow files reference actions by mutable tags (`@v1`, `@v2`, `@main`), all downstream consumers silently execute the attacker's code on their next workflow run.

Detection:
```bash
# Find tag-based references (vulnerable)
grep -rn "uses:.*@v[0-9]" .github/workflows/
grep -rn "uses:.*@main\|uses:.*@master" .github/workflows/

# Find SHA-pinned references (likely safe)
grep -rn "uses:.*@[a-f0-9]\{40\}" .github/workflows/
```

### Entrypoint script injection

Legitimate action code is replaced with a credential stealer. The malicious entrypoint performs the attack, then executes the real action code to avoid detection. Users see normal action output while their secrets are being exfiltrated.

### Process memory reading

On Linux GitHub-hosted runners, the payload reads `/proc/{PID}/mem` of the `Runner.Worker` process to extract secrets from memory. This bypasses any masking applied to log output.

```bash
# IOC pattern in logs
grep -iE "/proc/(self|[0-9]+)/(mem|environ)" workflow_logs.txt
```

### Environment variable dumping

The payload reads `/proc/{PID}/environ` or calls `env`/`printenv` to harvest all environment variables, including secrets injected by GitHub Actions.

### Exfiltration patterns

**Base64/double-base64 encoding:**
```bash
# Look for base64-encoded blobs in workflow logs
grep -oE '[A-Za-z0-9+/]{100,}={0,2}' workflow_logs.txt
```

**HTTPS POST to typosquatted or lookalike domains:**
```bash
# Unexpected outbound requests
grep -iE "curl|wget" workflow_logs.txt | grep -v "github.com\|githubusercontent\|actions"
```

**GitHub repository creation as exfiltration dead drop:**
The attacker uses the victim's GITHUB_TOKEN to create a new public repo and pushes stolen credentials there. Look for unexpected repo creation in your org.

```bash
gh api "/orgs/ORG/repos?sort=created&direction=desc&per_page=20" \
  --jq '.[] | "\(.name) \(.created_at)"'

# Specifically check for known dead drop names
gh api "/orgs/ORG/repos" --jq '.[] | select(.name | test("tpcp|docs-tpcp")) | .full_name'
```

**Process replacement:**
The malicious code runs, then `exec`s the legitimate action binary so the job appears to complete normally. This makes detection from job output alone very difficult.

### Self-hosted runner persistence

Self-hosted runners retain state between jobs. The Trivy payload deployed multiple persistence mechanisms:

```bash
# systemd user services
find ~/.config/systemd/user/ -name "*.service" -mtime -7 2>/dev/null
systemctl --user list-units --type=service --state=running

# systemd system services (requires root)
find /etc/systemd/system/ -name "internal-monitor.service" 2>/dev/null

# Python backdoors in config directories
ls -la ~/.config/sysmon/sysmon.py 2>/dev/null
ls -la ~/.local/share/pgmon/service.py 2>/dev/null
ls -la /var/lib/svc_internal/runner.py 2>/dev/null
ls -la /var/lib/pgmon/pgmon.py 2>/dev/null

# Check for unexpected cron entries
crontab -l 2>/dev/null
```

### Credential targets in CI

These are the secrets and tokens that GitHub Actions supply chain attacks typically target:

**Automatic secrets:**
- `GITHUB_TOKEN` — scoped to the repo, but can have write permissions
- `ACTIONS_RUNTIME_TOKEN` — used internally by the runner

**User-configured secrets (vary by repo):**
- Cloud credentials: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AZURE_CREDENTIALS`, `GCP_SA_KEY`
- Registry tokens: `DOCKER_PASSWORD`, `NPM_TOKEN`, `PYPI_API_TOKEN`, `RUBYGEMS_API_KEY`, `NUGET_API_KEY`
- Deploy keys and SSH keys
- Database connection strings
- API keys for third-party services
- Webhook URLs (Slack, PagerDuty)

**Environment variables on self-hosted runners:**
- Any credentials configured in the runner's environment
- Cloud metadata endpoint tokens (AWS IMDSv1)
- Kubernetes service account tokens at `/var/run/secrets/kubernetes.io/serviceaccount/token`

## Network IOC patterns

When specific C2 domains aren't known, look for these patterns in workflow logs:

- Domains that typosquat the compromised action's organization (e.g., `aquasecurtiy` instead of `aquasecurity`)
- Domains impersonating security vendors (e.g., `checkmarx.zone`)
- Connections to blockchain-based C2 (`.icp0.io` domains)
- HTTPS POST requests with large payloads to non-GitHub domains
- Unexpected DNS queries from workflow steps
- References to `tpcp` or `tpcp.tar.gz` in any context

```bash
# Search workflow logs for network IOCs
grep -iE "curl|wget|nc |ncat|socat" workflow_logs.txt | grep -v "github.com"
grep -iE "aquasecurtiy|checkmarx\.zone|icp0\.io" workflow_logs.txt
grep -i "tpcp" workflow_logs.txt
```
