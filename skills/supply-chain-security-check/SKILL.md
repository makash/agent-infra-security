---
name: supply-chain-security-check
description: Investigate whether a project, environment, container, or CI pipeline is affected by a dependency supply chain incident. Find direct and transitive usage, check compromised versions and indicators of compromise, and recommend containment and remediation actions.
license: MIT
compatibility: Requires Bash and Python 3. Optional: pip, pipdeptree, docker, kubectl, jq, rg.
---

# Supply Chain Security Check

## Purpose
Investigate whether a project, build, image, host, or CI environment is affected by a newly disclosed package supply chain incident, identify blast radius, and produce exact remediation actions.

## When to use
Use this skill when:
- a package on PyPI, npm, crates.io, RubyGems, Maven, NuGet, Go modules, or Docker Hub is reported compromised
- a transitive dependency may have pulled in a bad version
- you need a fast answer on "do we use this anywhere?"
- you need a clean incident note for engineering or security
- you need to identify what to rotate, rebuild, or block

## Inputs
- Package name
- Ecosystem: python, node, go, rust, java, docker, etc.
- Known bad versions
- Known safe version or mitigation if available
- Indicators of compromise
- Repos, folders, images, or runners to inspect
- Optional: build logs, lockfiles, SBOMs, image digests, CI logs

## Required outputs
1. Executive summary
2. Where the package appears
3. Whether usage is direct or transitive
4. Exact affected versions found
5. Systems likely exposed
6. Immediate containment actions
7. Credential rotation scope
8. Cleanup and rebuild actions
9. Gaps and unknowns
10. Copy-paste commands used

## Workflow

### 1. Confirm incident facts
Collect:
- bad versions
- install time window if known
- package manager and registry affected
- official guidance
- indicators of compromise
- whether pinned containers, vendored dependencies, or source installs were unaffected

### 2. Find direct references in source
Search for:
- requirements.txt
- requirements-*.txt
- pyproject.toml
- poetry.lock
- uv.lock
- Pipfile.lock
- setup.py
- setup.cfg
- package-lock.json
- pnpm-lock.yaml
- yarn.lock
- go.mod
- go.sum
- Cargo.toml
- Cargo.lock
- pom.xml
- build.gradle
- Dockerfile
- CI workflows
- install scripts
- bootstrap scripts
- docs or examples with install commands

### 3. Find transitive use in built environments
Check the actual installed environment, not just source files.

For Python environments check:
- pip list
- pip inspect
- pip show
- pip freeze
- pipdeptree
- site-packages contents
- cached wheels
- container layers
- CI job logs

Determine:
- whether the package was installed
- which top-level package pulled it in
- whether the resolved version matches a known bad version
- whether install timing overlaps the incident window

### 4. Hunt for indicators of compromise
Look for:
- suspicious files in site-packages
- suspicious domains or outbound connections
- unusual subprocess creation
- secrets access patterns
- startup hooks such as `.pth` files
- package versions installed during the incident window

### 5. Classify impact
Classify each finding as:
- Not present
- Present but safe version
- Present and likely affected
- Present but insufficient evidence
- Confirmed compromise

### 6. Recommend actions
If affected:
- isolate host, runner, or container
- revoke and rotate secrets (see detailed checklist below)
- remove malicious artifacts
- rebuild from known-good base
- pin or block bad versions
- audit transitive constraints
- review CI/CD and dependency caches
- add registry and dependency monitoring

#### Credential rotation per-class checklist

**SSH keys:**
```bash
ls -la ~/.ssh/
```
Regenerate each key pair and update `authorized_keys` on all remote hosts.

**AWS:**
```bash
aws iam list-access-keys --user-name $(aws iam get-user --query User.UserName --output text)
```
Create new access keys, delete the compromised ones, and invalidate any active sessions.

**GCP:**
```bash
gcloud auth revoke --all
gcloud auth application-default revoke
```
Regenerate service account keys via the console or `gcloud iam service-accounts keys create`.

**Azure:**
```bash
az account clear
```
Rotate credentials via the Azure portal; regenerate any service principal secrets.

**Kubernetes:**
```bash
kubectl config delete-context <CONTEXT>
```
Re-authenticate to each cluster and rotate service account tokens.

**.env files — identify all secrets to rotate:**
```bash
find . -name ".env*" -exec grep -h "KEY\|SECRET\|TOKEN\|PASSWORD\|CREDENTIAL" {} \; | cut -d= -f1 | sort -u
```

**Git credentials:**
Use `git credential reject` to clear cached credentials and re-authenticate. Rotate any personal access tokens (PATs).

**Database passwords:**
Rotate any passwords found in `.env` files or connection strings. Update application configuration after rotation.

**CI/CD secrets:**
Rotate secrets stored in GitHub Actions (repository and organization secrets), GitLab CI variables, and any other CI/CD platforms in use.

**Crypto wallets:**
If wallet private keys or seed phrases were accessible on the compromised host, transfer funds to new wallets immediately.

### 7. Prevention
- Pin exact versions in dependency files (`==` not `>=` or `~=`)
- Generate SBOMs for visibility into your dependency tree:
  ```bash
  pip install cyclonedx-bom && cyclonedx-py requirements -i requirements.txt -o sbom.json
  ```
- Run pip-audit in CI to catch known vulnerabilities:
  ```bash
  pip install pip-audit && pip-audit
  ```
- For uv users, restrict install time to avoid pulling newly-compromised versions:
  ```bash
  uv pip install --exclude-newer "2026-03-23T00:00:00Z" <PACKAGE>
  ```
- Scope CI secrets to individual steps, not workflow-level env vars
- Use Trusted Publishing (OIDC) for your own packages on PyPI
- Use lockfiles with hashes to prevent silent substitution:
  ```bash
  pip-compile --generate-hashes
  # or
  uv pip compile --generate-hashes
  ```

## Default investigation commands

### Python source search
```bash
rg -n "litellm" .
rg -n "pip install .*litellm|google-adk|browser-use" .
find . -iname "requirements*.txt" -o -iname "pyproject.toml" -o -iname "*lock*"
```

### Python environment inspection
```bash
python -m pip list --format=json
python -m pip inspect > pip-inspect.json
python -m pip show litellm
python -m pip freeze | grep -i litellm
pipdeptree | grep -i -A 5 -B 5 litellm
```

### Artifact and indicator checks
```bash
python - <<'PY'
import os
import site

for p in site.getsitepackages():
    for root, _, files in os.walk(p):
        for f in files:
            if f == "litellm_init.pth":
                print(os.path.join(root, f))
PY

find / -name "litellm_init.pth" 2>/dev/null
grep -R "models.litellm.cloud" /var/log /tmp "$HOME" 2>/dev/null
```

#### Generic .pth code execution detection
Legitimate `.pth` files (e.g. `distutils-precedence.pth`, `easy-install.pth`) contain simple path entries, not code execution patterns. Any `.pth` file importing dangerous modules or calling exec-like functions is suspicious.
```bash
SITE=$(python -c "import site; print(site.getsitepackages()[0])")
find "$SITE" -name "*.pth" -exec grep -l "base64\|subprocess\|exec\|eval\|compile\|import os\|import sys" {} \;
```

#### Persistence mechanism checks
Check for persistence mechanisms that a supply chain payload may have installed:
```bash
# systemd user services created or modified in the last 7 days
find ~/.config/systemd/user/ -name "*.service" -mtime -7 2>/dev/null

# Cron jobs
crontab -l 2>/dev/null
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ 2>/dev/null

# Python scripts dropped in config directories
find ~/.config -name "*.py" -mtime -7 2>/dev/null

# XDG autostart entries
find ~/.config/autostart -name "*.desktop" -mtime -7 2>/dev/null
```

#### Kubernetes lateral movement checks
Sophisticated payloads may use in-cluster service account tokens to deploy privileged pods across all nodes.
```bash
# Check for unexpected pods in kube-system, sorted by creation time
kubectl get pods -n kube-system --sort-by=.metadata.creationTimestamp

# Look for privileged pods across all namespaces
kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.containers[].securityContext.privileged == true) | .metadata.name'

# Recently created secrets
kubectl get secrets --all-namespaces --sort-by=.metadata.creationTimestamp | tail -20

# Audit RBAC for unexpected bindings created after the attack date
kubectl get clusterrolebindings -o json | jq '.items[] | select(.metadata.creationTimestamp > "<ATTACK_DATE>") | .metadata.name'
```

### Docker and CI
```bash
docker history <image>
docker run --rm <image> python -m pip freeze
```

## Output template

### Executive summary
State whether the project, image, runner, or host appears affected.

### Findings
For each repo, environment, image, or host:
- package present or absent
- direct or transitive
- resolved version
- evidence
- risk level

### Immediate actions
- containment
- secret rotation scope
- rebuild scope
- pinning or blocking recommendation

### Unknowns
List what still cannot be proven from available evidence.
