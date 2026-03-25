---
name: pypi-supply-chain-response
description: Respond to Python/PyPI supply chain attacks and compromised package incidents. Use this skill whenever a user mentions a compromised Python package, a PyPI supply chain attack, a malicious dependency, credential-stealing malware in a pip package, or asks how to check if they're affected by a package compromise. Also trigger when the user asks about rotating credentials after a Python package incident, finding transitive dependencies, hunting for IOCs from a pip install, auditing Python environments for malicious packages, or generating an incident response checklist for a PyPI compromise. Trigger even if the user just names a package and says it was "hacked", "backdoored", "compromised", or "pwned".
license: MIT
compatibility: Requires Bash, Python 3, and pip. Optional: uv, poetry, conda, pipdeptree, docker, kubectl.
---

# PyPI Supply Chain Attack Response

Help developers triage, investigate, contain, and recover from a compromised Python package on PyPI.

This skill produces one of three outputs depending on what the user asks for:

1. **Interactive triage checklist** — step-by-step walkthrough, one phase at a time, asking the user to run commands and report back before proceeding.
2. **Full incident response runbook** — a complete markdown document covering all six phases that the user can save and share with their team.
3. **Shell script** — a `check_compromise.sh` script that automates detection, reports findings, and prompts before any remediation action.

If the user doesn't specify which format, default to the interactive triage checklist. If the user says something like "just give me everything" or "runbook", produce the full markdown document. If they say "script" or "automate", generate the shell script.

## Gathering context

Before producing any output, collect the following from the user. If they've already provided some of this in the conversation, don't re-ask.

**Required:**
- **Package name** — the compromised package (e.g., `litellm`)
- **Compromised versions** — which versions contain the malicious payload (e.g., `1.82.7`, `1.82.8`)

**Helpful but not required (use defaults or skip if the user doesn't know):**
- **Known safe version** — the last clean version to pin to (e.g., `1.82.6`)
- **Attack window** — UTC time range when the bad versions were available on PyPI
- **Known IOCs** — domains, filenames, persistence paths, process names. If the user doesn't have these, use the built-in IOC pattern library (see `references/ioc-patterns.md`).
- **Payload behavior** — what the malware does (credential theft, persistence, lateral movement). If unknown, assume credential theft as the baseline.

## The six phases

Every output format follows these six phases in order. The depth and format change based on the output type, but the sequence is always the same.

### Phase 1: Exposure check — "Am I even affected?"

The goal is to determine whether the compromised package exists anywhere in the user's environments, including as a transitive dependency they never directly installed.

**Commands to guide the user through:**

Check if the package is installed and what version:
```
pip show <PACKAGE> | grep -E "^(Name|Version|Location)"
uv pip show <PACKAGE>
poetry show <PACKAGE>
conda list <PACKAGE>
```

Find what pulled it in as a transitive dependency (this is the critical step most developers miss):
```
pip install pipdeptree
pipdeptree -r -p <PACKAGE>
```
The reverse tree shows the chain. If `dspy` depends on `litellm>=1.64.0`, the user will see it here even though they only ran `pip install dspy`.

Hunt across ALL environments on the machine — developers often have multiple venvs, conda envs, global installs, and package manager caches:
```
find / -path "*/site-packages/<PACKAGE>" -type d 2>/dev/null
find / -name "*<PACKAGE>*.pth" 2>/dev/null
find ~/.cache/uv -name "*<PACKAGE>*" 2>/dev/null
pip cache list <PACKAGE>
```

Check Docker images built during the attack window:
```
docker images --format "{{.Repository}}:{{.Tag}} {{.CreatedAt}}" | sort -k2
docker run --rm <IMAGE> pip show <PACKAGE>
```

Search requirements and lockfiles for unpinned or loosely pinned references:
```
grep -rn "<PACKAGE>" --include="*.txt" --include="*.toml" --include="*.lock" --include="*.cfg" .
```
Flag dangerous patterns: `>=`, `~=`, `>`, or no version pin at all.

Check CI/CD logs for the package version string during the attack window:
```
grep -r "<PACKAGE>==" /path/to/ci/logs/
```

### Phase 2: Version confirmation — "Did I get the bad version?"

If Phase 1 found the package, confirm whether the installed version matches a compromised version.

```
pip show <PACKAGE> | grep Version
```

Check file timestamps to estimate when the package was installed:
```
stat $(python -c "import <PACKAGE>; print(<PACKAGE>.__file__)")
```

For .pth-based attacks (increasingly common), scan site-packages for .pth files containing suspicious patterns:
```
SITE=$(python -c "import site; print(site.getsitepackages()[0])")
find "$SITE" -name "*.pth" -exec grep -l "base64\|subprocess\|exec\|eval\|compile" {} \;
```

Check pip install logs if available:
```
cat ~/.pip/pip.log 2>/dev/null | grep <PACKAGE>
grep -r "<PACKAGE>" ~/.cache/pip/http/ 2>/dev/null | head -20
```

After confirming the version, classify the finding into one of these five categories to communicate risk clearly:

- **Not present** — package not found anywhere
- **Present, safe version** — installed but not a compromised version
- **Present, likely affected** — compromised version was installed
- **Present, insufficient evidence** — package found but version or install timing unclear
- **Confirmed compromise** — compromised version installed AND IOC indicators found

Use this classification in the output for each environment reviewed so the user and their team can quickly understand the severity.

### Phase 3: IOC hunting — "Did the malware execute?"

If the user confirmed they had a compromised version, look for evidence that the payload ran. Read `references/ioc-patterns.md` for the built-in pattern library. Combine those patterns with any attack-specific IOCs the user provides.

**Filesystem persistence:**
```
find ~/.config -name "*.py" -mtime -3 2>/dev/null
find ~/.config/systemd/user/ -name "*.service" -mtime -3 2>/dev/null
crontab -l 2>/dev/null
ls -la /etc/cron.d/ 2>/dev/null
```

**Network indicators:**
```
ss -tnp | grep python
netstat -tnp 2>/dev/null | grep python
```
If the user has specific C2 domains from the advisory, search logs:
```
grep -rF "<C2_DOMAIN>" /var/log/ 2>/dev/null
```

**Process inspection:**
```
ps aux | grep python | grep -v grep
```

**Kubernetes (if applicable):**
```
kubectl get pods -n kube-system --sort-by=.metadata.creationTimestamp
kubectl get secrets --all-namespaces -o json | jq '.items[] | select(.metadata.creationTimestamp > "<ATTACK_DATE>")'
```

**Credential access evidence:**
```
find ~/.ssh ~/.aws ~/.config/gcloud ~/.kube -atime -1 2>/dev/null
stat ~/.ssh/id_rsa 2>/dev/null | grep Access
```

### Phase 4: Containment — "Stop the bleeding"

Before removing anything, preserve evidence if your organization may need forensic analysis. Copy or snapshot affected environments, save pip inspect output, screenshot active network connections, and export relevant logs. Once you uninstall packages and purge caches, that evidence is gone.

```
# Preserve evidence before cleanup
python -m pip inspect > pip-inspect-evidence-$(date +%Y%m%d-%H%M%S).json
python -m pip freeze > pip-freeze-evidence-$(date +%Y%m%d-%H%M%S).txt
ss -tnp > network-connections-$(date +%Y%m%d-%H%M%S).txt 2>/dev/null
cp -r $(python -c "import site; print(site.getsitepackages()[0])") site-packages-backup-$(date +%Y%m%d-%H%M%S)/ 2>/dev/null
```

Remove the compromised package and purge caches so it can't be reinstalled from a cached wheel.

```
pip uninstall <PACKAGE> -y
pip cache purge
rm -rf ~/.cache/uv
rm -rf ~/.cache/pip
```

If persistence artifacts were found in Phase 3, remove them. In the interactive checklist, describe each artifact and ask the user to confirm before deleting. In the shell script, prompt with `read -p`.

Pin to a known-safe version:
```
echo "<PACKAGE>==<SAFE_VERSION>" >> requirements.txt
```

For Docker: rebuild images from a clean base, pinning the safe version. Don't just `docker exec` into running containers.

### Phase 5: Credential rotation — "Assume everything on that box is burned"

This is the phase developers skip because it's painful. Be explicit and systematic. The skill should walk through each credential class, not just say "rotate everything."

**SSH keys:**
```
ls -la ~/.ssh/
# Regenerate each key pair, update authorized_keys on remote hosts
```

**Cloud provider credentials:**
```
# AWS — list and rotate access keys
aws iam list-access-keys --user-name $(aws iam get-user --query User.UserName --output text)
# Then create new keys and delete old ones

# GCP — revoke application default credentials
gcloud auth revoke --all
gcloud auth application-default revoke
# Regenerate service account keys via console

# Azure
az account clear
# Rotate via Azure portal
```

**Kubernetes:**
```
# Regenerate kubeconfig
kubectl config delete-context <CONTEXT>
# Re-authenticate via your provider
```

**Environment variables and .env files:**
```
# Find all .env files and list the keys (not values) that need rotation
find . -name ".env*" -exec grep -h "KEY\|SECRET\|TOKEN\|PASSWORD\|CREDENTIAL" {} \; | cut -d= -f1 | sort -u
```
Then rotate each key at the respective provider's dashboard.

**Git credentials:**
```
git credential reject <<EOF
protocol=https
host=github.com
EOF
```

**Database passwords:** identify from .env files and connection strings, then rotate at the database level.

**Crypto wallets:** if wallet files were on the machine, transfer funds to a new wallet immediately.

#### Post-rotation audit

After rotating credentials, check whether the compromised credentials were already used maliciously. Look for:

- Whether the compromised credentials were used from unusual source IPs or regions after the suspected install time
- Whether they created new tokens, users, or persistence mechanisms
- Whether they accessed resources they shouldn't have
- Cloud provider audit logs: AWS CloudTrail, GCP Audit Logs, Azure Activity Log

```
# AWS — check recent API calls from the old access key
aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=<OLD_KEY_ID> --max-results 50

# GCP — check recent admin activity
gcloud logging read "protoPayload.authenticationInfo.principalEmail=<SERVICE_ACCOUNT>" --limit 50

# GitHub — check audit log for token usage
gh api /orgs/<ORG>/audit-log --method GET -F phrase="actor:<USERNAME>" -F per_page=50
```

### Phase 6: Prevention — "Don't get burned again"

These are the structural improvements to prevent the next supply chain attack from having the same impact.

**Pin exact versions in requirements:**
```
pip freeze | grep <PACKAGE>
# Use == pinning, not >= or ~=
```

**Generate an SBOM** so you can answer "am I affected?" in seconds next time:
```
pip install cyclonedx-bom
cyclonedx-py requirements -i requirements.txt -o sbom.json
```

**Run pip-audit in CI:**
```
pip install pip-audit
pip-audit
```

**For uv users, use --exclude-newer to freeze the supply chain timeline:**
```
uv pip install --exclude-newer "2026-03-23T00:00:00Z" <PACKAGE>
```

**Scope secrets in CI/CD:**
Instead of workflow-level environment variables, pass secrets only to the specific step that needs them. This limits blast radius if a dependency runs code during `pip install`.

**Use Trusted Publishing** for your own packages: OIDC tokens scoped to CI instead of long-lived PyPI API tokens.

**Lockfiles with hashes:** `pip-compile --generate-hashes` or `uv pip compile --generate-hashes` to detect tampered wheels.

## Output format guidance

### Interactive triage checklist

Walk the user through one phase at a time. After each phase, ask what they found before proceeding to the next. Adapt the remaining phases based on their answers. For example, if Phase 1 shows they're not exposed, stop and tell them they're clear — don't walk through IOC hunting.

Structure each phase as:
1. Brief explanation of what this phase checks and why
2. The commands to run (customized with the package name and versions from context)
3. What to look for in the output
4. A clear yes/no decision: "If you see X, proceed to Phase N. If not, you can stop here."

### Full incident response runbook

Produce a markdown document with all six phases, all commands pre-filled with the specific package name and versions, IOC domains, and persistence paths from the advisory. Include a summary header with the incident metadata (package, versions, attack window, IOC domains). This is meant to be shared with a team, so write it to be self-contained — someone reading it for the first time should understand what happened and what to do.

Save this as a `.md` file using the create_file tool.

### Shell script

Generate a bash script called `check_compromise.sh` that:
- Takes the package name as an argument (or hardcodes it if the user specifies)
- Runs detection checks from Phases 1-3
- Color-codes output: green for clean, red for findings, yellow for warnings
- Prompts with `read -p` before any destructive action (uninstall, cache purge, file deletion)
- Generates a summary report at the end listing what was found and what actions were taken
- Includes a `--dry-run` flag that skips all prompts and just reports

Read `scripts/check_compromise_template.sh` for the template. Customize it with the specific package details from the user's context.

Save this using the create_file tool and make it executable.

## Incident report template

When producing the full incident response runbook or interactive checklist, include this template at the end so the user can document their findings.

### Summary
- Incident:
- Package:
- Ecosystem:
- Known bad versions:
- Attack window:
- Systems reviewed:
- Result:

### Findings by system
- System name:
- Source reference found:
- Installed version:
- Direct or transitive:
- Indicator found:
- Risk level:
- Evidence:

### Secret exposure
- Secrets likely present:
- Secrets rotated:
- Audit logs checked:

### Actions taken
- Isolated:
- Rebuilt:
- Blocked versions:
- Monitoring added:

### Unknowns
- Missing logs:
- Deleted environments:
- Confidence level:

## Important notes

- Never tell the user they're "definitely safe" — supply chain attacks can have delayed or stealthy payloads. Use language like "no indicators found in the checks we ran" and suggest they monitor for advisories.
- The .pth attack vector is particularly dangerous because it fires on every Python interpreter startup, not just when the package is imported. Emphasize this when relevant.
- Transitive dependency exposure is the most common way developers are affected. Most people don't install packages like litellm directly — they get it through CrewAI, DSPy, Browser-Use, etc. The `pipdeptree -r` step is often the most important single command in the entire playbook.
- Credential rotation is non-negotiable if the compromised version was installed. The attacker had access to everything on that machine. Don't let the user skip this phase.
- For Kubernetes environments, the blast radius extends beyond the compromised node. Sophisticated payloads deploy privileged pods across all nodes using the service account token.
