---
name: github-actions-supply-chain-response
description: Respond to compromised GitHub Actions where tags have been overwritten with malicious code. Use this skill when a GitHub Action is reported compromised, when CI/CD secrets may have been exfiltrated through a poisoned action, when someone mentions Trivy, Checkmarx KICS, or any GitHub Action being backdoored, hacked, or tampered with. Also trigger when users ask about checking workflow run logs for exfiltration indicators, rotating CI secrets after a GitHub Actions compromise, or auditing GitHub Actions references across their organization.
license: MIT
compatibility: Requires gh CLI and bash. Optional: jq, git.
---

# GitHub Actions Supply Chain Attack Response

Help developers and security teams triage, investigate, contain, and recover from a compromised GitHub Action where tags have been overwritten with malicious code.

This skill produces one of three outputs depending on what the user asks for:

1. **Interactive triage checklist** — step-by-step walkthrough, one phase at a time, asking the user to run commands and report back before proceeding.
2. **Full incident response runbook** — a complete markdown document covering all six phases that the user can save and share with their team.
3. **Shell script** — a `check_gha_compromise.sh` script that automates detection, reports findings, and prompts before any remediation action.

If the user doesn't specify which format, default to the interactive triage checklist. If the user says something like "just give me everything" or "runbook", produce the full markdown document. If they say "script" or "automate", generate the shell script.

## Gathering context

Before producing any output, collect the following from the user. If they've already provided some of this in the conversation, don't re-ask.

**Required:**
- **Action name** — the compromised action (e.g., `aquasecurity/trivy-action`)
- **Organization** — the GitHub org or user to scan

**Helpful but not required (use defaults or skip if the user doesn't know):**
- **Attack window** — UTC time range when the malicious tags were live
- **Known safe SHA** — the last clean commit SHA to pin to
- **Known IOCs** — C2 domains, exfiltration patterns, persistence paths. If the user doesn't have these, use the built-in IOC pattern library (see `references/ioc-patterns.md`).
- **Payload behavior** — what the malware does (credential theft, persistence, lateral movement). If unknown, assume credential theft from CI environment as the baseline.

## The six phases

Every output format follows these six phases in order. The depth and format change based on the output type, but the sequence is always the same.

### Phase 1: Exposure check — "Do we use this action?"

The goal is to determine whether any repositories in the organization reference the compromised action in their workflow files.

**Commands to guide the user through:**

Search local workflow files for references to the affected action:
```bash
grep -rn "ACTION_NAME" .github/workflows/
```

Check if references use mutable tags (vulnerable) vs pinned SHAs (likely safe):
```bash
# Mutable tag references (VULNERABLE)
grep -rn "uses: ACTION_NAME@v" .github/workflows/
grep -rn "uses: ACTION_NAME@main" .github/workflows/

# SHA-pinned references (likely safe — verify the SHA is not the malicious commit)
grep -rn "uses: ACTION_NAME@[a-f0-9]\{40\}" .github/workflows/
```

Use gh CLI to search across the entire org:
```bash
gh search code "ACTION_NAME" --owner ORG --json repository,path
```

List all repos using the action and classify each reference as tag-based (vulnerable) or SHA-pinned (verify SHA):
```bash
gh search code "uses: ACTION_NAME" --owner ORG --json repository,path,textMatch
```

### Phase 2: Run window confirmation — "Did we run it during the attack?"

If Phase 1 found the action in any workflow, determine whether those workflows actually ran during the attack window.

List workflow runs during the attack window:
```bash
gh api "/repos/ORG/REPO/actions/runs?per_page=100&created=START..END" \
  --jq '.workflow_runs[] | "\(.id)|\(.created_at)|\(.conclusion)"'
```

Download and search workflow logs for the action reference:
```bash
gh run view RUN_ID --log 2>/dev/null | grep -i "ACTION_NAME"
```

Check if the run used a tag-based reference (vulnerable) or SHA-pinned (safe):
```bash
gh api "/repos/ORG/REPO/actions/runs/RUN_ID/jobs" \
  --jq '.jobs[].steps[] | select(.name | test("ACTION_NAME"; "i")) | .name'
```

Classify each run:
- **Tag-based reference during attack window** — assume compromised
- **SHA-pinned to known-safe SHA** — likely safe, verify the SHA
- **SHA-pinned to unknown SHA** — verify against known malicious commits
- **Run outside attack window** — likely safe, but check for second-wave attacks

### Phase 3: IOC hunting — "Did the malware execute?"

If Phase 2 confirmed runs during the attack window with tag-based references, hunt for evidence that the payload executed.

**Search workflow logs for known exfiltration patterns:**
```bash
# Download logs for a specific run
gh run view RUN_ID --log > /tmp/run_RUN_ID.log

# Search for IOC patterns
grep -i "base64" /tmp/run_RUN_ID.log
grep -iE "curl|wget" /tmp/run_RUN_ID.log | grep -v "github.com\|githubusercontent"
grep -i "tpcp" /tmp/run_RUN_ID.log
grep -iE "proc/(self|[0-9]+)/(mem|environ)" /tmp/run_RUN_ID.log
```

**Check for exfiltration dead drop repos:**
```bash
gh api "/orgs/ORG/repos" --jq '.[] | select(.name | test("tpcp|docs-tpcp")) | .full_name'
```

Search for repos created during the attack window that match dead drop patterns:
```bash
gh api "/orgs/ORG/repos?sort=created&direction=desc&per_page=20" \
  --jq '.[] | "\(.name) \(.created_at)"'
```

**Check for known C2 domain references in logs:**
```bash
# For Trivy compromise
grep -i "aquasecurtiy\|scan\.aquasecurtiy" /tmp/run_*.log
grep -i "45\.148\.10\.212" /tmp/run_*.log
grep -i "icp0\.io" /tmp/run_*.log

# For KICS compromise
grep -i "checkmarx\.zone\|83\.142\.209\.11" /tmp/run_*.log
```

**For self-hosted runners: check for persistence artifacts:**
```bash
# systemd services
find ~/.config/systemd/user/ -name "*.service" -mtime -7 2>/dev/null
find /etc/systemd/system/ -name "internal-monitor.service" 2>/dev/null

# Known Trivy persistence paths
ls -la ~/.config/sysmon/sysmon.py 2>/dev/null
ls -la ~/.local/share/pgmon/service.py 2>/dev/null
ls -la /var/lib/svc_internal/runner.py 2>/dev/null
ls -la /var/lib/pgmon/pgmon.py 2>/dev/null
```

### Phase 4: Containment — "Stop the bleeding"

**Pin affected action references to known-safe commit SHAs:**
Replace all tag-based references with SHA-pinned references in workflow files:
```yaml
# BEFORE (vulnerable)
- uses: aquasecurity/trivy-action@v1

# AFTER (safe)
- uses: aquasecurity/trivy-action@57a97c7e7821a5776cebc9bb87c984fa69cba8f1
```

**Cancel any in-flight workflow runs using the compromised action:**
```bash
gh api "/repos/ORG/REPO/actions/runs?status=in_progress" \
  --jq '.workflow_runs[].id' | while read run_id; do
    gh api -X POST "/repos/ORG/REPO/actions/runs/$run_id/cancel"
  done
```

**Clear GitHub Actions cache:**
```bash
gh api -X DELETE "/repos/ORG/REPO/actions/caches"
```

**Disable affected workflows temporarily if needed:**
```bash
gh workflow disable WORKFLOW_NAME -R ORG/REPO
```

**For self-hosted runners: isolate and rebuild.** Do not simply clean the runner. Rebuild from a fresh image. Self-hosted runners retain state between jobs, making persistence far more likely.

### Phase 5: Credential rotation — "Assume all CI secrets are burned"

This is the phase teams skip because it's painful. Be explicit and systematic. Any secret accessible to a workflow that ran the compromised action during the attack window must be rotated.

**List all secrets accessible to affected workflows:**
```bash
# Repository-level secrets
gh api "/repos/ORG/REPO/actions/secrets" --jq '.secrets[].name'

# Organization-level secrets
gh api "/orgs/ORG/actions/secrets" --jq '.secrets[].name'

# Environment-level secrets
gh api "/repos/ORG/REPO/environments" --jq '.environments[].name' | while read env; do
  echo "--- $env ---"
  gh api "/repos/ORG/REPO/environments/$env/secrets" --jq '.secrets[].name' 2>/dev/null
done
```

**Credential classes to rotate:**

- **GITHUB_TOKEN** — inherently scoped to the workflow run, but review its permissions. If `contents: write` or `packages: write` was granted, the attacker could have pushed code or packages.
- **Personal Access Tokens (PATs)** — revoke and regenerate any PATs stored as secrets.
- **Deploy keys** — regenerate SSH deploy keys for affected repos.
- **Cloud credentials (AWS, GCP, Azure)** — rotate access keys, service account keys, client secrets used in CI.
- **Docker registry credentials** — rotate tokens for Docker Hub, GHCR, ECR, GCR, ACR.
- **Package registry tokens** — npm tokens, PyPI API tokens, RubyGems API keys, NuGet API keys.
- **SSH keys** — any SSH keys stored as CI secrets for deployment.
- **Database credentials** — any database connection strings or passwords in CI secrets.
- **Webhook secrets** — Slack, PagerDuty, or other webhook URLs stored as secrets.

**Post-rotation audit:**

Check GitHub audit logs for suspicious activity during the attack window:
```bash
gh api "/orgs/ORG/audit-log" --method GET \
  -F phrase="created:START..END" -F per_page=100
```

Check whether stolen GITHUB_TOKENs were used to create repos (dead drop pattern):
```bash
gh api "/orgs/ORG/repos?sort=created&direction=desc&per_page=20" \
  --jq '.[] | "\(.name) \(.created_at) \(.pushed_at)"'
```

### Phase 6: Prevention — "Don't get burned again"

**Pin ALL GitHub Actions to full commit SHAs, never mutable tags:**
```yaml
# BAD — mutable tag, can be overwritten
- uses: actions/checkout@v4

# GOOD — immutable SHA
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
```

**Use GitHub's Actions allow-list** to restrict which actions can run:
- Settings > Actions > General > Allow select actions and reusable workflows
- Only allow actions from verified creators and specific repositories

**Enable Dependabot for GitHub Actions version updates:**
```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
```

**Use StepSecurity Harden-Runner for runtime monitoring:**
```yaml
- uses: step-security/harden-runner@v2
  with:
    egress-policy: audit  # or block
```

**Review GITHUB_TOKEN permissions — use minimum required:**
```yaml
permissions:
  contents: read
  # Only add write permissions for steps that truly need them
```

**Separate CI secrets:** Don't give build workflows access to deploy secrets. Use GitHub Environments with protection rules to gate access to production credentials.

**Use OpenID Connect (OIDC)** instead of long-lived credentials for cloud deployments:
```yaml
permissions:
  id-token: write
  contents: read

- uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: arn:aws:iam::123456789:role/deploy
    aws-region: us-east-1
```

## Output format guidance

### Interactive triage checklist

Walk the user through one phase at a time. After each phase, ask what they found before proceeding to the next. Adapt the remaining phases based on their answers. For example, if Phase 1 shows they don't use the action, stop and tell them they're clear — don't walk through IOC hunting.

Structure each phase as:
1. Brief explanation of what this phase checks and why
2. The commands to run (customized with the action name, org, and attack window from context)
3. What to look for in the output
4. A clear yes/no decision: "If you see X, proceed to Phase N. If not, you can stop here."

### Full incident response runbook

Produce a markdown document with all six phases, all commands pre-filled with the specific action name, org, attack window, IOC domains, and persistence paths from the advisory. Include a summary header with the incident metadata (action, compromised tags, attack window, IOC domains). This is meant to be shared with a team, so write it to be self-contained — someone reading it for the first time should understand what happened and what to do.

Save this as a `.md` file using the create_file tool.

### Shell script

Generate a bash script called `check_gha_compromise.sh` that:
- Takes the org name and action name as arguments
- Runs detection checks from Phases 1-3
- Color-codes output: green for clean, red for findings, yellow for warnings
- Prompts with `read -p` before any destructive action (cache clearing, workflow disabling)
- Generates a summary report at the end listing what was found and what actions were taken
- Includes a `--dry-run` flag that skips all prompts and just reports

Read `scripts/check_gha_compromise.sh` for the template. Customize it with the specific action details from the user's context.

Save this using the create_file tool and make it executable.

## Incident report template

When producing the full incident response runbook or interactive checklist, include this template at the end so the user can document their findings.

### Summary
- Incident:
- Compromised action:
- Ecosystem: GitHub Actions
- Compromised tags:
- Known safe SHA:
- Attack window:
- Repositories reviewed:
- Result:

### Findings by repository
- Repository:
- Workflow file:
- Reference type (tag/SHA):
- Runs during attack window:
- IOC indicators found:
- Risk level:
- Evidence:

### Secret exposure
- Secrets accessible to affected workflows:
- Secrets rotated:
- Audit logs checked:
- Dead drop repos found:

### Actions taken
- Workflows disabled:
- References pinned to SHA:
- Caches cleared:
- Runners rebuilt:
- Secrets rotated:
- Monitoring added:

### Unknowns
- Missing logs (retention expired):
- Deleted workflow runs:
- Third-party action dependencies of the compromised action:
- Confidence level:

## Important notes

- Never tell the user they're "definitely safe" — supply chain attacks can have delayed or stealthy payloads. Use language like "no indicators found in the checks we ran" and suggest they monitor for advisories.
- The cascading nature of these attacks is critical — compromised Trivy credentials led to KICS, compromised KICS credentials led to LiteLLM on PyPI. A single compromised action can cascade across ecosystems. Always ask: "What other systems did the stolen CI credentials have access to?"
- Tag-based action references are the root cause — mutable tags can be force-pushed to point at any commit. Always pin to full commit SHAs.
- Self-hosted runners have additional persistence risks compared to GitHub-hosted runners. GitHub-hosted runners are ephemeral, but self-hosted runners retain filesystem state between jobs. The Trivy attack deployed systemd services, Python backdoors, and init scripts on self-hosted runners.
- Workflow logs are retained for a limited time (90 days by default). If the attack happened close to the retention window, download and archive logs immediately before they expire.
- The GITHUB_TOKEN scope matters. If the workflow had `contents: write`, the attacker could push code. If it had `packages: write`, the attacker could publish packages. Review the permissions block in each affected workflow.
- Credential rotation is non-negotiable if a compromised action ran during the attack window. The attacker had access to every secret exposed to that workflow. Don't let the user skip this phase.
