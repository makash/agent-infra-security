---
title: "feat: Layered Skill Architecture with npm Ecosystem Support"
type: feat
date: 2026-03-31
deepened: 2026-03-31
---

# Layered Skill Architecture with npm Ecosystem Support

## Enhancement Summary

**Deepened on:** 2026-03-31
**Research agents used:** npm-supply-chain-research, credential-rotation-security, architecture-strategist, code-simplicity-reviewer, spec-flow-analyzer

### Key Improvements
1. Fixed npm cache forensics commands (`npm cache ls` removed in npm 7 — use `_cacache` index search instead)
2. Added AWS STS deny-policy pattern for credential rotation (sessions survive key deletion for 36 hours)
3. Added routing mechanism: exclusion language in generic skill description + CATALOG.md routing preamble
4. Added pnpm/Bun/yarn lockfile support to npm skill scope
5. Clarified "auto-trigger" mechanism — it's description-based LLM matching, not background scanning

### Simplicity Challenge (from code-simplicity-reviewer)
The simplicity reviewer argues: **only build the npm skill, defer everything else.** The rationale: only the Axios compromise creates a real requirement today. The architecture refactoring (credential rename, generic rewrite, best-practices skill) is speculative improvement without a concrete user need. This is a valid YAGNI argument. The counter-argument: credential rotation is already duplicated across 3 skills (~210 lines) and will be duplicated in a 4th (npm) if we don't consolidate now. The user should decide scope before implementation.

### Critical Gaps Discovered (from spec-flow-analyzer)
1. **No routing priority in Claude Code** — skill matching is LLM-based, not prioritized. Need exclusion language.
2. **No state passing between skills** — handoff from ecosystem to credential skill relies on the user re-stating context.
3. **"Auto-trigger" is not a real Claude Code feature** — best-practices skill must rely on description matching.
4. **Phase numbering confusion** in credential skill rewrite needs definitive new numbering.

## Overview

Restructure the agent-infra-security skill set into a clean layered architecture: ecosystem-specific skills handle deep incident response, a generic skill serves as the fallback, a best-practices skill proactively catches preventable issues, and a credential skill owns the full detection-to-rotation lifecycle. Add npm ecosystem support triggered by the Axios supply chain compromise (2026-03-31).

## Problem Statement

1. `supply-chain-security-check` claims multi-ecosystem support but is Python-only (hardcoded `pip`, `pipdeptree`, `litellm` patterns)
2. Credential rotation is duplicated across 3 skills (~210 lines total) with no single owner
3. No npm coverage despite npm being the largest attack surface (Axios: 80M weekly downloads, compromised today)
4. No proactive prevention skill — all skills are reactive (incident already happened)

## Architecture

```
┌─────────────────────────────────────────────────────┐
│              supply-chain-best-practices             │
│         (proactive, ecosystem-aware prevention)      │
└─────────────────────────────────────────────────────┘
                         ▲ auto-triggers on risky patterns

┌──────────────┐ ┌──────────────┐ ┌──────────────────┐
│ pypi-supply- │ │ npm-supply-  │ │ github-actions-  │
│ chain-       │ │ chain-       │ │ supply-chain-    │
│ response     │ │ response     │ │ response         │
│              │ │ (NEW)        │ │                  │
└──────┬───────┘ └──────┬───────┘ └────────┬─────────┘
       │                │                   │
       │   "For credential rotation, use    │
       │    credential-exfiltration-response"│
       ▼                ▼                   ▼
┌─────────────────────────────────────────────────────┐
│          credential-exfiltration-response            │
│   (detection phases 1-4 + NEW rotation phases 5-6)  │
│         supports dual entry: detect-first OR         │
│              skip-to-rotation                        │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│            supply-chain-security-check               │
│  (REWRITTEN: truly generic, ecosystem-agnostic       │
│   fallback for Go, Rust, Ruby, Java, Docker, etc.)   │
└─────────────────────────────────────────────────────┘
```

**Routing:** Ecosystem-specific skills trigger directly for known ecosystems. `supply-chain-security-check` is the catch-all fallback.

**Routing implementation (from architecture + spec-flow review):**
- Claude Code skill matching is LLM-based on the `description` field — there is no priority system
- To enforce "specific-first, generic fallback": the generic skill's description MUST include exclusion language: "Do NOT use this skill for npm, PyPI, or GitHub Actions — use the dedicated ecosystem skill instead."
- The generic skill should also include a redirect instruction: if the user describes a covered ecosystem, say so and offer to defer to the ecosystem-specific skill
- Consider adding a routing preamble to `CATALOG.md` that lists ecosystem → skill mappings
- "Auto-trigger" for best-practices means the skill description is written to match when the LLM notices risky patterns — there is no background scanning mechanism in Claude Code

## Implementation Phases

### Phase 1: Build `npm-supply-chain-response` (URGENT — Axios is active)

**Priority: Highest.** The Axios compromise is happening today (2026-03-31). This skill needs to ship first.

**Structure mirrors `pypi-supply-chain-response`:**

#### `skills/npm-supply-chain-response/SKILL.md`

- Frontmatter with npm-specific trigger phrases: "compromised npm package", "axios compromised", "malicious npm dependency", "postinstall backdoor", "plain-crypto-js"
- Three output modes: interactive checklist, full runbook, shell script
- Context gathering: package name, compromised versions, safe version, attack window, IOCs

**Six phases:**

1. **Exposure check** — Search lockfiles (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lockb`) and `node_modules/` for the compromised package. Check transitive dependencies via `npm ls`. Hunt across all environments including global installs, npm cache, CI runners, Docker images.
   ```bash
   npm ls <PACKAGE> 2>/dev/null
   yarn why <PACKAGE> 2>/dev/null
   pnpm why <PACKAGE> 2>/dev/null
   grep -rn "<PACKAGE>" package-lock.json yarn.lock pnpm-lock.yaml 2>/dev/null
   find / -path "*/node_modules/<PACKAGE>" -type d 2>/dev/null
   # npm cache ls was REMOVED in npm 7+. Search the content-addressable store directly:
   grep -r '<PACKAGE>' ~/.npm/_cacache/index-v5/ 2>/dev/null
   npm ls -g --depth=0 2>/dev/null | grep "<PACKAGE>"
   ```
   **Monorepo support:** For workspaces, run `npm ls` from the workspace root AND individual packages. Lockfiles may exist at multiple levels.

2. **Version confirmation** — Confirm installed version matches compromised version. Check `node_modules/<PACKAGE>/package.json` for version field. Check file timestamps.
   ```bash
   cat node_modules/<PACKAGE>/package.json | grep '"version"'
   stat node_modules/<PACKAGE>/package.json
   ```

3. **IOC hunting** — npm-specific patterns:
   - Check for `postinstall` scripts across ALL installed packages (not just the compromised one — typosquatted deps carry the payload):
     ```bash
     npm query ':attr(scripts, [postinstall])' | jq '.[].name'
     ```
   - Anti-forensics detection: look for `package.md` alongside `package.json` (the Axios attack swaps these to hide evidence)
   - Filesystem IOCs per platform (macOS: `/Library/Caches/com.apple.act.mond`, Windows: `%PROGRAMDATA%\wt.exe`, Linux: `/tmp/ld.py`)
   - Network IOCs: C2 domain connections
   - Process inspection for background payloads
   - Environment-gated payloads: check if payload only fires in CI (`CI=true`, `GITHUB_ACTIONS`)
   ```bash
   # Scan ALL packages for lifecycle scripts (broader than single package check)
   find node_modules -maxdepth 2 -name package.json \
     -exec grep -l '"preinstall\|postinstall\|preuninstall"' {} \;
   # Anti-forensics: package.md swap
   ls node_modules/<MALICIOUS_DEP>/package.md 2>/dev/null
   # Compare scripts field on disk vs what npm query reports (detect post-install tampering)
   # Platform-specific IOCs
   ls -la /Library/Caches/com.apple.act.mond 2>/dev/null  # macOS
   ls -la /tmp/ld.py 2>/dev/null  # Linux
   ```

4. **Containment** — Remove compromised package, purge npm cache, pin safe version. Preserve evidence first.
   ```bash
   npm cache clean --force
   rm -rf node_modules/<MALICIOUS_DEP>
   npm install <PACKAGE>@<SAFE_VERSION> --save-exact
   ```

5. **Credential rotation** — **Explicit handoff:** "For credential rotation and abuse detection, use the `credential-exfiltration-response` skill. Tell it which credential types were accessible on the compromised system."

6. **Prevention** — npm-specific:
   - `npm install --save-exact` for pinning
   - `npm ci` (strict lockfile) vs `npm install` (updates lockfile)
   - `--ignore-scripts` in CI with selective `npm rebuild` for trusted native deps (sharp, esbuild)
   - `npm audit` in CI (CVEs only) + Socket.dev for behavioral supply chain detection
   - Corepack for package manager version pinning (stable since Node 20+)
   - `npm audit signatures` to verify package provenance (Sigstore-based, GA since npm 9.5+)
   - `npm publish --provenance` for publishing your own packages (requires `id-token: write` in GitHub Actions)
   - Lockfile lint: `npx lockfile-lint --path package-lock.json --type npm --allowed-hosts npm`

#### `skills/npm-supply-chain-response/references/ioc-patterns.md`

Axios-specific IOCs plus generic npm attack patterns:
- C2: `sfrclak.com:8000`, campaign ID `6202033`
- Attacker email: `ifstap@proton.me`
- XOR key: `OrDeR_7077`
- Malicious package: `plain-crypto-js` (4.2.0, 4.2.1)
- Platform payloads: macOS (`com.apple.act.mond`), Windows (`wt.exe`, VBS/PS1 dropper), Linux (`ld.py`)
- Anti-forensics: `setup.js` self-deletion via `fs.unlink(__filename)`, `package.md` → `package.json` swap
- Generic npm patterns: `postinstall` script abuse, typosquatted dependency injection

#### `skills/npm-supply-chain-response/scripts/check_npm_compromise.sh`

Automated checker following the same pattern as `check_compromise_template.sh`:
- Color-coded output, `--dry-run` flag, confirmation prompts
- Takes package name and org as arguments
- Scans lockfiles, node_modules, npm cache
- Checks for platform-specific IOCs

#### `skills/npm-supply-chain-response/README.md`

Standalone usage docs, same pattern as other skill READMEs.

---

### Phase 2: Expand `credential-exfiltration-detection` → `credential-exfiltration-response`

**What changes:**
- Rename skill directory: `credential-exfiltration-detection/` → `credential-exfiltration-response/`
- Rename in SKILL.md frontmatter: `name: credential-exfiltration-response`
- Update description to include rotation trigger phrases
- Add Phase 5 (Credential Rotation) and Phase 6 (Verify Rotation)
- Support dual entry point in skill instructions

**New phases to add:**

**Phase 5: Credential Rotation**

Move and consolidate credential rotation content from `pypi-supply-chain-response` (Phase 5) and `github-actions-supply-chain-response` (Phase 5). Organize by credential class:

- SSH keys: regenerate, update authorized_keys
- AWS: rotate access keys, invalidate sessions
- GCP: revoke, regenerate service account keys
- Azure: rotate service principal secrets
- Kubernetes: regenerate kubeconfig, rotate service account tokens
- Git credentials: credential reject, rotate PATs
- Package registry tokens: PyPI, npm, Docker Hub
- Database passwords
- CI/CD secrets (GitHub Actions, GitLab CI)
- .env file secrets
- Crypto wallets

Each credential class gets:
- Detection command (do you have this?)
- Rotation command (how to rotate)
- Verification command (confirm old one is dead)

**Research insights for rotation:**
- **AWS STS critical gotcha:** Sessions survive key deletion for up to 36 hours. Must deploy an inline deny-all policy with `aws:TokenIssueTime` condition to immediately invalidate. Remove the policy after 36 hours. This is the ONLY reliable way to kill existing STS tokens.
- **GCP:** Key deletion is immediate — no delayed invalidation window.
- **GitHub:** PAT revocation is immediate. GitHub App installation tokens expire in 1 hour. `GITHUB_TOKEN` is scoped per workflow run — no rotation needed, but audit permissions.
- **npm:** Token revocation is immediate. Use `npm token list` / `npm token revoke`.
- **Verification pattern (universal):** Attempt an authenticated API call with the OLD credential, confirm 401/403.
- **Provider-specific delays:**
  | Provider | Delay | Mitigation |
  |----------|-------|------------|
  | AWS STS | Up to 36h | Deny policy with `aws:TokenIssueTime` |
  | GCP | None | Key deletion is immediate |
  | GitHub | PATs immediate; Apps up to 1h | Wait for expiry |
  | npm | None | Revocation is immediate |

**Phase 6: Verify Rotation** (existing Phase 4 content, renumbered)

Current Phase 4 (verify rotation completeness) becomes Phase 6.

**Dual entry point instruction in SKILL.md:**

> If the user already knows which credentials are compromised (e.g., they completed an ecosystem-specific skill's investigation), skip Phases 1-3 and start at Phase 4 (current Phase 3: lateral movement) or Phase 5 (rotation). Ask the user: "Do you already know which credentials were exposed, or do you need to scope and detect first?"

**Update important notes:**

Remove: "This skill does NOT include credential rotation steps."
Add: "This skill handles the full credential lifecycle: detection, lateral movement analysis, rotation, and verification."

**Files changed:**
- `skills/credential-exfiltration-response/SKILL.md` (renamed + expanded)
- `skills/credential-exfiltration-response/references/cloud-audit-queries.md` (unchanged, moved)
- `skills/credential-exfiltration-response/references/credential-scope-checklist.md` (unchanged, moved)
- `skills/credential-exfiltration-response/references/rotation-checklists.md` (NEW — per-credential-class rotation commands)

---

### Phase 3: Update Ecosystem Skills (Remove Rotation, Add Handoffs)

**`skills/pypi-supply-chain-response/SKILL.md`:**
- Replace Phase 5 (Credential Rotation, ~60 lines of rotation commands) with explicit handoff:
  > **Phase 5: Credential rotation**
  > Assume everything on the compromised system is burned. For systematic credential rotation and abuse detection, use the `credential-exfiltration-response` skill. Tell it which credential types were accessible — it will walk through rotation for each class and verify the old credentials are invalidated.
- Keep Phase 6 (Prevention) as-is — it's PyPI-specific
- Remove the "Post-rotation audit" subsection from Phase 5 (now in credential skill)

**`skills/github-actions-supply-chain-response/SKILL.md`:**
- Same treatment: replace Phase 5 rotation commands with handoff to `credential-exfiltration-response`
- Keep Phase 6 (Prevention) as-is — it's GitHub Actions-specific
- Keep the "List all secrets accessible to affected workflows" commands in Phase 5 — those are about scoping what CI secrets exist, which feeds into the credential skill

**Files changed:**
- `skills/pypi-supply-chain-response/SKILL.md`
- `skills/github-actions-supply-chain-response/SKILL.md`

---

### Phase 4: Rewrite `supply-chain-security-check` as Truly Generic

**What changes:**
- Strip ALL Python-specific content (pip, pipdeptree, litellm, .pth patterns, site-packages)
- Strip all hardcoded package names
- Keep the 7-phase workflow structure but make each phase ecosystem-agnostic
- Use placeholder syntax for ecosystem-specific commands

**Rewritten phases (ecosystem-agnostic):**

1. **Confirm incident facts** — Collect: package name, ecosystem, bad versions, attack window, IOCs, official guidance. (Unchanged)

2. **Find direct references in source** — Search for ALL lockfile/manifest formats (already lists them: requirements.txt, package-lock.json, go.mod, Cargo.lock, etc.). Remove the Python-heavy default commands section.

3. **Find transitive use in built environments** — Generic instructions: "Check the installed environment for the package. Use the ecosystem's dependency tree tool to find what pulled it in." Provide a table of commands per ecosystem instead of inline Python commands:
   | Ecosystem | List packages | Dependency tree | Show package |
   |-----------|--------------|-----------------|--------------|
   | Python | `pip list` | `pipdeptree -r -p PKG` | `pip show PKG` |
   | Node | `npm ls` | `npm ls PKG` | `npm ls PKG --json` |
   | Go | `go list -m all` | `go mod graph` | `go list -m PKG` |
   | Rust | `cargo tree` | `cargo tree -i PKG` | — |
   | Ruby | `gem list` | `bundle show` | `gem info PKG` |
   | Java | `mvn dependency:tree` | `mvn dependency:tree -Dincludes=PKG` | — |

4. **Hunt for IOCs** — Generic patterns: unusual files, suspicious network connections, background processes, persistence mechanisms. Remove litellm-specific `.pth` checks. Keep generic .pth detection for Python but label it as Python-specific.

5. **Classify impact** — Five levels (unchanged, already generic)

6. **Recommend actions** — Generic containment, explicit handoff to `credential-exfiltration-response` for rotation. Remove the inline credential rotation checklists.

7. **Prevention** — Generic principles: pin exact versions, use lockfiles with hashes, run vulnerability scanners in CI, scope CI secrets, use OIDC/Trusted Publishing. Remove Python-only commands.

**Update default investigation commands** — Replace the Python-only section with a multi-ecosystem quick reference table.

**Files changed:**
- `skills/supply-chain-security-check/SKILL.md` (rewrite)

---

### Phase 5: Create `supply-chain-best-practices` (Proactive)

**New skill:** `skills/supply-chain-best-practices/`

**SKILL.md frontmatter:**
- Proactive description: "Detect and fix supply chain security weaknesses before they're exploited. Auto-triggers when risky patterns are found: unpinned dependencies, missing lockfile hashes, workflow-level CI secrets, no SBOM, mutable GitHub Action tags."
- Trigger phrases: "harden dependencies", "supply chain best practices", "dependency security audit", "pin my dependencies"

**Skill content — ecosystem-aware checks:**

The skill inspects the current project and produces findings + fixes for:

1. **Dependency pinning** — Scan for unpinned or loosely pinned deps
   - Python: `>=`, `~=`, no version in requirements.txt
   - Node: `^`, `~`, `*` in package.json
   - Go: check go.mod for `latest`
   - GitHub Actions: tag-based references vs SHA-pinned

2. **Lockfile integrity** — Check for presence and hash verification
   - Python: `pip-compile --generate-hashes`, `uv pip compile --generate-hashes`
   - Node: `npm ci` (uses lockfile strictly), `package-lock.json` presence
   - Go: `go.sum` presence
   - Rust: `Cargo.lock` presence and committed

3. **CI secret scoping** — Check for workflow-level secrets vs step-level
   - GitHub Actions: `env:` at workflow level vs per-step `with:`
   - Recommend OIDC over long-lived credentials

4. **SBOM generation** — Check for existing SBOM, recommend generation
   - Python: `cyclonedx-bom`
   - Node: `cyclonedx-npm`
   - Generic: `syft`

5. **Vulnerability scanning** — Check for CI integration
   - Python: `pip-audit`
   - Node: `npm audit`
   - Generic: `osv-scanner`

6. **Trusted Publishing / provenance** — Check if packages are published with OIDC
   - PyPI: Trusted Publishing
   - npm: npm provenance
   - GitHub Actions: SLSA provenance

**Output:** Findings table with severity, specific fix commands, and a summary score.

**Files:**
- `skills/supply-chain-best-practices/SKILL.md`
- `skills/supply-chain-best-practices/references/pinning-guide.md` (per-ecosystem pinning commands)
- `skills/supply-chain-best-practices/README.md`

---

### Phase 6: Update Catalog, Manifests, README

**`CATALOG.md`:**
- Add `npm-supply-chain-response` entry with trigger phrases
- Add `supply-chain-best-practices` entry with trigger phrases
- Update `credential-exfiltration-detection` → `credential-exfiltration-response` (name, description, trigger phrases)
- Update `supply-chain-security-check` description to reflect generic rewrite

**`.claude-plugin/marketplace.json` and `.claude-plugin/plugin.json`:**
- Bump version to 2.0.0 (breaking: renamed skill, new architecture)
- Skills auto-discovered from `skills/` directory (no explicit listing needed per compound-engineering pattern)

**`README.md`:**
- Update skill inventory table
- Update architecture description
- Add Axios to the "built in response to" section
- Update sample prompts

---

## Acceptance Criteria

### Functional Requirements

- [ ] `npm-supply-chain-response` skill triggers on "axios got compromised" and walks through 6-phase investigation
- [ ] `npm-supply-chain-response` produces all 3 output modes (checklist, runbook, script)
- [ ] `npm-supply-chain-response` includes Axios-specific IOCs (sfrclak.com, plain-crypto-js, platform payloads)
- [ ] `credential-exfiltration-response` handles both entry points: detect-first and skip-to-rotation
- [ ] `credential-exfiltration-response` includes complete rotation checklists for all credential classes
- [ ] `pypi-supply-chain-response` Phase 5 hands off to credential skill (no inline rotation)
- [ ] `github-actions-supply-chain-response` Phase 5 hands off to credential skill (no inline rotation)
- [ ] `supply-chain-security-check` contains zero Python-specific hardcoded commands
- [ ] `supply-chain-security-check` has multi-ecosystem command reference table
- [ ] `supply-chain-best-practices` auto-triggers on risky dependency patterns
- [ ] `supply-chain-best-practices` checks pinning, lockfiles, CI secrets, SBOM, vuln scanning
- [ ] All skills discoverable via `/skills` as `(agent-infra-security)`
- [ ] CATALOG.md updated with all 6 skills

### Quality Gates

- [ ] No credential rotation content duplicated across skills (single owner: credential-exfiltration-response)
- [ ] No ecosystem-specific commands in supply-chain-security-check
- [ ] All IOC data verified against source (Elastic Security gist for Axios)
- [ ] No fabricated values — all emails, URLs, hashes verified against git or source material

## References

### Internal

- Brainstorm: `docs/brainstorms/2026-03-31-skill-architecture-brainstorm.md`
- Existing pypi skill: `skills/pypi-supply-chain-response/SKILL.md`
- Existing credential skill: `skills/credential-exfiltration-detection/SKILL.md`
- Existing github-actions skill: `skills/github-actions-supply-chain-response/SKILL.md`
- Existing generic skill: `skills/supply-chain-security-check/SKILL.md`

### External

- Axios compromise report: https://gist.github.com/joe-desimone/36061dabd2bc2513705e0d083a9673e7
- Compound-engineering plugin structure (reference for manifests): `~/.claude/plugins/cache/every-marketplace/compound-engineering/`
