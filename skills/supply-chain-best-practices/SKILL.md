---
name: supply-chain-best-practices
description: Proactively audit and harden dependency management against supply chain attacks. Use this skill when a user asks about securing their dependencies, hardening their CI/CD pipeline against supply chain attacks, auditing their lockfiles or dependency pins, setting up SBOM generation, implementing dependency signing or provenance verification, or preventing the next supply chain compromise. Also trigger proactively when reviewing dependency configuration files (package.json, requirements.txt, Gemfile, go.mod, Cargo.toml, pom.xml) and noticing risky patterns like unpinned versions, missing lockfiles, or postinstall scripts. This skill is preventive — for active incident response, use the ecosystem-specific skills instead.
license: MIT
compatibility: Requires Bash. Ecosystem-specific tools as needed (npm, pip, cargo, go, bundle, etc.).
---

# Supply Chain Best Practices

Proactively audit and harden your project's dependency management to prevent supply chain attacks.

**This skill is preventive, not reactive.** For active incident response (compromised package, IOC hunting, credential rotation), use the ecosystem-specific skills: `npm-supply-chain-response`, `pypi-supply-chain-response`, `github-actions-supply-chain-response`, or the generic `supply-chain-security-check`.

## When to use

- Setting up a new project and want secure defaults
- Auditing an existing project's dependency hygiene
- Reviewing CI/CD pipeline security
- After an industry supply chain incident (even if you weren't affected) — learn from it
- When you notice risky patterns in dependency files during code review

## Audit checklist

Walk the user through each category. Adapt commands to the detected ecosystem(s) in the project.

### 1. Version pinning

**Goal:** Every dependency resolves to exactly one version. No ranges, no floating tags.

| Ecosystem | Risky pattern | Safe pattern |
|-----------|--------------|-------------|
| npm | `"axios": "^1.14.0"` or `"~1.14.0"` | `"axios": "1.14.0"` (use `--save-exact`) |
| Python | `requests>=2.28` or `requests` | `requests==2.28.0` |
| Ruby | `gem 'rails', '~> 7.0'` | `gem 'rails', '7.0.8'` |
| Go | Uses `go.sum` for integrity (automatic) | Verify `go.sum` is committed |
| Rust | `serde = "1"` (allows minor bumps) | `serde = "=1.0.197"` |
| Java | `<version>[1.0,2.0)</version>` | `<version>1.0.3</version>` |
| .NET | `Version="1.*"` | `Version="1.2.3"` |
| GitHub Actions | `uses: actions/checkout@v4` | `uses: actions/checkout@<SHA> # v4.1.1` |

**Audit commands:**
```bash
# npm — find non-exact versions
grep -E '"\^|"~|">=|">' package.json

# Python — find unpinned or range-pinned
grep -vE '==|#|^$|^-' requirements.txt 2>/dev/null

# GitHub Actions — find tag-based references
grep -rn 'uses:.*@v' .github/workflows/ 2>/dev/null
grep -rn 'uses:.*@main' .github/workflows/ 2>/dev/null
```

### 2. Lockfile integrity

**Goal:** Lockfiles exist, are committed, and used in CI.

| Ecosystem | Lockfile | CI command (lockfile-only) |
|-----------|---------|--------------------------|
| npm | `package-lock.json` | `npm ci` (not `npm install`) |
| Yarn | `yarn.lock` | `yarn install --frozen-lockfile` |
| pnpm | `pnpm-lock.yaml` | `pnpm install --frozen-lockfile` |
| Python (pip-tools) | `requirements.txt` (compiled) | `pip install -r requirements.txt` |
| Python (uv) | `uv.lock` | `uv sync --frozen` |
| Python (Poetry) | `poetry.lock` | `poetry install --no-update` |
| Ruby | `Gemfile.lock` | `bundle install --frozen` |
| Go | `go.sum` | `go mod verify` |
| Rust | `Cargo.lock` | Commit `Cargo.lock` for binaries |

**Lockfiles with hashes** (stronger — detects tampered packages):
```bash
# Python
pip-compile --generate-hashes requirements.in
uv pip compile --generate-hashes requirements.in

# npm
# package-lock.json includes integrity hashes by default

# Lockfile lint (npm)
npx lockfile-lint --path package-lock.json --type npm --allowed-hosts npm
```

**Audit:**
```bash
# Check if lockfiles exist and are committed
git ls-files | grep -iE 'lock|\.sum$'

# Check CI for lockfile-only commands
grep -rn 'npm ci\|--frozen-lockfile\|--no-update\|go mod verify' .github/workflows/ .gitlab-ci.yml Jenkinsfile 2>/dev/null
```

### 3. Install hooks and scripts

**Goal:** Disable automatic execution of arbitrary code during package install.

**npm postinstall** — the primary vector for npm supply chain attacks:
```bash
# Disable globally
npm config set ignore-scripts true

# Or in .npmrc (committed to repo)
echo "ignore-scripts=true" >> .npmrc

# Then selectively rebuild trusted native deps
npm rebuild sharp esbuild

# Audit which packages have postinstall
npm query ':attr(scripts, [postinstall])' 2>/dev/null | jq '.[].name'
```

**Python .pth files** — execute on every interpreter startup:
```bash
SITE=$(python -c "import site; print(site.getsitepackages()[0])")
find "$SITE" -name "*.pth" -exec grep -l "base64\|subprocess\|exec\|eval\|compile" {} \;
```

**Ruby extconf.rb** — native extension build scripts:
```bash
find vendor/bundle -name "extconf.rb" 2>/dev/null | head -20
```

### 4. Vulnerability scanning in CI

**Goal:** Automated checks on every PR and scheduled scans.

```yaml
# GitHub Actions example — npm
- run: npm audit --omit=dev

# GitHub Actions example — Python
- run: pip-audit

# GitHub Actions example — Go
- run: govulncheck ./...

# GitHub Actions example — Rust
- run: cargo audit

# GitHub Actions example — Ruby
- run: bundle audit check --update
```

**Multi-ecosystem with Trivy:**
```yaml
- uses: aquasecurity/trivy-action@<SHA>
  with:
    scan-type: 'fs'
    scan-ref: '.'
```

### 5. Provenance and signing

**Goal:** Verify packages come from who they claim to come from.

**npm provenance:**
```bash
# Verify signatures on installed packages
npm audit signatures

# Publish your own packages with provenance
# In GitHub Actions:
# permissions:
#   id-token: write
#   contents: read
# - run: npm publish --provenance
```

**Python Trusted Publishing:**
- Use OIDC tokens from GitHub Actions instead of long-lived PyPI API tokens
- Configure at pypi.org/manage/project/<PROJECT>/settings/publishing/

**Sigstore (multi-ecosystem):**
```bash
# Sign
cosign sign-blob --yes artifact.tar.gz

# Verify
cosign verify-blob artifact.tar.gz --signature artifact.tar.gz.sig --certificate artifact.tar.gz.pem
```

**Container image signing:**
```bash
# Sign
cosign sign <IMAGE_DIGEST>

# Verify
cosign verify <IMAGE_DIGEST>
```

### 6. CI/CD secret scoping

**Goal:** Minimize blast radius if a dependency runs malicious code during install.

**Don't do this:**
```yaml
env:
  AWS_ACCESS_KEY_ID: ${{ secrets.AWS_KEY }}
  AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET }}

steps:
  - run: npm ci          # <-- every step has cloud credentials
  - run: npm test
  - run: npm run deploy
```

**Do this instead:**
```yaml
steps:
  - run: npm ci           # No secrets
  - run: npm test         # No secrets
  - run: npm run deploy
    env:
      AWS_ACCESS_KEY_ID: ${{ secrets.AWS_KEY }}
      AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET }}
```

**Use OIDC instead of long-lived credentials:**
```yaml
permissions:
  id-token: write
  contents: read

- uses: aws-actions/configure-aws-credentials@<SHA>
  with:
    role-to-assume: arn:aws:iam::123456789:role/deploy
    aws-region: us-east-1
```

**Use GitHub Environments** with protection rules to gate access to production secrets.

### 7. SBOM generation

**Goal:** Know your full dependency tree so you can answer "am I affected?" in seconds.

```bash
# Python
pip install cyclonedx-bom
cyclonedx-py requirements -i requirements.txt -o sbom.json

# npm
npx @cyclonedx/cyclonedx-npm --output-file sbom.json

# Go
cyclonedx-gomod mod -json -output sbom.json

# Rust
cargo cyclonedx

# Multi-ecosystem with Syft
syft . -o cyclonedx-json > sbom.json
```

Store SBOMs as CI artifacts. When the next advisory drops, grep the SBOM instead of auditing every environment.

### 8. Dependency update strategy

**Goal:** Stay current without exposing yourself to zero-day compromises.

- **Dependabot / Renovate** for automated PRs with version bumps
- **Review changelogs** before merging dependency updates
- **Delay adoption** of new major versions by 48-72 hours (most supply chain attacks are caught within this window)
- **For uv users:** `--exclude-newer` to freeze the supply chain timeline:
  ```bash
  uv pip install --exclude-newer "2026-03-28T00:00:00Z" <PACKAGE>
  ```

### 9. Package manager hardening

**npm:**
```ini
# .npmrc
ignore-scripts=true
audit=true
fund=false
```

**pip:**
```bash
# Require hashes for all installs
pip install --require-hashes -r requirements.txt
```

**Corepack (Node.js):**
```bash
corepack enable
corepack prepare npm@10.9.0 --activate
```
Prevents a compromised global npm binary from being used.

## Output format

Produce a **checklist report** for the project:

```markdown
## Supply Chain Security Audit — [Project Name]

### Version Pinning: [PASS/WARN/FAIL]
- [Details]

### Lockfile Integrity: [PASS/WARN/FAIL]
- [Details]

### Install Hooks: [PASS/WARN/FAIL]
- [Details]

### Vulnerability Scanning: [PASS/WARN/FAIL]
- [Details]

### Provenance/Signing: [PASS/WARN/FAIL]
- [Details]

### CI Secret Scoping: [PASS/WARN/FAIL]
- [Details]

### SBOM: [PASS/WARN/FAIL]
- [Details]

### Update Strategy: [PASS/WARN/FAIL]
- [Details]

### Package Manager Hardening: [PASS/WARN/FAIL]
- [Details]

### Recommended Actions (priority order)
1. [Most critical fix]
2. [Next fix]
...
```

## Important notes

- This skill is preventive. Don't use it during an active incident — use the ecosystem-specific response skills.
- Not every project needs every hardening measure. Prioritize based on the project's risk profile: public-facing services need more than internal tools.
- Version pinning without lockfile integrity is incomplete — an attacker can publish a new version matching your pin if you don't verify hashes.
- The biggest bang for the buck is usually: exact version pins + lockfile with hashes + `ignore-scripts` in npm + scoped CI secrets. Start there.
