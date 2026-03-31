# supply-chain-best-practices

Proactively audit and harden dependency management against supply chain attacks.

## What it does

Nine-category security audit: version pinning, lockfile integrity, install hooks, vulnerability scanning, provenance/signing, CI secret scoping, SBOM generation, update strategy, and package manager hardening.

Produces a checklist report with PASS/WARN/FAIL for each category and prioritized remediation actions.

## When to use

- Setting up a new project
- Auditing an existing project's dependency hygiene
- After an industry supply chain incident (even if you weren't affected)
- When reviewing CI/CD pipeline security

This skill is **preventive**. For active incident response, use the ecosystem-specific skills (`npm-supply-chain-response`, `pypi-supply-chain-response`, etc.).

## Install as a Claude skill

Point your Claude skill path at this directory.

## License

MIT
