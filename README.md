# agent-infra-security

Claude skills and standalone tools for securing AI agent infrastructure.

Every skill in this repo works two ways: as a Claude skill you can install and trigger conversationally, and as a standalone resource (scripts, runbooks, IOC libraries) you can use without Claude at all.

## Skills

| Skill | What it does | Standalone tools |
|-------|-------------|-----------------|
| [pypi-supply-chain-response](skills/pypi-supply-chain-response/) | Triage and recover from a compromised Python package on PyPI | `check_compromise_template.sh`, IOC pattern library |

## Why this exists

AI agent infrastructure has a supply chain problem. Packages like LiteLLM sit at the center of the AI stack, routing API keys for dozens of LLM providers, and they're pulled in as transitive dependencies by frameworks most developers don't audit. When one of these packages gets compromised, the blast radius is enormous and the response playbook doesn't exist in most organizations.

This repo collects the response playbooks, detection scripts, and Claude skills that fill that gap. Each skill encodes the kind of triage process a security engineer would walk you through, except it's available to any developer at 2am when the advisory drops.

## Using the skills

### As Claude skills

Each skill directory contains a `SKILL.md` that Claude reads when triggered. Point your skill path at the specific skill directory, or install a packaged `.skill` bundle from [Releases](../../releases).

Trigger phrases are listed in each skill's `SKILL.md` frontmatter. For example, `pypi-supply-chain-response` triggers on anything from "litellm got compromised" to "how do I check if my pip dependencies are backdoored."

### As standalone tools

Every skill ships scripts and references that work without Claude. Check each skill's README for usage. Shell scripts include `--dry-run` flags and confirmation prompts before destructive actions.

## Contributing

If you've been through an incident and have a playbook worth encoding, open a PR. The structure for a new skill:

```
skills/<skill-name>/
├── SKILL.md              # Required. Claude instructions + YAML frontmatter.
├── README.md             # Required. Standalone usage docs.
├── references/           # Optional. IOC libraries, pattern files, reference docs.
└── scripts/              # Optional. Standalone scripts that work without Claude.
```

The `SKILL.md` frontmatter needs a `name` and `description`. The description controls when Claude triggers the skill, so make it specific about the contexts where the skill is useful.

## Repo structure

```
agent-infra-security/
├── README.md                                    # This file
├── LICENSE                                      # MIT
├── CATALOG.md                                   # Skill index with descriptions
└── skills/
    └── pypi-supply-chain-response/              # First skill
        ├── SKILL.md
        ├── README.md
        ├── references/
        │   └── ioc-patterns.md
        └── scripts/
            └── check_compromise_template.sh
```

## License

MIT
