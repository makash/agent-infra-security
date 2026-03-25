# pypi-supply-chain-response

Triage, investigate, and recover from a compromised Python package on PyPI.

Built in response to the [LiteLLM supply chain attack](https://futuresearch.ai/blog/litellm-pypi-supply-chain-attack/) (March 24, 2026). Generic enough for any PyPI compromise.

## What it does

Six-phase incident response: exposure check, version confirmation, IOC hunting, containment, credential rotation, prevention.

Three output modes: interactive triage checklist (default), full incident response runbook (markdown), or automated shell script with `--dry-run` support.

## Install as a Claude skill

Point your Claude skill path at this directory, or download the `.skill` bundle from [Releases](../../releases).

## Use the shell script standalone

No Claude required. Edit the configuration variables at the top for your incident, then run:

```bash
export COMPROMISED_VERSIONS="1.82.7 1.82.8"
export SAFE_VERSION="1.82.6"
export C2_DOMAINS="models.litellm.cloud checkmarx.zone"
export PERSISTENCE_PATHS="~/.config/sysmon/sysmon.py ~/.config/systemd/user/sysmon.service"
export MALICIOUS_FILES="litellm_init.pth"

./scripts/check_compromise_template.sh litellm
./scripts/check_compromise_template.sh litellm --dry-run
```

## Quick manual check

```bash
pip show <PACKAGE>                      # installed? what version?
pipdeptree -r -p <PACKAGE>              # what pulled it in?
find / -path "*/site-packages/<PACKAGE>" -type d 2>/dev/null  # other envs?
pip cache list <PACKAGE>                # cached wheels?
```

## Contents

```
pypi-supply-chain-response/
├── SKILL.md                            # Claude skill instructions
├── README.md                           # This file
├── references/
│   └── ioc-patterns.md                 # IOC pattern library
└── scripts/
    └── check_compromise_template.sh    # Standalone bash checker
```
