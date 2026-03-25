# IOC Pattern Library for PyPI Supply Chain Attacks

This reference contains common indicators of compromise seen across Python package supply chain attacks. Use these as a baseline when attack-specific IOCs are not available from an advisory.

## Payload delivery mechanisms

**.pth files** — The most dangerous vector. Python executes `.pth` files in `site-packages/` automatically at interpreter startup via `site.py`. No import required. Even running `pip`, `python -c`, or an IDE language server triggers them.

Detection:
```bash
SITE=$(python -c "import site; print(site.getsitepackages()[0])")
find "$SITE" -name "*.pth" -exec grep -l "base64\|subprocess\|exec\|eval\|compile\|import os\|import sys" {} \;
```
Legitimate `.pth` files exist (e.g., `distutils-precedence.pth`, `easy-install.pth`) but they contain simple path entries, not code execution patterns.

**setup.py / pyproject.toml install hooks** — Malicious code in `setup()` runs during `pip install`. Look for `cmdclass` overrides or `subprocess` calls in setup scripts.

**Obfuscated payloads in source files** — Base64-encoded strings, `exec()`/`eval()` calls, `compile()` with encoded data. Common in `__init__.py` or deep module files.

Detection:
```bash
# Search installed package source for obfuscation patterns
PKGDIR=$(python -c "import <PACKAGE>; import os; print(os.path.dirname(<PACKAGE>.__file__))")
grep -rn "base64\|exec(\|eval(\|compile(\|__import__\|subprocess" "$PKGDIR" --include="*.py"
```

## Persistence mechanisms

**systemd user services** — Drops a `.service` file that auto-starts a Python backdoor.
```bash
find ~/.config/systemd/user/ -name "*.service" -mtime -7 2>/dev/null
systemctl --user list-units --type=service --state=running
```

**Cron jobs:**
```bash
crontab -l 2>/dev/null
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ 2>/dev/null
```

**Python scripts in config directories:**
```bash
find ~/.config -name "*.py" -mtime -7 2>/dev/null
find ~/.local/bin -name "*.py" -mtime -7 2>/dev/null
```

**XDG autostart entries:**
```bash
find ~/.config/autostart -name "*.desktop" -mtime -7 2>/dev/null
```

## Credential harvesting targets

These are the files and locations that supply chain malware typically sweeps. If the compromised version was installed, assume all of these were read and exfiltrated.

**SSH keys:**
- `~/.ssh/id_rsa`, `~/.ssh/id_ed25519`, `~/.ssh/id_ecdsa` and their `.pub` counterparts
- `~/.ssh/config`, `~/.ssh/known_hosts`

**Cloud credentials:**
- AWS: `~/.aws/credentials`, `~/.aws/config`, env vars `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`
- GCP: `~/.config/gcloud/application_default_credentials.json`, `~/.config/gcloud/credentials.db`
- Azure: `~/.azure/accessTokens.json`, `~/.azure/azureProfile.json`

**Kubernetes:**
- `~/.kube/config`
- In-cluster service account token at `/var/run/secrets/kubernetes.io/serviceaccount/token`

**Environment variables and .env files:**
- `.env`, `.env.local`, `.env.production` in project directories
- Shell history: `~/.bash_history`, `~/.zsh_history` (may contain tokens passed as CLI args)

**Git credentials:**
- `~/.gitconfig` (may contain tokens in URL)
- `~/.git-credentials`
- GitHub/GitLab personal access tokens in env vars

**Databases:**
- `DATABASE_URL`, `DB_PASSWORD` in .env files
- `~/.pgpass`, `~/.my.cnf`

**Crypto wallets:**
- `~/.bitcoin/wallet.dat`
- `~/.ethereum/keystore/`
- Browser extension wallet data

**CI/CD secrets:**
- GitHub Actions: secrets exposed as workflow-level env vars during `pip install`
- GitLab CI: variables available in the runner environment

**Cloud metadata endpoints:**
- `http://169.254.169.254/latest/meta-data/` (AWS)
- `http://metadata.google.internal/computeMetadata/v1/` (GCP)
- `http://169.254.169.254/metadata/instance` (Azure)

## Exfiltration patterns

**Archive and POST** — The most common pattern. Credentials are collected into a tar/zip archive (often encrypted), then sent via HTTPS POST to a C2 domain.

Look for:
```bash
# Outbound HTTPS connections from Python processes
ss -tnp | grep python
lsof -i -P -n | grep python | grep ESTABLISHED

# Recently created archive files
find /tmp ~/.cache ~/.local -name "*.tar.gz" -o -name "*.zip" -mtime -1 2>/dev/null
```

**DNS exfiltration** — Less common in PyPI attacks but possible. Data encoded in DNS query subdomains.

**GitHub dead drops** — Credentials pushed to GitHub repos created with stolen tokens. Hard to detect from the victim side.

## Kubernetes lateral movement

Sophisticated payloads (like TeamPCP's) use the in-cluster service account token to deploy privileged pods across all nodes.

```bash
# Check for unexpected pods in kube-system
kubectl get pods -n kube-system --sort-by=.metadata.creationTimestamp

# Look for privileged pods
kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.containers[].securityContext.privileged == true) | .metadata.name'

# Check for recently created secrets
kubectl get secrets --all-namespaces --sort-by=.metadata.creationTimestamp | tail -20

# Audit RBAC for unexpected bindings
kubectl get clusterrolebindings -o json | jq '.items[] | select(.metadata.creationTimestamp > "<ATTACK_DATE>") | .metadata.name'
```

## Network IOC patterns

When specific C2 domains aren't known, look for these patterns:

- Domains that mimic the compromised package name (e.g., `models.litellm.cloud` for litellm)
- Domains impersonating security vendors (e.g., `checkmarx.zone`)
- Connections to unusual ports from Python processes
- HTTPS POST requests with large payloads from non-browser processes
- DNS queries to recently registered domains

```bash
# Check DNS cache if available
grep -r "litellm\|checkmarx" /var/log/syslog /var/log/messages 2>/dev/null

# Check firewall logs
grep -r "REJECT\|DROP" /var/log/ufw.log /var/log/firewalld 2>/dev/null | grep python
```
