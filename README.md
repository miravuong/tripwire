# Tripwire — Secrets Detection & Rotation Pipeline

Tripwire is a GitOps-native pipeline that prevents secrets from leaking into version control, automatically rotates compromised credentials, and alerts your team in real time. It layers multiple defenses — pre-commit hooks, CI scanning, Vault-managed secrets, scheduled rotation, and webhook alerts — so that a leaked secret is caught early and remediated automatically.

## Architecture

> See the interactive Excalidraw diagram above for the full architecture overview. The pipeline flows through three zones:

**Developer Workstation** — `git commit` triggers a pre-commit hook (Gitleaks + TruffleHog). If a secret is found, the commit is blocked locally.

**CI/CD (GitHub Actions)** — If a secret reaches the remote, CI scanning catches it, blocks the PR, triggers credential rotation, and sends a Slack/webhook alert.

**Infrastructure** — HashiCorp Vault manages dynamic, short-lived secrets. A rotation service (cron-scheduled or event-driven) replaces compromised credentials and stores new ones in Vault for downstream consumers.

## Components

### 1. Pre-commit Hooks

A local gate that blocks commits containing secrets before they ever reach the remote.

- **Gitleaks** scans staged diffs against a ruleset of regex patterns (AWS keys, GitHub tokens, private keys, etc.).
- **TruffleHog** adds entropy-based detection to catch secrets that don't match known patterns.
- Configured via a `.pre-commit-config.yaml` at the repo root using the [pre-commit](https://pre-commit.com/) framework.
- Runs in under a second on typical diffs so it doesn't slow developers down.

When a secret is detected the commit is rejected with a message identifying the file, line, and rule that matched.

### 2. CI Pipeline Scanning (GitHub Actions)

A second layer that catches anything the pre-commit hook missed — force-pushes, commits made from the web UI, or hooks that were skipped locally.

- A GitHub Actions workflow runs on every push and pull request.
- It checks out the full history (`fetch-depth: 0`) and runs both Gitleaks and TruffleHog against the diff range.
- If a secret is found the workflow fails, the PR is blocked from merging, and downstream jobs (rotation, alerting) are triggered.
- Results are uploaded as a SARIF artifact so findings appear directly in the GitHub Security tab.

### 3. HashiCorp Vault — Dynamic Secret Injection

Instead of storing long-lived credentials in config files or environment variables, Vault generates short-lived, scoped credentials on demand.

- Applications request database credentials, API keys, or cloud tokens from Vault at deploy time.
- Each credential has a TTL (e.g., 1 hour) and is automatically revoked when it expires.
- Vault's AppRole or Kubernetes auth method authenticates workloads without embedding any static secret.
- If a dynamic credential leaks, the blast radius is limited — it expires on its own and can be revoked immediately.

### 4. Credential Auto-Rotation

A rotation service that replaces compromised or aging credentials without manual intervention.

- **Scheduled rotation**: A cron job periodically rotates credentials (e.g., every 90 days) through Vault's rotation API or provider-specific CLIs (AWS `iam create-access-key`, GitHub token refresh, etc.).
- **Event-driven rotation**: When the CI scanner detects a leaked secret, it publishes an event that triggers immediate rotation of that specific credential.
- The rotation service updates the credential in Vault so downstream consumers pick up the new value automatically on their next lease renewal.
- Old credentials are revoked as part of the rotation to close the exposure window.

### 5. Slack / Webhook Alerts

Real-time notifications so the security team knows the moment a secret is detected.

- On detection, the CI workflow sends a payload to a Slack incoming webhook (or any HTTP endpoint).
- The alert includes: repository name, branch, commit SHA, the rule that matched, the file path, and who authored the commit.
- The actual secret value is **never** included in the alert.
- Alerts can also be routed to PagerDuty, Opsgenie, or any incident management tool via generic webhook.

## Workflow Walkthrough

Here's what happens end to end when a developer accidentally commits an AWS secret key:

| Step | What happens | Outcome |
|------|-------------|---------|
| 1 | Developer runs `git commit` | Pre-commit hook fires |
| 2 | Gitleaks scans the staged diff | Match found: `AWS_SECRET_ACCESS_KEY` pattern in `config/settings.py` |
| 3 | Commit is **blocked** locally | Developer sees an error with the file, line number, and matched rule |
| 4 | Developer removes the secret and commits again | Clean commit passes the hook |
| 5 | Push to remote triggers the CI workflow | GitHub Actions runs Gitleaks + TruffleHog on the push range |
| 6 | CI scan passes (secret was removed) | PR is mergeable, pipeline continues |

If the pre-commit hook was bypassed (e.g., `--no-verify`) and the secret reaches the remote:

| Step | What happens | Outcome |
|------|-------------|---------|
| 5 | CI workflow detects the secret in the pushed commits | Workflow fails, PR is blocked |
| 6 | Alert sent to Slack with commit details | Security team is notified immediately |
| 7 | Rotation service receives the detection event | The compromised AWS key is rotated via `iam create-access-key` and the old key is deactivated |
| 8 | New credential is stored in Vault | Downstream services pick up the new key on next lease renewal |
| 9 | Developer is asked to rewrite history (`git filter-repo`) to scrub the secret from Git | Exposure in version history is eliminated |

## Project Structure

```
tripwire/
├── .pre-commit-config.yaml          # Pre-commit hook configuration
├── .gitleaks.toml                    # Gitleaks rules and allowlist
├── .github/
│   └── workflows/
│       └── secrets-scan.yml          # CI scanning workflow
├── vault/
│   ├── policies/                     # Vault ACL policies
│   ├── roles/                        # AppRole / K8s auth role definitions
│   └── config.hcl                    # Vault server configuration
├── rotation/
│   ├── rotate.sh                     # Rotation entrypoint script
│   ├── providers/                    # Per-provider rotation logic (AWS, GCP, GitHub, etc.)
│   └── cron.yaml                     # Scheduled rotation definitions
├── alerting/
│   ├── notify.sh                     # Webhook dispatch script
│   └── templates/                    # Alert message templates (Slack blocks, etc.)
└── README.md                         # This file
```

## Getting Started

### Prerequisites

| Tool | Purpose | Install |
|------|---------|---------|
| [pre-commit](https://pre-commit.com/) | Hook framework | `pip install pre-commit` |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Regex-based secret scanner | `brew install gitleaks` |
| [TruffleHog](https://github.com/trufflesecurity/trufflehog) | Entropy + regex scanner | `brew install trufflehog` |
| [HashiCorp Vault](https://www.vaultproject.io/) | Secrets management | `brew install vault` |
| [GitHub CLI (`gh`)](https://cli.github.com/) | PR / Actions interaction | `brew install gh` |

### Quick Setup

1. **Install the pre-commit hooks**
   ```bash
   pre-commit install
   ```

2. **Verify hooks are working** — try committing a test secret:
   ```bash
   echo 'AKIAIOSFODNN7EXAMPLE' > test.txt
   git add test.txt && git commit -m "test"
   # Expected: commit blocked by Gitleaks
   rm test.txt
   ```

3. **Configure Vault** (requires a running Vault instance):
   ```bash
   export VAULT_ADDR=https://vault.example.com
   vault login
   vault policy write tripwire vault/policies/tripwire.hcl
   ```

4. **Set up CI** — push to a branch and confirm the `secrets-scan` workflow runs in the Actions tab.

5. **Configure alerts** — add a `SLACK_WEBHOOK_URL` secret to your GitHub repo settings so the workflow can send notifications.

## License

MIT
