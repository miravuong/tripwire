#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_FILE="${REPO_ROOT}/.gitleaks.toml"

if ! command -v gitleaks >/dev/null 2>&1; then
  echo "gitleaks is required. Install with: brew install gitleaks"
  exit 1
fi

if [[ ! -f "${CONFIG_FILE}" ]]; then
  echo "Could not find config file: ${CONFIG_FILE}"
  exit 1
fi

WORKDIR="$(mktemp -d)"
POS_FILE="${WORKDIR}/positive-cases.txt"
NEG_FILE="${WORKDIR}/negative-cases.txt"

cleanup() {
  rm -rf "${WORKDIR}"
}
trap cleanup EXIT

# Build realistic tokens in pieces so this helper script itself does not
# accidentally look like a secret leak in your repo.
vault_prefix="hvs"
vault_token="${vault_prefix}.$(printf 'A%.0s' {1..28})"

db_scheme_part1="post"
db_scheme_part2="gres"
db_uri="${db_scheme_part1}${db_scheme_part2}://tripwire:Sup3rSecurePass@db.example.com:5432/tripwire"

pw_key_part1="pass"
pw_key_part2="word"
pw_line="${pw_key_part1}${pw_key_part2} = \"Sup3rSecurePass\""

slack_host_1="https://hooks"
slack_host_2=".slack.com/services/"
slack_tid="T$(printf '1%.0s' {1..8})"
slack_bid="B$(printf '2%.0s' {1..8})"
slack_secret="$(printf 'a%.0s' {1..26})"
slack_webhook="${slack_host_1}${slack_host_2}${slack_tid}/${slack_bid}/${slack_secret}"

k8s_key_part1="k8s"
k8s_key_part2="_token"
k8s_jwt_head="eyJ"
k8s_jwt_tail="$(printf 'x%.0s' {1..60})"
k8s_token_line="${k8s_key_part1}${k8s_key_part2} = \"${k8s_jwt_head}${k8s_jwt_tail}\""

webhook_base="https://alerts.example.com/hook"
webhook_q_key="token"
webhook_q_val="$(printf 'Z%.0s' {1..20})"
webhook_with_token="${webhook_base}?${webhook_q_key}=${webhook_q_val}"

cat >"${POS_FILE}" <<EOF
# Positive cases: these should be detected by your .gitleaks.toml
vault_token = "${vault_token}"
database_url = "${db_uri}"
${pw_line}
slack_webhook = "${slack_webhook}"
${k8s_token_line}
webhook = "${webhook_with_token}"
EOF

cat >"${NEG_FILE}" <<'EOF'
# Negative cases: these should not match your custom rules
commit_sha = "abc1234def5678"
service_url = "https://example.com/path?foo=bar"
note = "password reset flow docs"
postgres_hint = "postgres://user@db.example.com/no-password"
EOF

echo "Created test files in: ${WORKDIR}"
echo "Running gitleaks against positive and negative test cases..."
echo

set +e
gitleaks detect --no-git --source "${WORKDIR}" --config "${CONFIG_FILE}" --verbose
RESULT=$?
set -e

echo
if [[ "${RESULT}" -eq 0 ]]; then
  echo "No leaks detected. This is unexpected for positive cases."
  exit 1
fi

echo "Leaks detected as expected."
echo
echo "Expected rule hits include:"
echo "  - vault-token"
echo "  - database-uri"
echo "  - hardcoded-password"
echo "  - slack-webhook-url"
echo "  - kubernetes-sa-token"
echo "  - webhook-with-token"
echo
echo "Tip: rerun with --redact if you want sanitized terminal output."
