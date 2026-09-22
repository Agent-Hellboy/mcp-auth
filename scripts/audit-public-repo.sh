#!/usr/bin/env bash
set -euo pipefail

tracked_files="$(git ls-files)"

if printf '%s\n' "$tracked_files" | grep -E '(^|/)(\.env|.*\.(pem|key|p12|pfx))$' >/dev/null; then
  echo "Sensitive environment or key artifact is tracked" >&2
  exit 1
fi

if git grep -n -I -E 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.' -- ':!uv.lock' ':!scripts/audit-public-repo.sh' >/dev/null; then
  echo "Private key material or credential-like token found" >&2
  exit 1
fi

email_matches="$(git grep -n -I -E '[[:alnum:]._%+-]+@[[:alnum:].-]+\.[[:alpha:]]{2,}' -- ':!uv.lock' ':!scripts/audit-public-repo.sh' || true)"
# RFC 2606 reserves example.com/.org/.net and every name under them for
# documentation, so those can never be a real mailbox. Exempt subdomains too:
# matching only the bare domain failed on fixtures like user:pw@client.example.com.
if printf '%s\n' "$email_matches" | grep -vE '@([[:alnum:]-]+\.)*example\.(com|org|net)\b' | grep -q .; then
  echo "Email address found; use neutral placeholders" >&2
  exit 1
fi

echo "Public repository audit passed: no tracked key files, private key material, credential-like tokens, or email addresses."
