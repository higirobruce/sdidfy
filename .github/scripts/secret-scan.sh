#!/usr/bin/env bash
#
# secret-scan.sh — a grep-based check for obviously committed credentials.
#
# This is deliberately the cheap version: no new dependencies, no network, no
# service to enrol in. It catches credentials that were pasted in whole and
# committed — the common accident — and nothing cleverer. It has no entropy
# model, no git-history awareness (it scans the working tree / the checkout,
# not previous commits), and no notion of what a value is used for.
#
# A real programme needs a real tool. See the placeholder step in
# .github/workflows/security.yml — gitleaks for history-aware detection and
# GitHub's own push protection / secret scanning for the org-wide control.
#
# Documented dev defaults are tolerated by design (they are published in
# .env.example, README.md and docs/runbook.md, and the broker refuses to boot
# in production while any of them is still set — apps/broker/src/config.ts):
#     dev-only-nid-pepper-change-me   NID_PEPPER
#     dev-admin-token                 ADMIN_API_TOKEN
#     sdid_dev                        local Postgres password
#
# Exit codes: 0 = clean, 1 = findings, 2 = the scan itself failed.

set -uo pipefail

cd "$(dirname "$0")/../.." || exit 2

status=0

note() { printf '%s\n' "$*"; }

fail() {
  status=1
  printf '\n[secret-scan] FINDING: %s\n' "$1"
  printf '%s\n' "$2"
  if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
    printf '::error::[secret-scan] %s\n' "$1"
  fi
}

# Paths that are never scanned. `pnpm-lock.yaml` holds integrity hashes that
# look like high-entropy secrets to any regex; .env.example and docs/ publish
# the dev defaults on purpose.
EXCLUDES=(
  --exclude-dir=node_modules
  --exclude-dir=dist
  --exclude-dir=build
  --exclude-dir=coverage
  --exclude-dir=.git
  --exclude-dir=.turbo
  --exclude=pnpm-lock.yaml
  --exclude=*.png
  --exclude=*.jpg
  --exclude=*.pdf
  --binary-files=without-match
)

# Values allowed to appear anywhere: the documented dev defaults, and the
# obvious "fill this in" markers. Every entry here is a hole — justify it.
ALLOWLIST='dev-only-nid-pepper-change-me|dev-admin-token|sdid_dev|change-me|changeme|placeholder|example\.com|your-|<your|xxxx|process\.env|EXAMPLE'

# scan <label> <extra-grep-args...> -- <pattern>
# Runs grep, distinguishes "no match" (fine) from "grep errored" (fatal), and
# filters the allowlist. `-e` is mandatory: several patterns begin with `-`,
# which grep would otherwise parse as options and silently scan nothing.
scan() {
  local label="$1"; shift
  local extra=()
  while [ "$1" != '--' ]; do extra+=("$1"); shift; done
  shift
  local pattern="$1"

  local out rc
  out=$(grep -rEn "${EXCLUDES[@]}" "${extra[@]}" -e "$pattern" . 2>&1)
  rc=$?
  if [ "$rc" -ge 2 ]; then
    printf '\n[secret-scan] grep failed for "%s" (exit %s):\n%s\n' "$label" "$rc" "$out"
    exit 2
  fi
  out=$(printf '%s' "$out" | grep -Ev "$ALLOWLIST")
  if [ -n "$out" ]; then
    fail "$label" "$out"
  else
    note "     none"
  fi
}

# ---------------------------------------------------------------------------
# 1. High-confidence credential shapes. These have essentially no benign form,
#    so they are scanned across every file type.
# ---------------------------------------------------------------------------
note "[secret-scan] 1/4 high-confidence credential shapes"
scan "what looks like a real credential is committed" -- \
  '-----BEGIN( RSA| EC| DSA| OPENSSH| PGP)? PRIVATE KEY-----|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,}|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}|"type"[[:space:]]*:[[:space:]]*"service_account"'

# ---------------------------------------------------------------------------
# 2. Assigned secret-looking values (secret/password/token/api_key = "...").
#    Restricted to values of 20+ credential-ish characters.
#
#    Test and fixture files are excluded by naming convention (*.spec.ts,
#    *.test.ts, testkit.ts, *.fixture.ts): they legitimately carry throwaway
#    client secrets and stub tokens, and every one of them that this scan
#    flagged during calibration was a false positive. That is a real hole — a
#    live credential parked in a file called `*.fixture.ts` is invisible here —
#    and it is the trade that keeps the check believed rather than muted.
#    If you need a new exclusion, it must be a *filename convention*, never a
#    widened value pattern.
# ---------------------------------------------------------------------------
note "[secret-scan] 2/4 hard-coded secret assignments"
scan "a long literal is assigned to a secret-looking name" \
  -i --exclude='*.spec.ts' --exclude='*.test.ts' --exclude='testkit.ts' \
  --exclude='*.fixture.ts' --exclude='*.fixtures.ts' -- \
  '(secret|password|passwd|passphrase|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key)["'"'"']?[[:space:]]*[:=][[:space:]]*["'"'"'][A-Za-z0-9+/=_.-]{20,}["'"'"']'

# ---------------------------------------------------------------------------
# 3. A real .env must never be committed. .gitignore covers it; this catches
#    the case where it was force-added before the ignore rule existed.
# ---------------------------------------------------------------------------
note "[secret-scan] 3/4 committed .env files"
envs=$(find . -type f \( -name '.env' -o -name '.env.*' \) \
  -not -name '.env.example' \
  -not -path './node_modules/*' -not -path './.git/*' 2>/dev/null)
if [ -n "$envs" ]; then
  fail "an environment file other than .env.example is present in the tree" "$envs"
else
  note "     none (only .env.example, as intended)"
fi

# ---------------------------------------------------------------------------
# 4. PRIVATE key material. A broker signing key in the checkout is a
#    token-forgery key (SPEC 06 §3, T13). No environment writes key material to
#    the filesystem any more — dev keys live in the signing_keys table and
#    production custody is a KMS/HSM (decision #5) — but a key can still be
#    dropped into a checkout by hand, and .gitignore only helps if nobody
#    force-adds.
#
#    Deliberately narrow: check 1 already catches anything with a PEM
#    `-----BEGIN … PRIVATE KEY-----` header, so this only adds the formats that
#    have no such header. A `.pem`/`.crt` holding a public certificate — which
#    packages/attestation legitimately needs as a test fixture for App Attest
#    and Play Integrity chains — is NOT a finding.
# ---------------------------------------------------------------------------
note "[secret-scan] 4/4 private key material in other formats"
keys=''
# PKCS#8 / PKCS#12 containers are private by definition, and binary, so no
# content test is possible or needed.
containers=$(find . -type d -name node_modules -prune -o -type f \
  \( -name '*.p8' -o -name '*.p12' -o -name '*.pfx' \) -print 2>/dev/null)
[ -n "$containers" ] && keys="${keys}${containers}"$'\n'
# A JWK is private iff it carries the private component: "d" for EC/RSA/OKP,
# or "k" for a symmetric key. A public JWK set (a JWKS dump) has neither.
for f in $(find . -type d -name node_modules -prune -o -type f -name '*.json' -print 2>/dev/null); do
  if grep -qE '"(kty)"[[:space:]]*:' "$f" 2>/dev/null &&
     grep -qE '"(d|k)"[[:space:]]*:[[:space:]]*"' "$f" 2>/dev/null; then
    keys="${keys}${f} (JWK with a private component)"$'\n'
  fi
done
keys=$(printf '%s' "$keys" | sed '/^$/d')
if [ -n "$keys" ]; then
  fail "private key material is present in the checkout — signing keys live in the KMS/HSM, never the repo" "$keys"
else
  note "     none"
fi

echo
if [ "$status" -eq 0 ]; then
  echo "[secret-scan] clean."
  echo "[secret-scan] Reminder: this scans the checkout only, with fixed patterns."
  echo "[secret-scan] It is not a substitute for history-aware scanning (see security.yml)."
else
  echo "[secret-scan] FAILED — see findings above."
  echo "[secret-scan] If a hit is a documented dev default, add it to ALLOWLIST in this"
  echo "[secret-scan] script WITH a comment saying why it is safe. Never widen a pattern."
fi
exit "$status"
