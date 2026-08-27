#!/usr/bin/env bash
#
# check-audit-append-only.sh — prove, against a real Postgres, that the
# `audit_events` append-only guarantee (SPEC 07 §4) is actually enforced by the
# database and not merely written down in a migration.
#
# The guard script (.github/scripts/guard-non-negotiables.mjs) checks that no
# source file *asks* to mutate audit rows. This checks the other half: that if
# something did ask, Postgres would refuse. Both are needed — the trigger is
# the control, the source scan is the tripwire.
#
# What it asserts:
#   1. Both guard triggers exist on audit_events (row-level + TRUNCATE).
#   2. INSERT still works — append-only means append, not read-only.
#   3. UPDATE  is rejected, and rejected *by the trigger* (message match).
#   4. DELETE  is rejected, likewise.
#   5. TRUNCATE is rejected, likewise.
#   6. The probe row survives all three attempts.
#
# DESTRUCTIVE-ISH: step 2 appends a synthetic row with a bogus prev_hash/hash,
# which breaks the tamper-evident chain from that row onward. That is fine for
# a throwaway CI database and unacceptable anywhere else, so this script
# refuses to run against a non-local host unless ALLOW_NONLOCAL=1 is set
# explicitly. Never point it at staging or production.
#
# Usage:  DATABASE_URL=postgresql://sdid:sdid_dev@localhost:5432/sdid_bridge \
#           bash .github/scripts/check-audit-append-only.sh
#
# Exit codes: 0 = all properties hold, 1 = a property failed, 2 = setup error.

set -uo pipefail

DATABASE_URL="${DATABASE_URL:-postgresql://sdid:sdid_dev@localhost:5432/sdid_bridge}"

if ! command -v psql >/dev/null 2>&1; then
  echo "[audit-check] psql not found — install postgresql-client" >&2
  exit 2
fi

# Fail closed on anything that is not obviously a local scratch database.
if [ "${ALLOW_NONLOCAL:-0}" != "1" ]; then
  case "$DATABASE_URL" in
    *@localhost:*|*@127.0.0.1:*|*@postgres:*|*@localhost/*|*@127.0.0.1/*)
      ;;
    *)
      echo "[audit-check] refusing to run against a non-local database." >&2
      echo "[audit-check] This appends a chain-breaking probe row. Set ALLOW_NONLOCAL=1" >&2
      echo "[audit-check] only if you are certain the target is disposable." >&2
      exit 2
      ;;
  esac
fi

status=0
PROBE_ACTION='ci.append_only_probe'

pass() { printf '  ok    — %s\n' "$1"; }
bad() {
  status=1
  printf '  FAIL  — %s\n' "$1"
  if [ -n "${2:-}" ]; then printf '%s\n' "$2" | sed 's/^/          /'; fi
  if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
    printf '::error::[audit-check] %s\n' "$1"
  fi
}

# Run SQL, expect success, echo the single scalar result.
q() {
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -qtAX -c "$1" 2>&1
}

# Run SQL, expect the append-only trigger to reject it.
expect_rejected() {
  local label="$1" sql="$2" out rc
  out=$(psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -qtAX -c "$sql" 2>&1)
  rc=$?
  if [ "$rc" -eq 0 ]; then
    bad "$label was ACCEPTED — audit_events is not append-only" "$out"
    return
  fi
  if ! printf '%s' "$out" | grep -qi 'append-only'; then
    bad "$label failed, but NOT with the append-only trigger's error — the statement may be failing for an unrelated reason" "$out"
    return
  fi
  pass "$label rejected by the append-only trigger"
}

echo "[audit-check] target: $(printf '%s' "$DATABASE_URL" | sed 's#://[^@]*@#://***@#')"
echo

# --- 1. the triggers exist -------------------------------------------------
echo "[audit-check] 1. guard triggers present on audit_events"
triggers=$(q "SELECT string_agg(tgname, ',' ORDER BY tgname)
              FROM pg_trigger
              WHERE tgrelid = 'audit_events'::regclass AND NOT tgisinternal")
if [ -z "$triggers" ] || printf '%s' "$triggers" | grep -qi 'error'; then
  bad "could not read triggers on audit_events (is the schema migrated?)" "$triggers"
  echo
  echo "[audit-check] aborting: without the table there is nothing to test."
  exit 1
fi
pass "triggers: $triggers"

# pg_trigger.tgtype bits: 1 = ROW, 2 = BEFORE, 4 = INSERT, 8 = DELETE,
# 16 = UPDATE, 32 = TRUNCATE.
upd_del_guard=$(q "SELECT count(*) FROM pg_trigger
                   WHERE tgrelid = 'audit_events'::regclass AND NOT tgisinternal
                     AND (tgtype & 2) > 0 AND (tgtype & 16) > 0 AND (tgtype & 8) > 0")
trunc_guard=$(q "SELECT count(*) FROM pg_trigger
                 WHERE tgrelid = 'audit_events'::regclass AND NOT tgisinternal
                   AND (tgtype & 32) > 0")
[ "${upd_del_guard:-0}" -ge 1 ] \
  && pass "a BEFORE UPDATE OR DELETE trigger is installed" \
  || bad "no BEFORE UPDATE OR DELETE trigger on audit_events"
[ "${trunc_guard:-0}" -ge 1 ] \
  && pass "a BEFORE TRUNCATE trigger is installed" \
  || bad "no BEFORE TRUNCATE trigger on audit_events"

# --- 2. append still works -------------------------------------------------
echo
echo "[audit-check] 2. INSERT (append) is still permitted"
ins=$(psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -qtAX -c \
  "INSERT INTO audit_events (id, actor, action, result, prev_hash, hash)
   VALUES (gen_random_uuid(), '{\"kind\":\"system\",\"id\":\"ci\"}'::jsonb,
           '$PROBE_ACTION', 'success', 'ci-probe-prev', 'ci-probe-hash')
   RETURNING seq" 2>&1)
if [ $? -ne 0 ] || [ -z "$ins" ]; then
  bad "INSERT into audit_events failed — append-only must still allow appends" "$ins"
  echo
  echo "[audit-check] aborting: no probe row to test mutation against."
  exit 1
fi
probe_seq=$(printf '%s' "$ins" | tail -n1 | tr -d '[:space:]')
pass "probe row appended at seq=$probe_seq"

# --- 3/4/5. mutation is rejected -------------------------------------------
# Row-level triggers only fire for rows that actually match, which is why the
# probe row above exists: an UPDATE matching zero rows would "succeed" and this
# check would pass against a table with no guard at all.
echo
echo "[audit-check] 3. UPDATE / DELETE / TRUNCATE are rejected"
expect_rejected "UPDATE of an existing audit row" \
  "UPDATE audit_events SET result = 'tampered' WHERE seq = $probe_seq"
expect_rejected "DELETE of an existing audit row" \
  "DELETE FROM audit_events WHERE seq = $probe_seq"
expect_rejected "TRUNCATE of audit_events" \
  "TRUNCATE TABLE audit_events"

# --- 6. the row survived ---------------------------------------------------
echo
echo "[audit-check] 4. the probe row is untouched"
after=$(q "SELECT result FROM audit_events WHERE seq = $probe_seq")
if [ "$after" = "success" ]; then
  pass "seq=$probe_seq still reads result='success'"
else
  bad "probe row changed or disappeared (result='$after')"
fi

echo
if [ "$status" -eq 0 ]; then
  echo "[audit-check] PASS — audit_events is append-only at the database level (SPEC 07 §4)."
  echo "[audit-check] Note: triggers bind to normal roles. A superuser, a role with"
  echo "[audit-check] session_replication_role=replica, or storage-level access can still"
  echo "[audit-check] alter rows — which is exactly what the hash chain exists to detect"
  echo "[audit-check] (/admin/audit/verify, docs/runbook.md §5)."
else
  echo "[audit-check] FAIL — the append-only guarantee is not enforced. This is a"
  echo "[audit-check] non-negotiable (SPEC 07 §4); do not merge."
fi
exit "$status"
