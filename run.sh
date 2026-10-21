#!/usr/bin/env bash
# php2shell one-shot: audit, apply the PHP mitigation, install a patched PHP
# where one exists, then re-audit so the Summary reflects the end state. Stops
# before changing anything if the audit finds a stop-level sign of compromise.
#
# Usage: sudo ./run.sh [--no-patch] [--include-eol] [audit.sh options]
#   --no-patch     audit and mitigate only; don't touch PHP packages
#   --include-eol  also install a newer build for PHP 8.1 and older (unverified)
#   Other options are passed to audit.sh.
# Exit codes: 0 done, 3 stopped on a stop-level flag (nothing changed),
#   1 a step failed, other = the audit itself failed.
#
# The nginx guard is not part of this: it depends on each server's sites, so it
# is run separately (see README).

set -u

here=$(cd "$(dirname "$0")" && pwd)

NOPATCH=0
EOL=""
AUDIT_ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --no-patch) NOPATCH=1 ;;
    --include-eol) EOL="--include-eol" ;;
    *) AUDIT_ARGS+=("$1") ;;
  esac
  shift
done

latest_report() { ls -t /root/php2shell-audit-*.txt 2>/dev/null | head -1; }

"$here/audit.sh" --refresh ${AUDIT_ARGS[@]+"${AUDIT_ARGS[@]}"}
rc=$?
# audit.sh tees its output through a background process; give it a moment to
# finish writing the report before we read it back.
sleep 1
report=$(latest_report)

if [ "$rc" -eq 3 ]; then
  echo
  echo "################################################################"
  echo "STOPPED: the audit found a stop-level sign of compromise."
  echo "Nothing was changed on this server. Do not mitigate or patch yet;"
  echo "preserve the report and review it first."
  echo "################################################################"
  [ -n "$report" ] && sed -n '/^== Summary/,$p' "$report"
  exit 3
elif [ "$rc" -ne 0 ]; then
  echo "audit.sh failed with exit code $rc; not mitigating." >&2
  exit "$rc"
fi

echo
echo "== Applying mitigation =="
"$here/mitigate.sh"
mrc=$?

prc=0
patch_out=""
if [ "$NOPATCH" -eq 0 ]; then
  echo
  echo "== Patching PHP where a fixed build exists =="
  patch_out=$(mktemp)
  # The audit above already refreshed apt. $EOL is intentionally unquoted: empty means no argument.
  # shellcheck disable=SC2086
  "$here/patch.sh" --no-refresh $EOL 2>&1 | tee "$patch_out"
  prc=${PIPESTATUS[0]}
fi

# Re-audit quietly so the final Summary shows PHP state after mitigation and
# patching, not before. Compromise checks are skipped: the first audit already
# did them, and repeating them minutes later only adds false flags (the
# DigitalOcean console key from the first audit has expired by now, which
# looks like a changed authorized_keys).
"$here/audit.sh" --php-only >/dev/null 2>&1
sleep 1
final=$(latest_report)

echo
echo "################ RESULT (copy from here) ################"
echo "mitigate.sh exit code: $mrc"
if [ -n "$patch_out" ]; then
  echo "patch.sh exit code: $prc"
  sed -n '/^== PATCH SUMMARY/,$p' "$patch_out"
  rm -f "$patch_out"
fi
[ -n "$final" ] && sed -n '/^== Summary/,$p' "$final"

if [ "$mrc" -ne 0 ] || [ "$prc" -ne 0 ]; then exit 1; fi
exit 0
