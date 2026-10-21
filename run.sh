#!/usr/bin/env bash
# php2shell one-shot: audit, then apply the PHP mitigation unless the audit
# found a stop-level sign of compromise. Prints the Summary last so it is the
# part you copy back.
#
# Usage: sudo ./run.sh [audit.sh options]
#   Runs `audit.sh --refresh` (extra options are passed through), then
#   `mitigate.sh` only if the audit exits cleanly. Exit codes: 0 done,
#   3 stopped on a stop-level flag (nothing was changed), other = a script failed.
#
# The nginx guard is not part of this: it depends on each server's sites, so it
# is run separately (see README).

set -u

here=$(cd "$(dirname "$0")" && pwd)

"$here/audit.sh" --refresh "$@"
rc=$?
# audit.sh tees its output through a background process; give it a moment to
# finish writing the report before we read it back.
sleep 1
report=$(ls -t /root/php2shell-audit-*.txt 2>/dev/null | head -1)

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

echo
echo "################ RESULT (copy from here) ################"
echo "mitigate.sh exit code: $mrc"
# The audit ran before the mitigation, so its "drop-in not installed" lines are
# out of date once mitigate.sh has succeeded.
if [ -n "$report" ]; then
  if [ "$mrc" -eq 0 ]; then
    sed -n '/^== Summary/,$p' "$report" | grep -v 'mitigation drop-in not installed'
  else
    sed -n '/^== Summary/,$p' "$report"
  fi
fi
exit "$mrc"
