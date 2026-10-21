#!/usr/bin/env bash
# php2shell one-shot: audit, apply the PHP mitigation, install a patched PHP
# where one exists, then re-audit so the result reflects the end state. Stops
# before changing anything if the audit finds a stop-level sign of compromise.
#
# Quiet by default: it prints a short result block and saves the details. The
# full audit report is under /root; --verbose also shows everything on screen.
#
# Usage: sudo ./run.sh [--verbose] [--no-patch] [--include-eol] [audit.sh options]
#   --verbose      show the full audit, mitigation and patch output
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

VERBOSE=0
NOPATCH=0
EOL=""
AUDIT_ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --verbose) VERBOSE=1 ;;
    --no-patch) NOPATCH=1 ;;
    --include-eol) EOL="--include-eol" ;;
    *) AUDIT_ARGS+=("$1") ;;
  esac
  shift
done

latest_report() { ls -t /root/php2shell-audit-*.txt 2>/dev/null | head -1; }
step() { echo "[$(date +%H:%M:%S)] $*"; }
# Run a step: full output with --verbose, otherwise saved to a file only.
quiet() { # quiet <outfile> cmd...
  local out="$1"; shift
  if [ "$VERBOSE" -eq 1 ]; then "$@" 2>&1 | tee "$out"; return "${PIPESTATUS[0]}"
  else "$@" >"$out" 2>&1; return $?; fi
}

host=$(hostname -f 2>/dev/null || hostname)
ver=$(git -C "$here" describe --tags --always 2>/dev/null || echo unknown)
# shellcheck disable=SC1091
os=$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown OS}")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

step "php2shell $ver on $host ($os)"
step "Auditing (the first run refreshes apt and sweeps /home, which can take a minute)..."
quiet "$tmp/audit.out" "$here/audit.sh" --refresh ${AUDIT_ARGS[@]+"${AUDIT_ARGS[@]}"}
rc=$?
# audit.sh tees its output through a background process; give it a moment to
# finish writing the report before we read it back.
sleep 1
report=$(latest_report)
summary() { sed -n '/^== Summary/,/^Report saved/p' "$1"; }

if [ "$rc" -eq 3 ]; then
  echo
  echo "################ STOPPED: nothing was changed ################"
  echo "The audit found a stop-level sign of compromise on $host."
  echo "Do not mitigate or patch yet; preserve the report and review it."
  echo
  [ -n "$report" ] && summary "$report" | grep -E '^(STOP|FLAG):'
  echo
  echo "Full report: $report"
  exit 3
elif [ "$rc" -ne 0 ]; then
  echo "audit.sh failed with exit code $rc; not mitigating. Output:" >&2
  tail -15 "$tmp/audit.out" >&2
  exit "$rc"
fi

step "Applying the PHP mitigation..."
quiet "$tmp/mitigate.out" "$here/mitigate.sh"
mrc=$?

prc=0
if [ "$NOPATCH" -eq 0 ]; then
  step "Patching PHP where a fixed build exists..."
  # The audit above already refreshed apt. $EOL is intentionally unquoted: empty means no argument.
  # shellcheck disable=SC2086
  quiet "$tmp/patch.out" "$here/patch.sh" --no-refresh $EOL
  prc=$?
fi

# Re-audit PHP state only: the first audit already did the compromise checks,
# and repeating them minutes later adds false flags (the DigitalOcean console
# key seen by the first audit has expired by now, which looks like a changed
# authorized_keys).
step "Re-checking PHP state..."
"$here/audit.sh" --php-only >/dev/null 2>&1
sleep 1
final=$(latest_report)

mit_versions=$(grep '^== PHP' "$tmp/mitigate.out" 2>/dev/null | sed 's/^== //; s/ ==$//' | paste -sd, - | sed 's/,/, /g')
flags=$( { [ -n "$report" ] && summary "$report" | grep -E '^FLAG:' | grep -vE '^FLAG: php'
           [ -n "$final" ] && summary "$final" | grep -E '^FLAG:'; } )

echo
echo "======================= php2shell result ======================="
echo "Server:      $host ($os)"
echo "Release:     $ver"
echo "Stop-level:  none"
if [ "$mrc" -eq 0 ]; then
  echo "Mitigation:  applied to ${mit_versions:-no PHP-FPM versions found}"
else
  echo "Mitigation:  PROBLEM (exit $mrc)"
  grep -E 'WARNING|ERROR' "$tmp/mitigate.out" | sed 's/^/             /'
fi
if [ "$NOPATCH" -eq 1 ]; then
  echo "Patch:       skipped (--no-patch)"
elif [ -f "$tmp/patch.out" ]; then
  echo "Patch:"
  sed -n '/^== PATCH SUMMARY/,$p' "$tmp/patch.out" | tail -n +2 | sed 's/^/  /'
  if [ "$prc" -ne 0 ]; then
    echo "  patch.sh exit code: $prc. Last lines of its output:"
    tail -12 "$tmp/patch.out" | sed 's/^/    /'
  fi
  if grep -q '^pid ' "$tmp/patch.out" 2>/dev/null; then
    echo "  Restart these (still on old PHP):"
    sed -n '/Processes still on old PHP/,/PATCH SUMMARY/p' "$tmp/patch.out" | grep '^pid ' | sed 's/^/    /'
  fi
fi
if [ -n "$flags" ]; then
  n=$(echo "$flags" | wc -l)
  echo "To review ($n):"
  echo "$flags" | sed 's/^FLAG: /  - /'
else
  echo "To review:   nothing flagged"
fi
echo "Full report: $report"
[ "$VERBOSE" -eq 0 ] && echo "(run ./run.sh --verbose to see the full output on screen)"
echo "================================================================"

if [ "$mrc" -ne 0 ] || [ "$prc" -ne 0 ]; then exit 1; fi
exit 0
