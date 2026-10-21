#!/usr/bin/env bash
# php2shell patch (CVE-2026-109618 / CVE-2026-109619)
#
# Upgrades each installed PHP-FPM version to a package that carries the fix,
# when apt offers one. It only touches packages named php<version>-*, never a
# full dist-upgrade, and it keeps Forge's edited php.ini and pool files.
#
# What counts as "fixed":
#   - PHP 8.2-8.5: the upstream release 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 or later.
#   - Ubuntu's own packages, which backport the fix under an old version number:
#     22.04 php8.1 >= 8.1.2-1ubuntu2.28, 24.04 php8.3 >= 8.3.6-0ubuntu0.24.04.13,
#     26.04 php8.5 >= 8.5.4-0ubuntu1.5. (Revisions taken from ma.ttias.be and
#     teramont.net; check them against Ubuntu's security notices.)
#   - PHP 8.1 and older from the Ondrej PPA/sury: no published way to tell, so a
#     newer build is only installed with --include-eol, and reported as unverified.
#
# Usage: sudo ./patch.sh [--dry-run] [--no-refresh] [--include-eol]
#   --dry-run      show what would be upgraded, change nothing
#   --no-refresh   skip apt-get update (run.sh has just done it)
#   --include-eol  also install a newer build for PHP 8.1 and older

set -u

DRY=0
REFRESH=1
EOL=0

usage() { sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY=1 ;;
    --no-refresh) REFRESH=0 ;;
    --include-eol) EOL=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)." >&2; exit 1; }

# shellcheck disable=SC1091
. /etc/os-release
RELEASE="${VERSION_ID:-unknown}"

upstream_fixed() {
  case "$1" in
    8.2) echo 8.2.35 ;;
    8.3) echo 8.3.36 ;;
    8.4) echo 8.4.27 ;;
    8.5) echo 8.5.12 ;;
    *) echo "" ;;
  esac
}

ubuntu_fixed() {
  case "$RELEASE:$1" in
    22.04:8.1) echo '8.1.2-1ubuntu2.28' ;;
    24.04:8.3) echo '8.3.6-0ubuntu0.24.04.13' ;;
    26.04:8.5) echo '8.5.4-0ubuntu1.5' ;;
    *) echo "" ;;
  esac
}

# "1:8.4.27-1+ubuntu24.04.1+deb.sury.org+1" -> 8.4.27
upstream_of() { echo "$1" | sed -E 's/^[0-9]+://' | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' | head -1; }

# Is package version $1 on branch $2 known to contain the fix?
is_fixed() {
  local ver="$1" branch="$2" up need ub
  [ -n "$ver" ] && [ "$ver" != "(none)" ] || return 1
  need=$(upstream_fixed "$branch")
  up=$(upstream_of "$ver")
  if [ -n "$need" ] && [ -n "$up" ] && [ "$(printf '%s\n%s\n' "$up" "$need" | sort -V | head -1)" = "$need" ]; then
    return 0
  fi
  # Ubuntu's own builds keep the old upstream number; compare their revision instead.
  # Skipped for sury/PPA builds, whose upstream number is already compared above.
  ub=$(ubuntu_fixed "$branch")
  if [ -n "$ub" ] && ! echo "$ver" | grep -q sury; then
    dpkg --compare-versions "$ver" ge "$ub" && return 0
  fi
  return 1
}

pkg_version() { dpkg-query -W -f='${Version}' "$1" 2>/dev/null; }
candidate() { apt-cache policy "$1" 2>/dev/null | awk '/Candidate:/{print $2}'; }

versions=$(dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' 'php*-fpm' 2>/dev/null \
  | awk '$1=="ii"{print $2}' | grep -E '^php[0-9]+\.[0-9]+-fpm$' | sed -E 's/^php//; s/-fpm$//' | sort -V)
[ -n "$versions" ] || { echo "No php*-fpm packages installed."; exit 0; }

if [ "$REFRESH" -eq 1 ]; then
  echo "== apt-get update =="
  apt-get update 2>&1 | grep -E '^(E|W):' || echo "clean"
fi

RESULTS=()
failed=0

for v in $versions; do
  echo
  echo "== PHP $v =="
  inst=$(pkg_version "php$v-fpm")
  cand=$(candidate "php$v-fpm")
  echo "installed: $inst"
  echo "candidate: ${cand:-none}"

  if is_fixed "$inst" "$v"; then
    echo "already on a fixed build"
    RESULTS+=("PHP $v: already fixed ($inst)")
    continue
  fi

  verified=1
  go=0
  if is_fixed "$cand" "$v"; then
    go=1
  elif [ -z "$(upstream_fixed "$v")" ] && [ -n "$cand" ] && [ "$cand" != "(none)" ] \
       && dpkg --compare-versions "$cand" gt "$inst"; then
    # EOL branch with a newer build: nothing here proves it contains the fix.
    verified=0
    if [ "$EOL" -eq 1 ]; then
      go=1
    else
      echo "a newer build exists ($cand) but its fix status can't be verified; rerun with --include-eol to install it"
      RESULTS+=("PHP $v: newer build $cand available, UNVERIFIED (not installed)")
      continue
    fi
  fi

  if [ "$go" -eq 0 ]; then
    echo "no build with the fix is available"
    RESULTS+=("PHP $v: NO FIXED BUILD AVAILABLE (candidate ${cand:-none})")
    continue
  fi

  # Everything installed for this PHP version, so extensions and the CLI stay in step with FPM.
  pkgs=$(dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' 2>/dev/null \
    | awk -v p="php$v" '$1=="ii" && (index($2, p "-")==1 || $2==p){print $2}')

  # A dry run of the upgrade: refuse if apt would remove anything.
  # shellcheck disable=SC2086
  sim=$(apt-get -s install --only-upgrade $pkgs 2>&1)
  if echo "$sim" | grep -q '^Remv'; then
    echo "apt would REMOVE packages; not upgrading:"
    echo "$sim" | grep '^Remv'
    RESULTS+=("PHP $v: FAILED (upgrade would remove packages; see output)")
    failed=1
    continue
  fi
  echo "would upgrade: $(echo "$sim" | grep -c '^Inst') package(s)"

  if [ "$DRY" -eq 1 ]; then
    RESULTS+=("PHP $v: [dry-run] would upgrade to $cand")
    continue
  fi

  # confold: keep Forge's edited php.ini and pool files instead of prompting.
  # shellcheck disable=SC2086
  if ! DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade \
       -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold $pkgs; then
    echo "apt-get failed for PHP $v" >&2
    RESULTS+=("PHP $v: FAILED (apt-get error)")
    failed=1
    continue
  fi

  # The package restarts FPM; make sure it came back on the new config.
  if ! "php-fpm$v" -t >/dev/null 2>&1; then
    echo "WARNING: php-fpm$v -t reports a config problem after the upgrade:" >&2
    "php-fpm$v" -t 2>&1 | tail -5 >&2
    RESULTS+=("PHP $v: FAILED (config test after upgrade)")
    failed=1
    continue
  fi
  systemctl is-active --quiet "php$v-fpm" || systemctl restart "php$v-fpm"
  if ! systemctl is-active --quiet "php$v-fpm"; then
    RESULTS+=("PHP $v: FAILED (service not running after upgrade)")
    failed=1
    continue
  fi
  now=$(pkg_version "php$v-fpm")
  if [ "$verified" -eq 1 ]; then
    RESULTS+=("PHP $v: PATCHED $inst -> $now")
  else
    RESULTS+=("PHP $v: upgraded $inst -> $now, fix UNVERIFIED")
  fi
done

echo
echo "== Processes still on old PHP files (restart these) =="
stale=0
for p in /proc/[0-9]*; do
  exe=$(readlink "$p/exe" 2>/dev/null) || continue
  case "$exe" in
    */php*"(deleted)")
      echo "pid ${p#/proc/}: $(tr '\0' ' ' < "$p/cmdline")"
      stale=1
      ;;
  esac
done
if [ "$stale" -eq 1 ]; then
  echo "Long-running workers (Forge daemons, queue workers) keep the old PHP until restarted."
else
  echo "none"
fi

echo
echo "== PATCH SUMMARY =="
printf '%s\n' "${RESULTS[@]}"
exit "$failed"
