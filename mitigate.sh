#!/usr/bin/env bash
# php2shell interim mitigation (CVE-2026-109618 / CVE-2026-109619)
#
# Writes one php.ini drop-in per installed PHP-FPM version that disables
# session upload progress and turns on strict session mode, then reloads FPM.
# PHP's advisory says this only reduces exposure to one attack path; the real
# fix is a patched PHP. The drop-in lives in conf.d so a Laravel Forge edit of
# php.ini (or Forge coming back online) does not overwrite it.
#
# Deliberately NOT set: memory_limit=-1 and a low post_max_size, which the
# advisory also suggests. On shared WordPress servers those can cause outages
# or break uploads, so they are a per-server decision.
#
# Usage: sudo ./mitigate.sh [--dry-run] [--revert]
#   --dry-run  show what would change, change nothing
#   --revert   remove the drop-ins and reload FPM (restores upload progress)

set -u

DRY=0
REVERT=0
NAME=99-php2shell-mitigation.ini

usage() { sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY=1; shift ;;
    --revert) REVERT=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)." >&2; exit 1; }

CONTENT='; Managed by php2shell mitigate.sh. Remove with: ./mitigate.sh --revert
session.upload_progress.enabled = 0
session.use_strict_mode = 1'

run() {
  if [ "$DRY" -eq 1 ]; then echo "[dry-run] $*"; else "$@"; fi
}

status=0
found=0
for v in $(ls /etc/php 2>/dev/null | grep -E '^[0-9]+\.[0-9]+$'); do
  bin="php-fpm$v"
  dir="/etc/php/$v/fpm/conf.d"
  file="$dir/$NAME"
  [ -d "$dir" ] && command -v "$bin" >/dev/null 2>&1 || continue
  found=1
  echo "== PHP $v =="

  if [ "$REVERT" -eq 1 ]; then
    if [ -f "$file" ]; then
      run rm -f "$file"
      run systemctl reload "php$v-fpm" || status=1
      echo "reverted"
    else
      echo "no drop-in present"
    fi
    continue
  fi

  if [ -f "$file" ] && [ "$(cat "$file")" = "$CONTENT" ]; then
    echo "drop-in already current"
  elif [ "$DRY" -eq 1 ]; then
    echo "[dry-run] would write $file"
  else
    printf '%s\n' "$CONTENT" > "$file"
    echo "wrote $file"
  fi

  # A pool-level php_admin_value/php_value is applied after php.ini and would
  # silently undo the mitigation for that pool.
  if grep -nE 'php(_admin)?_(value|flag)\[session\.upload_progress\.enabled\]' \
      /etc/php/"$v"/fpm/pool.d/*.conf 2>/dev/null; then
    echo "WARNING: a pool overrides session.upload_progress.enabled (shown above)" >&2
    status=1
  fi

  if [ "$DRY" -eq 1 ]; then continue; fi

  if ! "$bin" -t >/dev/null 2>&1; then
    echo "ERROR: $bin -t failed with the drop-in; removing it" >&2
    rm -f "$file"
    status=1
    continue
  fi
  systemctl reload "php$v-fpm" || { echo "ERROR: reload failed for php$v-fpm" >&2; status=1; continue; }

  eff=$("$bin" -i 2>/dev/null | grep -E '^session\.upload_progress\.enabled =>' | awk '{print $3}')
  echo "session.upload_progress.enabled now: ${eff:-unknown}; service $(systemctl is-active "php$v-fpm")"
  [ "$eff" = "Off" ] || [ "$eff" = "0" ] || { echo "WARNING: setting did not take effect" >&2; status=1; }
done

[ "$found" -eq 1 ] || { echo "No PHP-FPM installs found under /etc/php." >&2; exit 1; }
exit "$status"
