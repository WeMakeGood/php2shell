#!/usr/bin/env bash
# php2shell audit (CVE-2026-109618 / CVE-2026-109619)
#
# Read-only with respect to the server's configuration and packages: it only
# inspects, then writes one root-only report file. Run it before mitigating or
# patching so we know what each server actually has (Ubuntu 20.04 boxes in
# particular: nobody has confirmed the PPA ships fixed builds for them).
#
# Usage: sudo ./audit.sh [--days N] [--refresh]
#   --days N   look-back window for "recently modified" checks (default 7)
#   --refresh  run `apt-get update` first so candidate versions are current

set -u

DAYS=7
REFRESH=0

usage() { sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --days) DAYS="${2:-}"; shift 2 ;;
    --refresh) REFRESH=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

case "$DAYS" in ''|*[!0-9]*) echo "--days needs a number" >&2; exit 2 ;; esac
[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)." >&2; exit 1; }

# The report can include cron lines and key comments, so keep it root-only.
umask 077
REPORT="/root/php2shell-audit-$(hostname -s)-$(date +%Y%m%d-%H%M%S).txt"
exec > >(tee "$REPORT") 2>&1

WARN=()
warn() { WARN+=("$*"); }
h() { printf '\n== %s ==\n' "$*"; }

# First fixed upstream release per branch. 8.1 and older have none.
fixed_for() {
  case "$1" in
    8.2) echo 8.2.35 ;;
    8.3) echo 8.3.36 ;;
    8.4) echo 8.4.27 ;;
    8.5) echo 8.5.12 ;;
    *) echo "" ;;
  esac
}

version_ge() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" = "$2" ]; }

if [ "$REFRESH" -eq 1 ]; then
  h "apt-get update"
  apt-get update 2>&1 | tail -5
fi

h "System"
hostname -f 2>/dev/null || hostname
# shellcheck disable=SC1091
. /etc/os-release && echo "$PRETTY_NAME"
uname -r
date -u '+%Y-%m-%d %H:%M:%S UTC'
if command -v pro >/dev/null 2>&1; then
  pro status 2>&1 | head -15
else
  echo "pro (Ubuntu Pro client) not installed"
fi

h "APT sources mentioning ondrej/sury"
grep -rhE '^(deb |URIs:)' /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null \
  | grep -Ei 'ondrej|sury' || echo "none found"

h "Installed PHP packages"
dpkg-query -W -f='${db:Status-Abbrev} ${Package} ${Version}\n' 'php*' 2>/dev/null \
  | awk '$1=="ii"{print $2, $3}'

h "Which PHP version each nginx site uses"
if ls /etc/nginx/sites-enabled/* >/dev/null 2>&1; then
  for f in /etc/nginx/sites-enabled/*; do
    sock=$(grep -ho 'php[0-9]\+\.[0-9]\+-fpm' "$f" 2>/dev/null | sort -u | tr '\n' ' ')
    echo "$(basename "$f"): ${sock:-no php-fpm socket}"
  done
  echo "-- count per version --"
  grep -ho 'php[0-9]\+\.[0-9]\+-fpm' /etc/nginx/sites-enabled/* 2>/dev/null | sort | uniq -c
else
  echo "no nginx sites-enabled found"
fi

for v in $(ls /etc/php 2>/dev/null | grep -E '^[0-9]+\.[0-9]+$'); do
  bin="php-fpm$v"
  command -v "$bin" >/dev/null 2>&1 || continue

  h "PHP $v (FPM)"
  runtime=$("$bin" -v 2>/dev/null | head -1)
  echo "$runtime"
  upstream=$(echo "$runtime" | grep -oE 'PHP [0-9]+\.[0-9]+\.[0-9]+' | awk '{print $2}')
  echo "service: $(systemctl is-active "php$v-fpm" 2>&1)"

  echo "-- package versions (installed / candidate) --"
  apt-cache policy "php$v-fpm" | sed -n '2,3p'

  fixed=$(fixed_for "$v")
  changelog="/usr/share/doc/php$v-fpm/changelog.Debian.gz"
  if [ -f "$changelog" ] && zgrep -qE 'CVE-2026-10961[89]' "$changelog"; then
    echo "VERDICT: PATCHED (package changelog names the CVEs)"
  elif [ -n "$fixed" ] && [ -n "$upstream" ] && version_ge "$upstream" "$fixed"; then
    echo "VERDICT: PATCHED (upstream $upstream >= $fixed)"
  elif [ -z "$fixed" ]; then
    echo "VERDICT: UNKNOWN (branch $v has no upstream fix; confirm package revision with the vendor)"
    warn "php$v: no upstream fix, patch status unconfirmed"
  else
    echo "VERDICT: NOT PATCHED (upstream $upstream, need >= $fixed)"
    warn "php$v: NOT PATCHED ($upstream, need >= $fixed)"
  fi

  echo "-- effective FPM ini --"
  "$bin" -i 2>/dev/null \
    | grep -E '^(session\.upload_progress\.enabled|session\.use_strict_mode|memory_limit|post_max_size|upload_max_filesize) =>'

  dropin=$(ls /etc/php/"$v"/fpm/conf.d/*php2shell* 2>/dev/null)
  if [ -n "$dropin" ]; then
    echo "mitigation drop-in: $dropin"
  else
    echo "mitigation drop-in: none"
    warn "php$v: mitigation drop-in not installed"
  fi

  echo "-- per-pool overrides that could undo mitigation or hit memory settings --"
  grep -nE '^\s*php(_admin)?_(value|flag)\[(session\.|memory_limit|post_max_size|upload_max_filesize)' \
    /etc/php/"$v"/fpm/pool.d/*.conf 2>/dev/null || echo "none"
done

h "Stale PHP processes (running a deleted/replaced binary or library)"
stale=0
for pid in $(pgrep -f 'php-fpm: master process'); do
  if grep -qE '/(usr|lib|opt)/.* \(deleted\)$' "/proc/$pid/maps" 2>/dev/null; then
    echo "STALE: pid $pid ($(tr '\0' ' ' < /proc/$pid/cmdline))"
    stale=1
  fi
done
if [ "$stale" -eq 1 ]; then
  warn "php-fpm master still running old binaries; restart needed"
else
  echo "none"
fi

h "Compromise check (mtimes can be forged, so this finds careless attackers only)"

echo "-- processes spawned by php-fpm workers (healthy servers show none) --"
workers=$(pgrep -d, -f 'php-fpm: pool')
if [ -n "$workers" ]; then
  kids=$(ps -o pid,ppid,user,etime,args --ppid "$workers" 2>/dev/null | tail -n +2)
  if [ -n "$kids" ]; then
    echo "$kids"
    warn "child processes under php-fpm workers (see report)"
  else
    echo "none"
  fi
else
  echo "no pool workers running"
fi

echo "-- processes running from a deleted executable --"
found=0
for p in /proc/[0-9]*; do
  if readlink "$p/exe" 2>/dev/null | grep -q '(deleted)'; then
    pid=${p#/proc/}
    # Old php-fpm binaries are expected before a restart; reported above instead.
    tr '\0' ' ' < "$p/cmdline" | grep -q 'php-fpm: ' && continue
    echo "pid $pid: $(tr '\0' ' ' < "$p/cmdline")"
    found=1
  fi
done
if [ "$found" -eq 1 ]; then
  warn "process running from deleted executable (see report)"
else
  echo "none"
fi

echo "-- PHP files inside wp-content/uploads (index.php stubs under 100 bytes ignored) --"
up=$(find /home -xdev -type f \
  \( -iname '*.php' -o -iname '*.phtml' -o -iname '*.phar' -o -iname '*.php[0-9]' \) \
  -path '*/wp-content/uploads/*' ! \( -name index.php -size -100c \) 2>/dev/null)
if [ -n "$up" ]; then
  echo "$up" | head -50
  echo "total: $(echo "$up" | wc -l)"
  warn "PHP files in wp-content/uploads (see report)"
else
  echo "none"
fi

echo "-- PHP files modified in last $DAYS days outside plugins/themes/core/cache/vendor --"
recent=$(find /home -xdev \
  \( -path '*/wp-content/plugins' -o -path '*/wp-content/themes' -o -path '*/wp-content/upgrade' \
     -o -path '*/wp-content/cache' -o -path '*/wp-content/uploads' -o -path '*/wp-admin' \
     -o -path '*/wp-includes' -o -name vendor -o -name node_modules -o -name .git \) -prune \
  -o -type f -name '*.php' -mtime "-$DAYS" -print 2>/dev/null)
if [ -n "$recent" ]; then
  echo "$recent" | head -50
  echo "total: $(echo "$recent" | wc -l) (WordPress core updates and wp-config edits are legitimate causes)"
  warn "recently modified PHP files outside updatable dirs (review)"
else
  echo "none"
fi

echo "-- cron: files modified in last $DAYS days (full contents shown), others summarized --"
for f in /var/spool/cron/crontabs/* /etc/cron.d/* /etc/crontab; do
  [ -f "$f" ] || continue
  if find "$f" -mtime "-$DAYS" | grep -q .; then
    echo "### RECENT: $f ($(stat -c '%y' "$f"))"
    grep -vE '^\s*(#|$)' "$f"
    warn "cron file changed recently: $f"
  else
    echo "$f: $(grep -cvE '^\s*(#|$)' "$f") active line(s), modified $(stat -c '%y' "$f" | cut -d. -f1)"
  fi
done

echo "-- persistence locations modified in last $DAYS days --"
pers=$(find /etc/systemd/system /etc/sudoers.d /etc/profile.d /etc/ssh /usr/local/bin /usr/local/sbin \
  -type f -mtime "-$DAYS" 2>/dev/null)
if [ -n "$pers" ]; then
  echo "$pers"
  warn "persistence-related files changed recently (review)"
else
  echo "none"
fi
if [ -e /etc/ld.so.preload ]; then
  echo "/etc/ld.so.preload EXISTS:"; cat /etc/ld.so.preload
  warn "/etc/ld.so.preload exists (rootkit indicator unless you created it)"
else
  echo "/etc/ld.so.preload: absent"
fi

echo "-- accounts with login shells, uid 0 or uid >= 1000 --"
awk -F: '($3==0 || $3>=1000) && $7 !~ /(nologin|false)$/ {print $1, "uid="$3, $6, $7}' /etc/passwd

echo "-- authorized_keys (fingerprint, mtime) --"
for d in /root /home/*; do
  k="$d/.ssh/authorized_keys"
  [ -f "$k" ] || continue
  echo "$k modified $(stat -c '%y' "$k" | cut -d. -f1)"
  ssh-keygen -lf "$k" 2>/dev/null | sed 's/^/    /'
  if find "$k" -mtime "-$DAYS" | grep -q .; then
    warn "authorized_keys changed recently: $k"
  fi
done

echo "-- recent logins --"
last -n 15 -a 2>/dev/null | head -15

echo "-- listening sockets --"
ss -tlnp 2>/dev/null

h "Summary"
if [ ${#WARN[@]} -eq 0 ]; then
  echo "No flags raised."
else
  printf 'FLAG: %s\n' "${WARN[@]}"
fi
echo
echo "Report saved to $REPORT (root-only; it may contain cron lines, review before sharing)."
