#!/usr/bin/env bash
# php2shell in-place Ubuntu release upgrade for Forge-style servers:
# 20.04 -> 22.04 -> 24.04, one hop at a time, keeping the IP, the data and the
# Forge configuration. Built from a rehearsal on a clone of a real server.
#
# Forge advises against OS release upgrades
# (https://laravel.com/forge/docs/knowledge-base/servers). This keeps Forge's
# files in place, but whether Forge can still manage the server afterwards can
# only be checked on the real server. Snapshot the droplet first.
#
# Subcommands (anything that changes the server needs --yes; without it, it only
# prints what it would do):
#   check                      read-only: is this server ready for the next hop?
#   prepare [--swap-mysql]     back up /etc, set third-party apt sources aside,
#                              bring Ubuntu's own packages current, optionally
#                              swap MySQL.com packages for Ubuntu's mysql-server
#   hop                        start do-release-upgrade (detached, non-interactive)
#   status                     progress of a running or finished hop
#   verify                     services, Forge config files and the per-site HTTP
#                              baseline compared with before the first hop
#   post                       after the last hop and a reboot: restore the PHP
#                              and DigitalOcean sources, reinstall PHP, verify
# Usage: sudo ./upgrade.sh <subcommand> [--yes] [--swap-mysql]
#
# Run `hop` from the DigitalOcean console: SSH is unreachable for several
# minutes while the upgrade restarts sshd. Reboot yourself when status says so.

set -u

STATE=/root/php2shell-upgrade
HERE=$(cd "$(dirname "$0")" && pwd)

SUB="${1:-}"; [ $# -gt 0 ] && shift
YES=0; SWAP=0
for a in "$@"; do
  case "$a" in
    --yes) YES=1 ;;
    --swap-mysql) SWAP=1 ;;
    -h|--help) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown option: $a" >&2; exit 2 ;;
  esac
done
case "$SUB" in check|prepare|hop|status|verify|post) ;; ""|-h|--help) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;; *) echo "Unknown subcommand: $SUB" >&2; exit 2 ;; esac
[ "$(id -u)" -eq 0 ] || { echo "Run as root." >&2; exit 1; }

# shellcheck disable=SC1091
. /etc/os-release
FROM="${VERSION_ID:-}"; CODENAME="${VERSION_CODENAME:-}"
case "$FROM" in 20.04) TO=22.04 ;; 22.04) TO=24.04 ;; *) TO="" ;; esac

h()    { printf '\n== %s ==\n' "$*"; }
ok()   { echo "  ok:   $*"; }
warn() { echo "  WARN: $*"; }
fail() { echo "  FAIL: $*"; PROBLEMS=$((PROBLEMS + 1)); }
PROBLEMS=0
step() { echo; echo "-> $*"; }
# Run a command only with --yes; otherwise just say what would run.
act()  { if [ "$YES" -eq 1 ]; then "$@"; else echo "   [dry-run] would run: $*"; fi; }

third_party_sources() {
  # Everything in sources.list.d except Ubuntu's own sources.
  for f in /etc/apt/sources.list.d/*; do
    [ -f "$f" ] || continue
    if grep -qE '^(deb |URIs:)' "$f" && ! grep -E '^(deb |URIs:)' "$f" | grep -qvE 'ubuntu\.com|mirrors\.digitalocean\.com/ubuntu'; then continue; fi
    echo "$f"
  done
}

# "Actually installed" (status ii). `dpkg -s` also succeeds for packages that were
# removed with their config kept (status rc), which is exactly what a MySQL swap leaves behind.
pkg_installed() { [ "$(dpkg-query -W -f='${db:Status-Abbrev}' "$1" 2>/dev/null | cut -c1-2)" = ii ]; }

free_gb() { df -BG --output=avail / | tail -1 | tr -dc '0-9'; }

do_check() {
  h "Can this server take the next hop?"
  [ -n "$TO" ] && ok "Ubuntu $FROM ($CODENAME) -> $TO" || { echo "  Ubuntu $FROM: nothing to do (this tool upgrades 20.04 and 22.04)."; return 0; }
  g=$(free_gb); if [ "$g" -ge 8 ]; then ok "${g} GB free on /"; elif [ "$g" -ge 5 ]; then warn "only ${g} GB free on /; free space first (journal, apt cache, old logs)"; else fail "only ${g} GB free on /; need at least 5"; fi
  [ -z "$(dpkg --audit 2>&1)" ] && ok "dpkg is consistent" || fail "dpkg --audit reports problems"
  fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 && fail "another apt/dpkg process is running" || ok "no apt lock held"
  grep -qE '^Prompt=lts' /etc/update-manager/release-upgrades 2>/dev/null && ok "release-upgrades Prompt=lts" || fail "/etc/update-manager/release-upgrades is not set to Prompt=lts"
  [ -f /var/run/reboot-required ] && fail "a reboot is pending; reboot before starting a hop" || ok "no reboot pending"
  systemctl is-active --quiet droplet-agent && ok "droplet-agent (DigitalOcean console) is running" || warn "droplet-agent is not running; the web console may not work during the upgrade"
  if pkg_installed mysql-community-server; then
    warn "MySQL is the MySQL.com package. Ubuntu's own mysql-server conflicts with it and blocks the release tool: run 'prepare --swap-mysql --yes'"
  else ok "MySQL is not the MySQL.com package ($(dpkg-query -W -f='${Version}' mysql-server 2>/dev/null || echo 'not installed'))"; fi
  echo "  third-party apt sources that will be set aside:"; third_party_sources | sed 's/^/    /'
  echo "  PHP/Node/nginx packages not from Ubuntu (these may be removed or replaced by a hop):"
  dpkg-query -W -f='${Package} ${Version}\n' 2>/dev/null | grep -E 'deb\.sury\.org|nodesource' | awk '{print $1}' | grep -E '^(php[0-9.]*-(fpm|cli)|nginx|nodejs)$' | tr '\n' ' ' | sed 's/^/    /'; echo
  echo; [ "$PROBLEMS" -eq 0 ] && echo "READY for 'prepare'." || { echo "$PROBLEMS blocking problem(s)."; return 1; }
}

save_restore_set() {
  # The PHP packages to bring back afterwards. A hop can remove them, so this is
  # recorded before each hop, and merged with what was recorded earlier: a PHP
  # version added in between (for example through Forge) must come back too.
  local cur
  cur=$(dpkg-query -W -f='${db:Status-Abbrev} ${Package} ${Version}\n' 2>/dev/null \
    | awk '$1=="ii" && $3 ~ /deb\.sury\.org/ {print $2}' | grep -E '^php')
  { [ -f "$STATE/restore-set.txt" ] && cat "$STATE/restore-set.txt"; echo "$cur"; } | sed '/^$/d' | sort -u > "$STATE/restore-set.txt.new" \
    && mv "$STATE/restore-set.txt.new" "$STATE/restore-set.txt"
  echo "   restore set: $(wc -l < "$STATE/restore-set.txt") packages ($(grep -oE '^php[0-9]+\.[0-9]+-fpm$' "$STATE/restore-set.txt" | sed 's/^php//; s/-fpm$//' | tr '\n' ' ')FPM versions)"
}

do_prepare() {
  [ -n "$TO" ] || { echo "Nothing to prepare on Ubuntu $FROM."; exit 0; }
  do_check || { echo; echo "Fix the blocking problems first."; exit 1; }
  h "prepare ($FROM -> $TO)"; [ "$YES" -eq 1 ] || echo "(dry run: nothing is changed without --yes)"
  step "create $STATE and back up /etc, the package list and the site baseline"
  if [ "$YES" -eq 1 ]; then
    mkdir -p "$STATE/sources.d"
    # Keep the first backup: it is the "before" state that verify compares against.
    if [ -e "$STATE/etc-$FROM.tgz" ]; then echo "   $STATE/etc-$FROM.tgz already exists; keeping it"
    else tar czf "$STATE/etc-$FROM.tgz" /etc 2>/dev/null && echo "   $STATE/etc-$FROM.tgz ($(du -h "$STATE/etc-$FROM.tgz" | cut -f1))"; fi
    dpkg-query -W -f='${Package} ${Version}\n' > "$STATE/versions-$FROM.txt"
    apt-mark showmanual > "$STATE/manual-$FROM.txt"
    save_restore_set
    # The baseline is refreshed on every prepare: it is the "before" state of the hop about to run,
    # so sites removed on purpose between hops do not show up as differences later.
    if [ -x "$HERE/preflight.sh" ]; then
      "$HERE/preflight.sh" 2>/dev/null > "$STATE/preflight-$FROM.txt"
      grep '^BASELINE' "$STATE/preflight-$FROM.txt" > "$STATE/baseline-$FROM.txt"
      [ -f "$STATE/baseline-before.txt" ] || cp "$STATE/baseline-$FROM.txt" "$STATE/baseline-before.txt"
      echo "   baseline for $FROM: $(wc -l < "$STATE/baseline-$FROM.txt") sites"
    else warn "preflight.sh not found next to this script; no site baseline recorded"; fi
  else echo "   [dry-run] would write backups, the restore set and a site baseline"; fi
  step "keep the existing file on any config conflict during the upgrade"
  act sh -c 'printf "// php2shell: on a config-file conflict during the upgrade, keep the file already on the server.\nDpkg::Options { \"--force-confold\"; \"--force-confdef\"; };\n" > /etc/apt/apt.conf.d/99php2shell-confold'
  step "set third-party apt sources aside (Launchpad deleted the 20.04 PHP and nginx files, so the release tool can never see the system as fully updated while they are enabled)"
  for f in $(third_party_sources); do
    echo "   $f"
    if [ "$YES" -eq 1 ]; then [ -e "$STATE/sources.d/$(basename "$f")" ] || cp -a "$f" "$STATE/sources.d/"; mv "$f" "$STATE/sources.d/moved-$(basename "$f")"; fi
  done
  if grep -vE '^\s*(#|$)' /etc/apt/sources.list 2>/dev/null | grep -qvE 'ubuntu\.com|mirrors\.digitalocean\.com/ubuntu'; then warn "/etc/apt/sources.list contains non-Ubuntu lines; edit them out by hand"; fi
  step "use Ubuntu's official archive in sources.list (the release tool disables unknown mirrors such as mirrors.digitalocean.com; on one server that left no 'main' component, so it could not find ubuntu-minimal and aborted)"
  if grep -vE '^\s*(#|$)' /etc/apt/sources.list 2>/dev/null | grep -qvE '(archive|security)\.ubuntu\.com'; then
    echo "   sources.list uses a non-official mirror; replacing it with archive.ubuntu.com and security.ubuntu.com for $CODENAME (original saved to $STATE/sources.list.orig)"
    if [ "$YES" -eq 1 ]; then
      [ -e "$STATE/sources.list.orig" ] || cp -a /etc/apt/sources.list "$STATE/sources.list.orig"
      cat > /etc/apt/sources.list <<EOL
# Written by php2shell upgrade.sh so do-release-upgrade recognises every source.
# The original is in $STATE/sources.list.orig
deb http://archive.ubuntu.com/ubuntu $CODENAME main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu $CODENAME-updates main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu $CODENAME-backports main restricted universe multiverse
deb http://security.ubuntu.com/ubuntu $CODENAME-security main restricted universe multiverse
EOL
    else echo "   [dry-run] would rewrite /etc/apt/sources.list"; fi
  else echo "   already official"; fi
  step "refresh apt (Ubuntu sources only)"
  act sh -c 'apt-get update 2>&1 | grep -E "^(E|W|Err):" || echo "   clean"'
  if pkg_installed mysql-community-server; then
    if [ "$SWAP" -eq 1 ]; then
      step "swap MySQL.com packages for Ubuntu's mysql-server (data directory and config are kept; no purge)"
      if [ "$YES" -eq 1 ]; then
        export DEBIAN_FRONTEND=noninteractive
        systemctl stop mysql
        apt-get -y remove mysql-community-server mysql-community-server-core mysql-community-client mysql-community-client-core mysql-community-client-plugins mysql-apt-config 2>&1 | grep -E '^(Removing|E:)' | head -12
        apt-get -y install mysql-server 2>&1 | grep -E '^(E:|0 upgraded)'
        systemctl start mysql; sleep 5
        systemctl is-active --quiet mysql && echo "   mysql active: $(mysqld --version | cut -c1-80)" || { echo "   MYSQL IS NOT RUNNING; stop here and look at /var/log/mysql/error.log"; exit 1; }
      else echo "   [dry-run] would stop mysql, remove the mysql-community-* packages, install Ubuntu's mysql-server"; fi
    else echo; echo "MySQL is the MySQL.com package: re-run with --swap-mysql, or the release tool will refuse to start."; [ "$YES" -eq 1 ] && exit 1; fi
  fi
  step "bring Ubuntu's own packages up to date"
  act sh -c 'DEBIAN_FRONTEND=noninteractive apt-get -y dist-upgrade 2>&1 | tail -3'
  if [ "$YES" -eq 1 ]; then
    n=$(apt list --upgradable 2>/dev/null | grep -vc Listing)
    if [ "$n" -eq 0 ]; then echo "   nothing left to upgrade"; else echo "   $n package(s) still upgradable (the release tool will refuse to start): $(apt list --upgradable 2>/dev/null | grep -v Listing | awk -F/ '{print $1}' | tr '\n' ' ')"; exit 1; fi
    [ -f /var/run/reboot-required ] && { echo "   a reboot is required now: reboot, then run 'prepare' again"; exit 1; }
    echo "   release check: $(do-release-upgrade -c 2>&1 | tail -2 | tr '\n' ' ')"
    touch "$STATE/prepared-$FROM"; echo; echo "Prepared. Next: snapshot the droplet, then './upgrade.sh hop --yes' from the DigitalOcean console."
  fi
}

do_hop() {
  [ -n "$TO" ] || { echo "Nothing to upgrade on Ubuntu $FROM."; exit 0; }
  [ -f "$STATE/prepared-$FROM" ] || { echo "Run 'prepare --yes' first (no prepared marker for $FROM)."; exit 1; }
  [ -f /var/run/reboot-required ] && { echo "Reboot first."; exit 1; }
  h "hop $FROM -> $TO"
  echo "Make sure the droplet is snapshotted. SSH will drop for several minutes; use the DigitalOcean console to watch."
  [ "$YES" -eq 1 ] || { echo "[dry-run] would run: do-release-upgrade -f DistUpgradeViewNonInteractive (detached)"; exit 0; }
  rm -f "$STATE/hop-$FROM.rc"
  cat > "$STATE/hop-$FROM.sh" <<EOS
export DEBIAN_FRONTEND=noninteractive
echo "start \$(date -u +%T)" > "$STATE/hop-$FROM.log"
do-release-upgrade -f DistUpgradeViewNonInteractive >> "$STATE/hop-$FROM.log" 2>&1
echo "rc=\$? \$(date -u +%T)" > "$STATE/hop-$FROM.rc"
EOS
  setsid nohup bash "$STATE/hop-$FROM.sh" > /dev/null 2>&1 < /dev/null &
  sleep 20; echo "started. Watch with: $0 status"
  tail -2 "$STATE/hop-$FROM.log" 2>/dev/null
}

do_status() {
  h "status"; echo "OS: $(lsb_release -ds); kernel $(uname -r); reboot required: $([ -f /var/run/reboot-required ] && echo YES || echo no)"
  for rc in "$STATE"/hop-*.rc; do [ -f "$rc" ] && echo "$(basename "$rc"): $(cat "$rc")"; done
  pgrep -af 'DistUpgradeViewNonInteractive' >/dev/null && echo "a release upgrade is RUNNING; last log: $(tail -1 /var/log/dist-upgrade/main.log 2>/dev/null | cut -c1-110)" || echo "no release upgrade running"
  ls "$STATE"/hop-*.rc >/dev/null 2>&1 && grep -q 'rc=0' "$STATE"/hop-*.rc 2>/dev/null && [ -f /var/run/reboot-required ] && echo "A hop finished OK. Reboot now ('reboot'), then './upgrade.sh verify'."
}

do_verify() {
  h "verify"; PROBLEMS=0
  echo "OS: $(lsb_release -ds); kernel $(uname -r)"
  for u in nginx mysql redis-server memcached ssh ufw droplet-agent cron; do systemctl list-unit-files "$u.service" >/dev/null 2>&1 && printf '  %-14s %s\n' "$u" "$(systemctl is-active "$u" 2>&1)"; done
  for u in $(systemctl list-unit-files 'php*-fpm.service' --no-legend 2>/dev/null | awk '{print $1}'); do printf '  %-14s %s\n' "${u%.service}" "$(systemctl is-active "$u" 2>&1)"; done
  echo "  failed units: $(systemctl --failed --no-legend | wc -l)"
  first=$(ls "$STATE"/etc-*.tgz 2>/dev/null | head -1)
  if [ -n "$first" ]; then
    echo; echo "Forge-relevant files vs the backup taken before the first hop ($(basename "$first")):"
    tmp=$(mktemp -d); tar xzf "$first" -C "$tmp" 2>/dev/null
    for f in nginx/nginx.conf ssh/sshd_config ufw/user.rules sudoers.d/php-fpm sudoers.d/nginx sudoers.d/supervisor $(cd "$tmp/etc" 2>/dev/null && ls php/*/fpm/php.ini php/*/fpm/pool.d/www.conf php/*/cli/php.ini mysql/mysql.conf.d/zz-forge-hardening.cnf 2>/dev/null); do
      if [ ! -e "$tmp/etc/$f" ]; then continue; elif [ ! -e "/etc/$f" ]; then echo "  MISSING now: $f"; PROBLEMS=$((PROBLEMS+1)); elif cmp -s "$tmp/etc/$f" "/etc/$f"; then echo "  unchanged: $f"; else echo "  CHANGED:   $f"; PROBLEMS=$((PROBLEMS+1)); fi
    done; rm -rf "$tmp"
  fi
  # Compare with the baseline taken before the hop that led here (22.04 -> the 20.04 one, 24.04 -> the 22.04 one).
  case "$FROM" in 22.04) prev=20.04 ;; 24.04) prev=22.04 ;; *) prev="" ;; esac
  ref="$STATE/baseline-$prev.txt"; [ -f "$ref" ] || ref="$STATE/baseline-before.txt"
  if [ -f "$ref" ] && [ -x "$HERE/preflight.sh" ]; then
    echo; echo "Site baseline vs $(basename "$ref") (a site that times out right after a reboot is retried once):"
    sleep 15; "$HERE/preflight.sh" 2>/dev/null | grep '^BASELINE' > "$STATE/baseline-now.txt"
    if ! diff "$ref" "$STATE/baseline-now.txt" >/dev/null; then sleep 30; "$HERE/preflight.sh" 2>/dev/null | grep '^BASELINE' > "$STATE/baseline-now.txt"; fi
    if diff "$ref" "$STATE/baseline-now.txt"; then echo "  all $(wc -l < "$STATE/baseline-now.txt") sites match"; else PROBLEMS=$((PROBLEMS+1)); fi
  fi
  echo; [ "$PROBLEMS" -eq 0 ] && echo "VERIFY: no differences." || echo "VERIFY: $PROBLEMS difference(s) above."
  return "$PROBLEMS"
}

do_post() {
  [ -f "$STATE/restore-set.txt" ] || { echo "No restore set in $STATE; was 'prepare --yes' run on the 20.04 server?"; exit 1; }
  [ -f /var/run/reboot-required ] && { echo "Reboot first, then run post."; exit 1; }
  h "post: restore PHP on Ubuntu $FROM ($CODENAME)"; [ "$YES" -eq 1 ] || echo "(dry run: nothing is changed without --yes)"
  key=$(ls /etc/apt/trusted.gpg.d/ondrej*php*.gpg 2>/dev/null | head -1)
  step "restore the PHP PPA ($CODENAME) and the DigitalOcean agent sources from $STATE/sources.d"
  if grep -ql 'ondrej/php' "$STATE"/sources.d/* 2>/dev/null; then
    if [ -z "$key" ]; then echo "   the ondrej/php signing key is not in /etc/apt/trusted.gpg.d; add it by hand, then re-run. Not downloading keys automatically."; exit 1; fi
    act sh -c "echo 'deb [signed-by=$key] https://ppa.launchpadcontent.net/ondrej/php/ubuntu $CODENAME main' > /etc/apt/sources.list.d/ondrej-php.list"
  else echo "   no ondrej/php source was set aside; skipping"; fi
  for f in droplet-agent.list digitalocean-agent.list; do
    [ -f "$STATE/sources.d/$f" ] && [ ! -e "/etc/apt/sources.list.d/$f" ] && act cp "$STATE/sources.d/$f" /etc/apt/sources.list.d/
  done
  echo "   (not restored on purpose: MySQL.com, NodeSource, ondrej/nginx. Ubuntu's own mysql, nodejs and nginx replace them.)"
  step "refresh apt, retrying: Launchpad answers 503 under load"
  if [ "$YES" -eq 1 ]; then for i in 1 2 3 4 5 6; do apt-get update 2>&1 | grep -E '^(E|Err):' > /tmp/p2s-upd.err || break; echo "   update retry $i"; sleep 20; done; fi
  step "reinstall the PHP packages that were installed before (from $STATE/restore-set.txt)"
  missing=""; want=""
  # A stub such as php7.3-common with no php7.3-fpm is a leftover, not a PHP version in use.
  vers=$(grep -oE '^php[0-9]+\.[0-9]+-fpm$' "$STATE/restore-set.txt" | sed -E 's/^php//; s/-fpm$//')
  keep=""
  for p in $(cat "$STATE/restore-set.txt"); do
    case "$p" in
      php-*) keep="$keep $p" ;;
      php[0-9]*) v=$(echo "$p" | sed -E 's/^php([0-9]+\.[0-9]+)-.*/\1/'); echo "$vers" | grep -qx "$v" && keep="$keep $p" || echo "   skipping $p (no php$v-fpm was installed)" ;;
    esac
  done
  for p in $keep; do
    if [ "$YES" -eq 1 ] && [ "$(apt-cache policy "$p" 2>/dev/null | awk '/Candidate/{print $2}')" = "(none)" -o -z "$(apt-cache policy "$p" 2>/dev/null | awk '/Candidate/{print $2}')" ]; then missing="$missing $p"; else want="$want $p"; fi
  done
  [ -n "$missing" ] && warn "not available for $CODENAME, skipped:$missing"
  echo "   installing:$want" | cut -c1-200
  if [ "$YES" -eq 1 ]; then
    done_ok=0
    for i in 1 2 3 4 5; do
      # shellcheck disable=SC2086
      if DEBIAN_FRONTEND=noninteractive apt-get install -y -o Acquire::Retries=5 -o Dpkg::Options::=--force-confold -o Dpkg::Options::=--force-confdef $want 2>&1 | tail -3; [ "${PIPESTATUS[0]}" -eq 0 ]; then done_ok=1; break; fi
      echo "   install attempt $i failed; retrying"; sleep 20
    done
    [ "$done_ok" -eq 1 ] || { echo "   PHP install did not complete; re-run 'post --yes' (downloaded packages are cached)."; exit 1; }
    step "make sure each PHP version is on a build that carries the PHP2Shell fix"
    [ -x "$HERE/patch.sh" ] && "$HERE/patch.sh" --no-refresh | sed -n '/PATCH SUMMARY/,$p'
    [ -x "$HERE/mitigate.sh" ] && { step "re-apply the interim mitigation"; "$HERE/mitigate.sh" | tail -4; }
    do_verify
  fi
}

case "$SUB" in
  check) do_check ;; prepare) do_prepare ;; hop) do_hop ;; status) do_status ;; verify) do_verify ;; post) do_post ;;
esac
