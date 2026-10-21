#!/usr/bin/env bash
# php2shell preflight: a read-only snapshot of everything an in-place Ubuntu
# release upgrade on a Forge-style server is likely to disturb, plus a per-site
# HTTP baseline to compare against afterwards. Writes nothing to the server.
#
# Usage: sudo ./preflight.sh [--sizes]
#   --sizes   also measure each site's disk use (slow on large servers)
# From another machine, without copying anything:
#   ssh root@server 'bash -s' < preflight.sh > before.txt
# After an upgrade step, run it again and compare the baseline lines:
#   diff <(grep '^BASELINE' before.txt) <(grep '^BASELINE' after.txt)

set -u

SIZES=0
[ "${1:-}" = "--sizes" ] && SIZES=1
[ "$(id -u)" -eq 0 ] || { echo "Run as root." >&2; exit 1; }

h() { printf '\n== %s ==\n' "$*"; }

h "System"
hostname -f 2>/dev/null || hostname
# shellcheck disable=SC1091
. /etc/os-release; echo "$PRETTY_NAME ($(uname -r), $(dpkg --print-architecture))"
uptime -p 2>/dev/null
echo "release-upgrades Prompt: $(grep -E '^Prompt=' /etc/update-manager/release-upgrades 2>/dev/null || echo 'file missing')"
echo "virtualization: $(systemd-detect-virt 2>/dev/null)"

h "Disk and memory (a release upgrade needs several GB free on / and /var)"
df -h / /var /boot 2>/dev/null | awk '!seen[$0]++'
df -i / | tail -1 | awk '{print "inodes used: " $5}'
free -h | sed -n '1,2p'
echo "apt cache: $(du -sh /var/cache/apt 2>/dev/null | cut -f1), journal: $(journalctl --disk-usage 2>/dev/null | grep -oE '[0-9.]+[KMG]' | head -1)"

h "Package manager health"
echo "held packages: $(apt-mark showhold | tr '\n' ' ')"
echo "dpkg --audit:"; dpkg --audit 2>&1 | head -5
echo "packages not fully installed:"; dpkg -l | awk '/^[a-z][a-z] /{ if ($1 != "ii") print }' | head -10
echo "pending upgrades (simulated, from the current index): $(apt-get -s upgrade 2>/dev/null | grep -c '^Inst')"
echo "autoremovable: $(apt-get -s autoremove 2>/dev/null | grep -c '^Remv')"
echo "reboot required: $([ -f /var/run/reboot-required ] && echo YES || echo no)"

h "Third-party apt sources (do-release-upgrade disables these)"
grep -rhE '^(deb |URIs:)' /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null \
  | grep -vE '(archive|security|ports)\.ubuntu\.com|old-releases\.ubuntu\.com|mirrors\.digitalocean\.com' \
  | sed -E 's#(https?://)[^/@]*@#\1***@#' | sort -u

h "Key packages: installed version and where it came from"
origin() {
  # the repo line right under the installed (***) entry in apt-cache policy
  apt-cache policy "$1" 2>/dev/null | awk '/\*\*\*/{f=1; next} f && /^ +[0-9]+ /{print $2; exit}'
}
for pkg in $(dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' 2>/dev/null \
    | awk '$1=="ii"{print $2}' \
    | grep -E '^(php[0-9.]*-fpm|php[0-9.]*-cli|nginx|nginx-common|mysql-server|mysql-community-server|mysql-server-[0-9.]+|mariadb-server|redis-server|memcached|supervisor|certbot|nodejs|composer|sendmail|ufw|fail2ban)$'); do
  printf '%-28s %-42s %s\n' "$pkg" "$(dpkg-query -W -f='${Version}' "$pkg")" "$(origin "$pkg")"
done

h "Installed PHP, nginx, MySQL and Redis packages (the set to restore after a release upgrade)"
dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' 2>/dev/null \
  | awk '$1=="ii"{print $2}' | grep -E '^(php|nginx|libnginx|mysql|libmysql|redis|memcached)' | tr '\n' ' '
echo

h "Databases"
echo "mysqld: $(mysqld --version 2>/dev/null | cut -c1-90 || echo none)"
echo "service: $(systemctl is-active mysql 2>/dev/null || systemctl is-active mysqld 2>/dev/null)"
echo "data dir: $(du -sh /var/lib/mysql 2>/dev/null | cut -f1)"
echo "databases (needs root MySQL access without a password; blank if not available):"
mysql -N -e 'select table_schema, round(sum(data_length+index_length)/1048576) as mb from information_schema.tables group by table_schema order by mb desc' 2>/dev/null | head -40

h "Services"
echo "failed units:"; systemctl --failed --no-legend 2>/dev/null | head
for u in nginx mysql redis-server memcached supervisor cron sendmail-mta ssh ufw; do
  printf '%-14s %s / %s\n' "$u" "$(systemctl is-active "$u" 2>/dev/null)" "$(systemctl is-enabled "$u" 2>/dev/null)"
done
for f in $(ls /lib/systemd/system/php*-fpm.service 2>/dev/null); do
  s=$(basename "$f" .service); printf '%-14s %s / %s\n' "$s" "$(systemctl is-active "$s")" "$(systemctl is-enabled "$s")"
done
echo "firewall:"; ufw status 2>/dev/null | head -12
echo "listening:"; ss -tlnp 2>/dev/null | awk 'NR>1{print $4, $6}' | sed -E 's/users:\(\("([^"]+)".*/\1/' | sort -u | head -20

h "Forge-specific files that must survive the upgrade"
for f in /etc/nginx/forge-conf /etc/nginx/nginx.conf /etc/sudoers.d /etc/supervisor/conf.d /root/.ssh/authorized_keys /home/forge/.ssh/authorized_keys; do
  if [ -e "$f" ]; then printf '%-40s present (%s)\n' "$f" "$(stat -c '%y' "$f" | cut -d. -f1)"; else printf '%-40s MISSING\n' "$f"; fi
done
echo "sudoers.d: $(ls /etc/sudoers.d 2>/dev/null | tr '\n' ' ')"
echo "supervisor programs:"; supervisorctl status 2>/dev/null | head -20
echo "users with crontabs: $(ls /var/spool/cron/crontabs 2>/dev/null | tr '\n' ' ')"
echo "php.ini files edited since install (versus the package copy; these are what a config prompt would overwrite):"
for v in $(ls /etc/php 2>/dev/null); do
  for f in /etc/php/$v/fpm/php.ini /etc/php/$v/cli/php.ini /etc/php/$v/fpm/pool.d/www.conf; do
    [ -f "$f" ] && printf '  %s modified %s\n' "$f" "$(stat -c '%y' "$f" | cut -d. -f1)"
  done
done

h "Sites (nginx) and HTTP baseline from this server"
for f in /etc/nginx/sites-enabled/*; do
  [ -e "$f" ] || continue
  site=$(basename "$f")
  case "$site" in default|000-catch-all) continue ;; esac
  name=$(grep -vE '^[[:space:]]*#' "$f" | grep -ohE 'server_name[[:space:]]+[^;]+' | head -1 | sed -E 's/^server_name[[:space:]]+//' | awk '{print $1}')
  root=$(grep -vE '^[[:space:]]*#' "$f" | grep -ohE '^[[:space:]]*root[[:space:]]+[^;]+' | head -1 | awk '{print $2}')
  php=$(grep -ohE 'php[0-9]+\.[0-9]+-fpm' "$f" | head -1)
  code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 20 --resolve "${name:-$site}:443:127.0.0.1" "https://${name:-$site}/" 2>/dev/null)
  size=""
  [ "$SIZES" -eq 1 ] && [ -n "$root" ] && size=" size=$(timeout 120 du -sxh "$(dirname "$root")" 2>/dev/null | cut -f1)"
  echo "BASELINE site=$site name=${name:-?} php=${php:-none} code=${code:-000}${size}"
  echo "  root=${root:-?}"
done
