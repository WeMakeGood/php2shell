#!/usr/bin/env bash
# php2shell nginx guard (CVE-2026-109618 / CVE-2026-109619)
#
# For servers that have no patched PHP available (Ubuntu 20.04 with PHP from
# the Ondrej PPA), stop hostile requests reaching PHP at all. Writes one nginx
# snippet per site into Laravel Forge's own include directory
# (/etc/nginx/forge-conf/<site>/server/), which Forge does not regenerate.
#
# Modes (combine freely; each apply rewrites the site's snippet):
#   --writes     reject everything except GET/HEAD/OPTIONS with 405. For
#                archival sites: no POST means no multipart upload reaches PHP.
#                Logins, comments and wp-admin stop working on that site.
#   --multipart  reject multipart/* request bodies with 415. Normal form posts
#                and logins keep working; file uploads stop.
#   --cf-only    accept connections only from Cloudflare's published IP
#                ranges (plus localhost). Refuses a site unless every
#                hostname in its server_name resolves into Cloudflare.
#   --cf-auto    check each site's DNS and choose: where every hostname is
#                behind Cloudflare, apply the --cf-only lock; where not, skip
#                the lock and apply only the other modes. Use it when you
#                don't know which sites are proxied. Don't combine with --cf-only.
#
# Usage:
#   sudo ./nginx-guard.sh list
#   sudo ./nginx-guard.sh apply [--writes] [--multipart] [--cf-only|--cf-auto] [--dry-run] [--force]
#                               (--all [--except a,b] | site ...)
#   sudo ./nginx-guard.sh revert (--all | site ...)
#
# Sites are named as in /etc/nginx/sites-enabled. Nothing is applied unless you
# name sites or pass --all. Sites whose nginx file lacks Forge's
# forge-conf include are skipped, never edited.

set -u

GUARD=php2shell-guard.conf
FORGE=/etc/nginx/forge-conf
ENABLED=/etc/nginx/sites-enabled

usage() { sed -n '2,35p' "$0" | sed 's/^# \{0,1\}//'; }

CMD="${1:-}"
[ $# -gt 0 ] && shift
WRITES=0; MULTI=0; CF=0; CF_AUTO=0; DRY=0; FORCE=0; ALL=0; EXCEPT=""
SITES=()
while [ $# -gt 0 ]; do
  case "$1" in
    --writes) WRITES=1 ;;
    --multipart) MULTI=1 ;;
    --cf-only) CF=1 ;;
    --cf-auto) CF_AUTO=1 ;;
    --dry-run) DRY=1 ;;
    --force) FORCE=1 ;;
    --all) ALL=1 ;;
    --except) EXCEPT="${2:-}"; shift ;;
    -h|--help) usage; exit 0 ;;
    -*) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    *) SITES+=("$1") ;;
  esac
  shift
done

case "$CMD" in
  list|apply|revert) ;;
  -h|--help|"") usage; exit 0 ;;
  *) echo "Unknown command: $CMD" >&2; usage >&2; exit 2 ;;
esac

[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)." >&2; exit 1; }
[ -d "$ENABLED" ] || { echo "No $ENABLED; is nginx installed?" >&2; exit 1; }

all_sites() {
  for f in "$ENABLED"/*; do
    [ -e "$f" ] || continue
    n=$(basename "$f")
    case "$n" in default|000-catch-all) continue ;; esac
    echo "$n"
  done
}

selected() {
  if [ "$ALL" -eq 1 ]; then
    all_sites | while read -r n; do
      case ",$EXCEPT," in *",$n,"*) continue ;; esac
      echo "$n"
    done
  elif [ ${#SITES[@]} -gt 0 ]; then
    printf '%s\n' "${SITES[@]}"
  fi
}

# Forge's own marker. Without it we can't know the snippet would be loaded.
has_include() { grep -qF "forge-conf/$1/server/" "$ENABLED/$1" 2>/dev/null; }

if [ "$CMD" = list ]; then
  printf '%-45s %-8s %s\n' SITE FORGE GUARD
  for n in $(all_sites); do
    inc=no; has_include "$n" && inc=yes
    g=-
    f="$FORGE/$n/server/$GUARD"
    if [ -f "$f" ]; then
      g=$(grep -oE 'writes|multipart|cf-only' "$f" | sort -u | tr '\n' ',' | sed 's/,$//')
    fi
    printf '%-45s %-8s %s\n' "$n" "$inc" "$g"
  done
  exit 0
fi

reload_nginx() {
  if nginx -t >/dev/null 2>&1; then
    systemctl reload nginx && echo "nginx reloaded"
  else
    echo "ERROR: nginx -t failed; not reloading" >&2
    nginx -t 2>&1 | tail -5 >&2
    return 1
  fi
}

if [ "$CMD" = revert ]; then
  [ "$ALL" -eq 1 ] || [ ${#SITES[@]} -gt 0 ] || { echo "Name sites or pass --all." >&2; exit 2; }
  n_removed=0
  if [ "$ALL" -eq 1 ]; then
    files=$(find "$FORGE" -path "*/server/$GUARD" -type f 2>/dev/null)
  else
    files=$(for s in "${SITES[@]}"; do [ -f "$FORGE/$s/server/$GUARD" ] && echo "$FORGE/$s/server/$GUARD"; done)
  fi
  for f in $files; do rm -f "$f" && echo "removed $f" && n_removed=$((n_removed + 1)); done
  [ "$n_removed" -gt 0 ] || { echo "nothing to revert"; exit 0; }
  reload_nginx
  exit $?
fi

# ---- apply ----
[ $((WRITES + MULTI + CF + CF_AUTO)) -gt 0 ] || { echo "Choose at least one of --writes --multipart --cf-only --cf-auto." >&2; exit 2; }
[ "$CF" -eq 1 ] && [ "$CF_AUTO" -eq 1 ] && { echo "Use --cf-only or --cf-auto, not both." >&2; exit 2; }
[ "$ALL" -eq 1 ] || [ ${#SITES[@]} -gt 0 ] || { echo "Name sites or pass --all." >&2; exit 2; }

CF_RANGES=""
CF_FILE=""

# Prints why and returns 1 if the Cloudflare lock can't be set up safely.
load_cf() {
  # allow/deny judge $remote_addr. If nginx rewrites it to the visitor's real
  # address (real_ip module), Cloudflare's ranges would never match and every
  # visitor would be denied.
  if nginx -T 2>/dev/null | grep -qE '^[[:space:]]*(set_real_ip_from|real_ip_header)'; then
    echo "nginx is configured with real_ip; the Cloudflare lock would deny every visitor." >&2
    return 1
  fi
  command -v curl >/dev/null 2>&1 || { echo "curl is required for the Cloudflare lock." >&2; return 1; }
  v4=$(curl -fsS --max-time 20 https://www.cloudflare.com/ips-v4) || { echo "Could not fetch Cloudflare ranges." >&2; return 1; }
  v6=$(curl -fsS --max-time 20 https://www.cloudflare.com/ips-v6) || { echo "Could not fetch Cloudflare ranges." >&2; return 1; }
  CF_RANGES=$(printf '%s\n%s\n' "$v4" "$v6" | tr -d '\r' | sed '/^$/d')
  # A fetch that returns an error page would otherwise end up inside nginx config.
  bad=$(echo "$CF_RANGES" | grep -vE '^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$|^[0-9a-fA-F:]+/[0-9]{1,3}$')
  if [ -n "$bad" ] || [ "$(echo "$CF_RANGES" | wc -l)" -lt 10 ]; then
    echo "Cloudflare range list looks wrong." >&2
    return 1
  fi
  CF_FILE=$(mktemp)
  trap 'rm -f "$CF_FILE"' EXIT
  echo "$CF_RANGES" > "$CF_FILE"
}

if [ "$CF" -eq 1 ] || [ "$CF_AUTO" -eq 1 ]; then
  if ! load_cf; then
    # --cf-only was an explicit request, so fail; --cf-auto falls back to the other modes.
    [ "$CF" -eq 1 ] && exit 1
    echo "(--cf-auto: Cloudflare lock unavailable this run; applying the other modes only)"
    CF_AUTO=0
  fi
fi

in_cf() {
  python3 -c '
import sys, ipaddress
nets = [ipaddress.ip_network(l.strip()) for l in open(sys.argv[1]) if l.strip()]
ip = ipaddress.ip_address(sys.argv[2])
sys.exit(0 if any(ip in n for n in nets if n.version == ip.version) else 1)
' "$CF_FILE" "$1"
}

# Every hostname the site answers to must be proxied, or --cf-only would take
# the unproxied one offline.
check_proxied() {
  local site="$1" ok=0 resolved=0 name addr
  command -v python3 >/dev/null 2>&1 || { echo "$site: python3 missing, cannot verify Cloudflare (use --force to skip)"; return 1; }
  # server_name may share a line with other directives; skip commented lines.
  names=$(grep -vE '^[[:space:]]*#' "$ENABLED/$site" | grep -ohE 'server_name[[:space:]]+[^;]+' \
    | sed -E 's/^server_name[[:space:]]+//' | tr -s ' \t' '\n' | grep -vE '^(_|localhost|\*.*|\..*|)$' | sort -u)
  [ -n "$names" ] || { echo "$site: no server_name found to check"; return 1; }
  for name in $names; do
    addrs=$(getent ahosts "$name" | awk '{print $1}' | sort -u)
    if [ -z "$addrs" ]; then
      echo "$site: $name does not resolve (ignored)"
      continue
    fi
    resolved=1
    for addr in $addrs; do
      if ! in_cf "$addr"; then
        echo "$site: $name resolves to $addr, which is not a Cloudflare address"
        ok=1
      fi
    done
  done
  # If nothing resolved, "no non-Cloudflare address found" proves nothing.
  if [ "$resolved" -eq 0 ]; then
    echo "$site: none of its hostnames resolve, so Cloudflare can't be confirmed"
    return 1
  fi
  return $ok
}

build_conf() {
  echo "# Managed by php2shell nginx-guard.sh. Remove with: nginx-guard.sh revert $1"
  if [ "$SITE_CF" -eq 1 ]; then
    echo "# cf-only: Cloudflare ranges fetched $(date -u +%F)"
    echo "allow 127.0.0.1;"
    echo "allow ::1;"
    echo "$CF_RANGES" | sed 's/.*/allow &;/'
    echo "deny all;"
  fi
  if [ "$WRITES" -eq 1 ]; then
    echo "# writes: archival site, no request bodies"
    echo 'if ($request_method !~ ^(GET|HEAD|OPTIONS)$) { return 405; }'
  fi
  if [ "$MULTI" -eq 1 ]; then
    echo "# multipart: block the request type the confirmed PHP2Shell paths use"
    echo 'if ($content_type ~* "multipart/") { return 415; }'
  fi
}

written=()
declare -A WCF
failed=0
SITE_CF=0
for site in $(selected); do
  if [ ! -f "$ENABLED/$site" ]; then
    echo "$site: not in $ENABLED"; failed=1; continue
  fi
  if ! has_include "$site"; then
    echo "$site: no Forge include (forge-conf/$site/server/) in its nginx file; skipped"; failed=1; continue
  fi
  SITE_CF=$CF
  if [ "$CF" -eq 1 ] && [ "$FORCE" -eq 0 ]; then
    if ! check_proxied "$site"; then
      echo "$site: SKIPPED (not fully behind Cloudflare). Proxy it or use --force."; failed=1; continue
    fi
  elif [ "$CF_AUTO" -eq 1 ]; then
    if out=$(check_proxied "$site"); then
      SITE_CF=1
      echo "$site: behind Cloudflare, origin lock will be applied"
    else
      SITE_CF=0
      echo "$site: not confirmed behind Cloudflare, origin lock skipped"
      echo "$out" | sed 's/^/    /'
      if [ $((WRITES + MULTI)) -eq 0 ]; then
        echo "$site: no other mode requested; no guard written"; continue
      fi
    fi
  fi
  file="$FORGE/$site/server/$GUARD"
  if [ "$DRY" -eq 1 ]; then
    echo "[dry-run] $site: would write $file"
    build_conf "$site" | grep -vE '^allow ' | sed 's/^/    /'
    [ "$SITE_CF" -eq 1 ] && echo "    (plus $(echo "$CF_RANGES" | wc -l) Cloudflare allow lines)"
    continue
  fi
  mkdir -p "$FORGE/$site/server"
  prev=""
  [ -f "$file" ] && prev=$(cat "$file")
  build_conf "$site" > "$file"
  if ! nginx -t >/dev/null 2>&1; then
    echo "$site: ERROR nginx -t failed with the snippet; restoring" >&2
    if [ -n "$prev" ]; then printf '%s\n' "$prev" > "$file"; else rm -f "$file"; fi
    failed=1; continue
  fi
  echo "$site: written"
  written+=("$site")
  WCF[$site]=$SITE_CF
done

[ "$DRY" -eq 1 ] && exit "$failed"
[ ${#written[@]} -gt 0 ] || exit 1

reload_nginx || exit 1

# Self-test against this server. A reload returns before the old workers stop
# answering, so each probe retries for a few seconds before it counts as failed.
expect() {
  local want="$1" code i
  shift
  for i in 1 2 3 4 5 6 7 8 9 10; do
    code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 15 "$@" 2>/dev/null)
    [ "$code" = "$want" ] && break
    sleep 0.5
  done
  echo "$code"
}

if command -v curl >/dev/null 2>&1; then
  # The server's own address is not a Cloudflare address, so it should be denied.
  selfip=$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' | grep -vE '^127\.' | head -1)
  for site in "${written[@]}"; do
    local_get=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 15 --resolve "$site:443:127.0.0.1" "https://$site/" 2>/dev/null)
    msg="localhost GET $local_get"
    if [ "$WRITES" -eq 1 ] || [ "$MULTI" -eq 1 ]; then
      want=415; [ "$WRITES" -eq 1 ] && want=405
      post=$(expect "$want" --resolve "$site:443:127.0.0.1" -X POST -F a=b "https://$site/")
      if [ "$post" = "$want" ]; then msg="$msg, multipart POST $post (blocked, as expected)"
      else msg="$msg, multipart POST $post (EXPECTED $want: guard not effective, check the site's nginx file)"; failed=1; fi
    fi
    if [ "${WCF[$site]:-0}" -eq 1 ] && [ -n "${selfip:-}" ]; then
      deny=$(expect 403 --resolve "$site:443:$selfip" "https://$site/")
      if [ "$deny" = 403 ]; then msg="$msg, non-Cloudflare address $deny (denied, as expected)"
      else msg="$msg, non-Cloudflare address $deny (EXPECTED 403: origin lock not effective)"; failed=1; fi
    fi
    echo "self-test $site: $msg"
  done
fi
exit "$failed"
