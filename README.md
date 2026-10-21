# php2shell

Scripts for checking and temporarily mitigating the PHP2Shell flaws (CVE-2026-109618 / CVE-2026-109619) on Ubuntu servers managed by Laravel Forge, without needing the Forge dashboard.

These are **not** a fix. The fix is a patched PHP build (8.5.12, 8.4.27, 8.3.36, 8.2.35 or a vendor backport). PHP 8.1 and older have no upstream release.

**Current release: `v1.0.0`**

## Quick start (run as root on each server)

Snapshot the droplet first. This always fetches the current release into `/root/php2shell`:

```sh
cd /root && rm -rf php2shell && git clone --branch v1.0.0 --depth 1 https://github.com/WeMakeGood/php2shell.git && cd php2shell
```

Then, from `/root/php2shell`:

```sh
./audit.sh --refresh          # read the Summary at the bottom first
./mitigate.sh --dry-run       # preview
./mitigate.sh                 # apply; undo with ./mitigate.sh --revert
```

The audit prints the release it ran as, so pasted output says which version produced it. Reports contain cron lines and key comments, so review before sharing them. If the audit flags anything under "Compromise check", stop and look before changing anything.

## Scripts

| Script | What it does | Changes the server? |
|---|---|---|
| `audit.sh` | Reports installed PHP packages, candidate versions, patch verdict per PHP version, which sites use which version, effective ini values, and basic compromise indicators | No (writes one root-only report to `/root`) |
| `mitigate.sh` | Writes `/etc/php/X/fpm/conf.d/99-php2shell-mitigation.ini` (upload progress off, strict sessions) and reloads FPM. `--dry-run` and `--revert` supported | Yes, reversible |
| `nginx-guard.sh` | Per-site nginx snippets in Forge's `forge-conf/<site>/server/` directory: `--writes` (only GET/HEAD/OPTIONS), `--multipart` (reject multipart bodies), `--cf-only` (accept only Cloudflare's IP ranges). `list`, `apply --dry-run` and `revert` supported | Yes, reversible |

The mitigation only reduces exposure to one suspected attack path. See [PHP's advisory](https://www.php.net/archive/2026.php).

## When no patched PHP exists (Ubuntu 20.04)

The Ondřej PPA publishes only for Ubuntu 22.04 and 24.04, so PHP from it on 20.04 cannot be updated through apt. `nginx-guard.sh` keeps hostile requests away from PHP instead:

```sh
./nginx-guard.sh list
./nginx-guard.sh apply --writes --cf-only --dry-run site1 site2   # preview
./nginx-guard.sh apply --writes --cf-only site1 site2
./nginx-guard.sh revert --all
```

- Nothing applies unless you name sites or pass `--all`. `--all --except a,b` skips sites.
- Choose modes per site by what it needs: `--writes` for sites nobody edits, `--multipart` for sites that need logins but not uploads, `--cf-only` for sites fully behind Cloudflare.
- `--cf-only` refuses a site unless every hostname in its `server_name` resolves to a Cloudflare address, and refuses entirely if nginx uses the `real_ip` module.
- After applying, it tests each site from the server itself. A failed self-test returns a non-zero exit code.
- Sites without Forge's `forge-conf/<site>/server/` include in their nginx file are skipped, never edited.
- These controls cover the confirmed multipart paths only. They do not fix the bug.

## Limits

- File modification times are easy for an attacker to forge. A clean compromise check is not proof of a clean server.
- Request logs do not record POST bodies, so exploitation attempts can't be found there.
- Tested on Ubuntu 22.04 (nginx plus PHP 8.1 and 8.3 from the Ondřej PPA, with systemd). Not yet run on 24.04, and `mitigate.sh` and `audit.sh` have been run on real 20.04 Forge servers. `nginx-guard.sh` has only been tested against a Forge-style layout, not a real Forge nginx file. Run `--dry-run` first.
- The patch verdict compares the upstream version from `php-fpm -v` and looks for the CVE IDs in the package changelog. A vendor backport that does neither shows as "NOT PATCHED" or "UNKNOWN" even if it is fixed.
- The compromise check lists shells under FPM workers, PHP files in uploads and recent changes. The signature sweep only knows one backdoor family (`2index.php` / `lock360.php`). It is a triage aid, not proof.
