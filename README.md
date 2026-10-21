# php2shell

Scripts for checking and temporarily mitigating the PHP2Shell flaws (CVE-2026-109618 / CVE-2026-109619) on Ubuntu servers managed by Laravel Forge, without needing the Forge dashboard.

These are **not** a fix. The fix is a patched PHP build (8.5.12, 8.4.27, 8.3.36, 8.2.35 or a vendor backport). PHP 8.1 and older have no upstream release.

## Scripts

| Script | What it does | Changes the server? |
|---|---|---|
| `audit.sh` | Reports installed PHP packages, candidate versions, patch verdict per PHP version, which sites use which version, effective ini values, and basic compromise indicators | No (writes one root-only report to `/root`) |
| `mitigate.sh` | Writes `/etc/php/X/fpm/conf.d/99-php2shell-mitigation.ini` (upload progress off, strict sessions) and reloads FPM. `--dry-run` and `--revert` supported | Yes, reversible |

The mitigation only reduces exposure to one suspected attack path. See [PHP's advisory](https://www.php.net/archive/2026.php).

## Running on a server

Pin to a reviewed commit so a later change to this repo can't run as root on your servers:

```sh
git clone https://github.com/WeMakeGood/php2shell.git
cd php2shell
git checkout <commit-hash-you-reviewed>
sudo ./audit.sh --refresh
sudo ./mitigate.sh --dry-run
sudo ./mitigate.sh
```

Read the audit's `Summary` section first. Reports contain cron lines and key comments, so review before sharing them.

## Limits

- File modification times are easy for an attacker to forge. A clean compromise check is not proof of a clean server.
- Request logs do not record POST bodies, so exploitation attempts can't be found there.
- Tested on Ubuntu 22.04 (nginx plus PHP 8.1 and 8.3 from the Ondřej PPA, with systemd). Not yet run on 20.04 or 24.04. Run `--dry-run` first and snapshot the droplet.
- The patch verdict compares the upstream version from `php-fpm -v` and looks for the CVE IDs in the package changelog. A vendor backport that does neither shows as "NOT PATCHED" or "UNKNOWN" even if it is fixed.
- The compromise check lists shells under FPM workers, PHP files in uploads and recent changes. It is a triage aid, not proof.
