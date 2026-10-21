# php2shell

Scripts for checking and temporarily mitigating the PHP2Shell flaws (CVE-2026-109618 / CVE-2026-109619) on Ubuntu servers managed by Laravel Forge, without needing the Forge dashboard.

These are **not** a fix. The fix is a patched PHP build (8.5.12, 8.4.27, 8.3.36, 8.2.35 or a vendor backport). PHP 8.1 and older have no upstream release.

**Current release: `v1.5.0`**

## Quick start (run as root on each server)

Snapshot the droplet first, then paste this one line. It fetches the current release and then:
1. audits the server (and stops if it finds a stop-level sign of compromise),
2. applies the PHP mitigation,
3. upgrades PHP to a patched build for every installed version that has one,
4. re-audits, so the final Summary shows the state after the changes.

```sh
cd /root && rm -rf php2shell && git clone --branch v1.5.0 --depth 1 https://github.com/WeMakeGood/php2shell.git && cd php2shell && ./run.sh
```

- **Stop-level signs** are a process spawned by a PHP worker, a known backdoor in a live site folder, or `/etc/ld.so.preload`. On any of these `run.sh` exits with code 3, prints `STOPPED`, and changes nothing. Review the report before doing anything else.
- Other flags (uploads PHP files, recently changed files and so on) are reported for you to review but don't block.
- **The patch step restarts PHP-FPM** for each version it upgrades (a few seconds of interruption) and may move a branch several releases forward (for example 8.4.5 to 8.4.27). It keeps your edited `php.ini` and pool files, and refuses any upgrade that would remove packages. Where no fixed build exists (for example the Ondřej PPA on Ubuntu 20.04) it says so and changes nothing. Use `./run.sh --no-patch` to skip it.
- **A failed download during the patch step is usually the repository, not the server.** Launchpad returns 503s under load, and apt abandons the whole upgrade when one package fails to download, so nothing is installed. The patch step retries a few times; if it still fails, run `cd /root/php2shell && ./patch.sh` again. Downloaded packages are cached, so each retry has less left to fetch and a repeat run converges.
- If the result says `NO FIXED BUILD AVAILABLE` on Ubuntu 22.04 or 24.04, the PPA has probably not published the fixed build for that server's architecture yet (a new PHP release publishes its source first and builds binaries over the following hours). Check again later with `cd /root/php2shell && ./patch.sh`; there's no need to re-clone. Ubuntu 20.04 will keep saying this, because the PPA publishes nothing for it.
- Long-running workers (Forge daemons, queue workers) keep the old PHP in memory until restarted. The patch step lists any it finds.
- The final re-audit checks PHP state only. Compromise checks run once, in the first audit, so look at that output if anything was flagged.
- **Output is short by default.** `run.sh` prints a few progress lines and one result block: server, mitigation, patch outcome per PHP version, and a list of flags to review. Each flag names what it found (process names, the first few file paths). The full audit is saved to `/root/php2shell-audit-<host>-<time>.txt`; add `--verbose` to see everything on screen. Copy from the `php2shell result` line down. Reports contain cron lines and key comments, so review before sharing them.
- Undo the mitigation with `./mitigate.sh --revert`. `audit.sh`, `mitigate.sh`, `patch.sh` and `nginx-guard.sh` can each be run on their own (`./patch.sh --dry-run` previews the upgrade).

## Scripts

| Script | What it does | Changes the server? |
|---|---|---|
| `audit.sh` | Reports installed PHP packages, candidate versions, patch verdict per PHP version, which sites use which version, effective ini values, and basic compromise indicators | No (writes one root-only report to `/root`) |
| `mitigate.sh` | Writes `/etc/php/X/fpm/conf.d/99-php2shell-mitigation.ini` (upload progress off, strict sessions) and reloads FPM. `--dry-run` and `--revert` supported | Yes, reversible |
| `patch.sh` | Upgrades each installed PHP-FPM version to a build that carries the fix. A build counts as fixed if its own changelog names the CVEs (the script downloads the candidate package and reads it), or it is upstream 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 or later, or Ubuntu's own backported revision. Only touches `php<version>-*` packages. Retries transient repository errors. `--dry-run` supported; a newer PHP 8.1-or-older build whose changelog doesn't name the fix is only installed with `--include-eol`, reported as unverified | Yes (package upgrade) |
| `upgrade.sh` | In-place Ubuntu release upgrade for Forge-style servers (20.04 to 22.04 to 24.04), one hop at a time: `check`, `prepare`, `hop`, `status`, `verify`, `post`. Changes need `--yes`; without it, it only prints the plan. See the section below | Yes (OS upgrade) |
| `preflight.sh` | Read-only snapshot for planning an in-place Ubuntu release upgrade: disk, package health, third-party apt sources, where key packages came from, Forge files, and a per-site HTTP baseline (`BASELINE` lines) to compare after each step. Writes nothing | No |
| `run.sh` | The Quick start: audit, then `mitigate.sh`, then `patch.sh`, then a fresh audit. Stops before changing anything if the audit finds a stop-level sign of compromise | Yes |
| `nginx-guard.sh` | Per-site nginx snippets in Forge's `forge-conf/<site>/server/` directory: `--writes` (only GET/HEAD/OPTIONS), `--multipart` (reject multipart bodies), `--cf-only` / `--cf-auto` (accept only Cloudflare's IP ranges). `list`, `apply --dry-run` and `revert` supported | Yes, reversible |

The mitigation only reduces exposure to one suspected attack path. See [PHP's advisory](https://www.php.net/archive/2026.php).

## When no patched PHP exists (Ubuntu 20.04)

The Ondřej PPA publishes only for Ubuntu 22.04 and 24.04, so PHP from it on 20.04 cannot be updated through apt. `nginx-guard.sh` keeps hostile requests away from PHP instead:

```sh
./nginx-guard.sh list
./nginx-guard.sh apply --cf-auto --writes --dry-run --all --except active-site   # preview
./nginx-guard.sh apply --cf-auto --writes --all --except active-site
./nginx-guard.sh apply --cf-auto active-site
./nginx-guard.sh revert --all
```

- Nothing applies unless you name sites or pass `--all`. `--all --except a,b` skips sites.
- Choose modes by what each site needs: `--writes` for sites nobody edits, `--multipart` for sites that need logins but not uploads.
- **`--cf-auto` checks DNS per site.** Sites whose every hostname is behind Cloudflare get the origin lock (connections accepted only from Cloudflare's ranges). Sites that aren't, or whose names don't resolve, skip the lock and get only the other modes you asked for, or nothing if you asked for none. It is safe to re-run after you proxy more sites.
- `--cf-only` is the strict form: it refuses a site that isn't confirmed behind Cloudflare. Both refuse the lock if nginx uses the `real_ip` module (`--cf-auto` carries on with the other modes).
- After applying, it tests each site from the server itself. A failed self-test returns a non-zero exit code.
- Sites without Forge's `forge-conf/<site>/server/` include in their nginx file are skipped, never edited.
- These controls cover the confirmed multipart paths only. They do not fix the bug.

## In-place Ubuntu upgrade (20.04 to 22.04 to 24.04)

The Ondřej PPA publishes nothing for 20.04 and Launchpad has deleted the old 20.04 PHP and nginx files, so those servers cannot get a patched PHP through apt. Moving them to 24.04 in place keeps the IP, the data and the Forge configuration. [Forge advises against OS release upgrades](https://laravel.com/forge/docs/knowledge-base/servers); this tool keeps Forge's files in place, but it has never been shown to leave Forge able to manage a server afterwards.

**Snapshot the droplet first** (power off or stop MySQL for a consistent one). Run from the DigitalOcean console, because SSH is unreachable for several minutes during each hop.

```sh
./upgrade.sh check                        # read-only: is this server ready?
./upgrade.sh prepare --swap-mysql --yes   # backups, set third-party sources aside, swap MySQL, update Ubuntu
./upgrade.sh hop --yes                    # 20.04 -> 22.04, detached; watch with ./upgrade.sh status
reboot
./upgrade.sh verify                       # services, Forge files and site baseline vs before
./upgrade.sh prepare --yes                # again, for the second hop
./upgrade.sh hop --yes                    # 22.04 -> 24.04
reboot
./upgrade.sh verify                       # PHP is down at this point (sites return 502): expected
./upgrade.sh post --yes                   # restore the PHP PPA, reinstall PHP, patch, mitigate, verify
```

What to expect, from rehearsals on a clone of a real server:
- **The release tool refuses to start** while the dead 20.04 sources are enabled ("install all available updates"), and while Ubuntu's `mysql-server` conflicts with MySQL.com's. `prepare` handles both: it sets third-party sources aside and, with `--swap-mysql`, replaces the MySQL.com packages with Ubuntu's `mysql-server` on the same data directory (no purge).
- **Hop 1 keeps PHP; hop 2 removes it.** The PPA's PHP and nginx packages survive the first hop but not the second. Sites that need PHP return 502 from then until `post` finishes. Plan a maintenance window.
- **nginx, Node and Redis are replaced by Ubuntu's own,** and MySQL by Ubuntu's. The existing `nginx.conf`, `php.ini`, `www.conf`, `sshd_config`, ufw rules and sudoers files were all left unchanged.
- **SSH drops for several minutes** while `sshd` is restarted.
- **Launchpad returns 503s under load.** `post` retries. To avoid depending on it, copy the PHP `.deb` files for the target release into `/var/cache/apt/archives` before `post`; apt verifies each against the signed index it downloads itself, so nothing is trusted just because it is there.

Limits: rehearsed on clones of one server (5 WordPress sites, PHP 8.1, MySQL.com 8.0). Not yet run on a production server. Servers with PHP 7.x or 8.0 sites are untested, and whether the PPA's 24.04 builds of those versions carry the PHP2Shell fix has not been checked. Forge's ability to manage the server afterwards can only be checked on the real server.

## Limits

- File modification times are easy for an attacker to forge. A clean compromise check is not proof of a clean server.
- Request logs do not record POST bodies, so exploitation attempts can't be found there.
- Tested on Ubuntu 22.04 (nginx plus PHP 8.1 and 8.3 from the Ondřej PPA, with systemd). Not yet run on 24.04, and `mitigate.sh` and `audit.sh` have been run on real 20.04 Forge servers. `nginx-guard.sh` has only been tested against a Forge-style layout, not a real Forge nginx file. Run `--dry-run` first.
- `patch.sh` has been tested end to end only with Ubuntu's own fixed package (22.04 `php8.1` 8.1.2-1ubuntu2 to 8.1.2-1ubuntu2.28). It has not yet been run against the PPA's fixed 8.3 / 8.4 builds, because the PPA was unreachable when it was written. The logic that recognises those builds is by version number.
- `patch.sh` trusts a table of Ubuntu revisions taken from secondary sources. After patching, `audit.sh` independently reads the package changelog for the CVE IDs where Ubuntu lists them.
- The patch verdict compares the upstream version from `php-fpm -v` and looks for the CVE IDs in the package changelog. A vendor backport that does neither shows as "NOT PATCHED" or "UNKNOWN" even if it is fixed.
- The compromise check lists shells under FPM workers, PHP files in uploads and recent changes. The signature sweep only knows one backdoor family (`2index.php` / `lock360.php`). It is a triage aid, not proof.
