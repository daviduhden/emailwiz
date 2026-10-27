---
name: mail-stack-provisioning
description: Safely change or audit the emailwiz installer flow, package handling, backups, init-system support, and rollback.
---

# Mail Stack Provisioning

## When to use

Use this skill when changing `emailwiz.bash`'s main flow, package list,
prerequisite checks, backup behavior, service management, re-run behavior,
DNS output, or rollback messages. Use it before running the installer in any
environment.

Do not use this skill as permission to run the installer on a real server.
Provisioning tests belong in a disposable, isolated VM or container.

## Facts to preserve

- Both scripts are standalone Bash with `set -euo pipefail` and GPLv3
  headers. There is no shared library, Makefile, CI, or test suite.
- `main` validates root, detects the init system and SSH ports, derives the
  base domain from `hostname --domain`, validates `MAIL_SUBDOM`, and only then
  confirms and installs. Domain validation must stay before the destructive
  package step.
- Existing installations trigger a prompt and a backup at
  `/var/backups/emailwiz/<timestamp>/mail-config.tar.gz`. The directory is
  `0700` and the archive is `0600` because it contains TLS and DKIM private
  keys. A backup failure aborts before the purge.
- The installer stops Dovecot/Postfix only after confirmation and after
  `apt-get update`. It preselects the Postfix "Internet Site" debconf values
  and uses `DEBIAN_FRONTEND=noninteractive`.
- The package list is `postfix postfix-pcre dovecot-imapd dovecot-pop3d
  dovecot-sieve opendkim opendkim-tools spamassassin spamc net-tools
  fail2ban bind9-host nftables`, plus `python3-systemd` on systemd.
- Service management goes through `svc_stop`, `svc_restart`, `svc_reload`,
  `svc_enable`, and `svc_reload_cmd`. They support systemd, OpenRC, runit,
  and a generic `service` fallback. Devuan must not be treated as systemd.
- Configuration order is firewall, TLS, Postfix, Dovecot, OpenDKIM,
  fail2ban, SpamAssassin, validation, service restart, DNS output, cron.
- The installer has no automatic rollback. `on_error` reports the failed
  status and the backup path. Restoring is a manual, explicit operation.
- `create_cronjob` writes `/etc/cron.weekly/postmaster-clean`, which deletes
  postmaster mail older than 30 days. The `postmaster` user is created before
  the cron job is installed.
- DNS records are written to the invoking sudo user's home when possible,
  otherwise `$HOME`, with mode `0600`.

## Procedure

1. Read `emailwiz.bash` and `README.md` completely. Trace `main` and note
   every function that can purge, overwrite, create a user, or restart a
   service.
2. Compare the proposed change with the actual package names, service names,
   paths, and prompts. Do not invent a dry-run flag, config file, or test
   target.
3. Keep destructive work after all validation that can be done without
   changing the host. Preserve the backup-before-purge rule.
4. If adding a step, place it in the correct order and update both the
   success path and `on_error`. Service failures must increment
   `service_failures` or abort; do not print a success message after a known
   failure.
5. Keep changes idempotent where practical: guard file appends, do not
   duplicate `master.cf` services, and do not rotate DKIM keys or overwrite
   published DNS data.
6. Update `README.md` when user-visible behavior changes, including backup
   permissions and the firewall's handling of `/etc/nftables.conf`.
7. For a runtime check, use only a disposable isolated environment. See
   `mail-service-safe-testing`.

## Validation

Static review is mandatory and can be done without running the installer:

- Confirm every function called by `main` is defined and every heredoc has a
  matching terminator.
- Confirm `set -euo pipefail` behavior is not defeated by an unguarded
  destructive command.
- Confirm the backup list still covers every file the installer mutates.
- Check that `README.md` claims match the scripts.

Optional external static checks, if the tools are installed:
`bash -n emailwiz.bash adddomain.bash` and
`shellcheck emailwiz.bash adddomain.bash`. These are not project targets and
were not run as part of this documentation task.

Runtime checks in an isolated VM only: inspect `/var/backups/emailwiz/`,
`postconf -n`, `doveconf -n`, `systemctl status` (or the init equivalent),
`nft list ruleset`, and mail logs. A snapshot is required before the first
run.

## Frequent problems

- Services stopped before the user declines the purge prompt. Keep the stop
  after confirmation.
- A failed backup followed by a purge. Treat backup failure as fatal.
- Domain or `MAIL_SUBDOM` validation after packages were purged. Validate
  first.
- `master.cf` blocks appended twice. Remove prior service blocks before
  appending.
- Firewall lockout on a non-22 SSH port. Detect configured/listening SSH
  ports before applying a drop policy.
- Assuming systemd on Devuan. Exercise the OpenRC/runit/sysvinit branches.
- Claiming success after OpenDKIM, Dovecot, Postfix, or fail2ban failed to
  restart. Track failures and return non-zero.
- Re-running a helper that appends DNS lines without deduplication.

## References

- `emailwiz.bash` - installer and main flow.
- `adddomain.bash` - domain helper with its own backup and validation.
- `README.md` - prerequisites, backup, DNS, and manual steps.
- `.agents/skills/mail-service-safe-testing/SKILL.md` - isolated test policy.

## Maintenance & Continuous Learning

Whenever this skill is used to change the repository, review this skill after
the implementation. Correct procedures that proved wrong, update commands,
paths, configuration and examples, incorporate reusable findings, and remove
outdated assumptions. Review the applicable root and nested `AGENTS.md` files,
specialized agents and related skills; update only the knowledge affected by
the work. Validate local references and run
`python3 scripts/validate-agent-knowledge.py --scope worktree` plus the
applicable project checks. For pull request comparisons, use the documented
`--scope range --base BASE_REF --head HEAD_REF` command. The canonical validator
is read-only and is required even when a task restricts execution of project
scripts; this does not authorize running installers or changing the host.
Report checks actually performed. A structural pass does not prove semantic
relevance, and a task is incomplete until synchronization is validated.
