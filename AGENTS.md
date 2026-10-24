# Agent Instructions

## Repository

`emailwiz` provisions a small, non-virtual mail server on Debian, Ubuntu, or
Devuan. It is intentionally two standalone Bash scripts plus documentation:

- `emailwiz.bash` - full installer: packages, Postfix, Dovecot, OpenDKIM,
  Certbot or a self-signed certificate, SpamAssassin, fail2ban, nftables, DNS
  output, and a postmaster cleanup cron job.
- `adddomain.bash` - adds an extra local domain to an existing installation,
  creates DKIM key material when missing, updates OpenDKIM/Postfix, and prints
  DNS records.
- `README.md` - user-facing setup and manual finishing steps.
- `LICENSE` - GPLv3. Keep the copyright headers in both scripts.

There is no Makefile, CI configuration, test suite, package manifest, or
shared shell library. Do not describe commands or files that do not exist.

## Commands That Exist

These are root-only, destructive host operations. Do not run them against a
real or shared server while changing documentation or code.

```sh
sudo ./emailwiz.bash
sudo env MAIL_SUBDOM=post ./emailwiz.bash
sudo ./adddomain.bash <new_domain> <mail_service_domain>
```

`MAIL_SUBDOM` defaults to `mail` and must be the same value used for the
original installation when running `adddomain.bash`.

## Conventions

- Bash with `set -euo pipefail`; keep functions `snake_case` and local
  variables prefixed with `_`.
- Use `postconf -e` for Postfix `main.cf`, `printf` for generated text, and
  quoted expansions. Keep the `log`, `warn`, and `error` helpers.
- Preserve the init-system abstraction (`systemd`, `openrc`, `runit`,
  `sysvinit`); do not assume systemd on Devuan.
- Output and comments are ASCII. Keep prose/comments near 72 columns where
  practical; generated configuration lines may be longer.
- Preserve existing user changes. Inspect `git status` and `git diff` before
  editing, and do not revert unrelated work.
- Do not add a dependency, service, alias, or DNS record unless the scripts
  actually configure it and the README explains it.

## Safety and Testing Policy

- Static analysis first: read the scripts, trace call order, and check
  heredocs, quoting, and generated configuration manually.
- Build and unit-test targets do not exist. Optional static checks such as
  `bash -n` and `shellcheck` are external tools, not project commands.
- Runtime validation is allowed only in a disposable VM/container with a
  snapshot, an out-of-band console, and no production mailboxes. Never test
  the firewall over an SSH-only connection unless the SSH port is known and
  allowed.
- `emailwiz.bash` purges and reinstalls packages, replaces mail/firewall
  configuration, creates users, and may obtain certificates. Always verify
  the backup at `/var/backups/emailwiz/<timestamp>/mail-config.tar.gz`
  (mode `0600`) before a re-run.
- Do not install packages, change system services, make commits, push, or
  modify production data as part of a documentation or review task.
- Distinguish clearly between static review, build, automated tests, and a
  real isolated integration run. A static reading is not proof that a
  service starts.

## Skills

Load the smallest skill that matches the task:

- [`mail-stack-provisioning`](.agents/skills/mail-stack-provisioning/SKILL.md)
  - installer flow, packages, backups, init systems, rollback.
- [`postfix-dovecot-integration`](.agents/skills/postfix-dovecot-integration/SKILL.md)
  - Postfix/Dovecot, auth socket, accounts, aliases, 2.3/2.4.
- [`mail-auth-and-dns`](.agents/skills/mail-auth-and-dns/SKILL.md)
  - OpenDKIM, SPF, DKIM, DMARC, MX, PTR, `adddomain.bash`.
- [`tls-certificates-and-firewall`](.agents/skills/tls-certificates-and-firewall/SKILL.md)
  - Certbot/self-signed TLS, Postfix/Dovecot TLS, nftables, fail2ban.
- [`mail-service-safe-testing`](.agents/skills/mail-service-safe-testing/SKILL.md)
  - isolated test plans, checks, and failure triage.

## Known Boundaries

The scripts use Unix system users for mailboxes and do not configure virtual
users, per-domain accounts, quotas, webmail, DNS-provider APIs, DKIM rotation,
or automatic rollback. MTA-STS and DANE are documented manual steps. Do not
silently claim these features exist.
