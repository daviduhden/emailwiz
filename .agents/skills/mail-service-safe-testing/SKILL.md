---
name: mail-service-safe-testing
description: Plan static, isolated, and runtime validation for emailwiz without risking production mail, SSH access, or data.
---

# Safe Testing of the Mail Stack

## When to use

Use this skill before running `emailwiz.bash`, `adddomain.bash`, or any
Postfix/Dovecot/OpenDKIM/nftables validation, and when reproducing a reported
mail-flow or firewall problem.

## Non-negotiable rules

- Do not run either script on a real server, a shared host, or a workstation
  used for production mail during a code or documentation review.
- Use a disposable VM or container with a snapshot and an out-of-band
  console. Never test a drop-policy firewall over an SSH-only connection
  unless the SSH port is known and already allowed.
- Do not send mail to real third parties from a test host. Use local users,
  a sink, or a domain you control.
- Do not install packages, alter system services, commit, push, or modify
  production mailboxes as part of a documentation task.
- Certbot has production rate limits. Use a test/staging endpoint or a
  throwaway domain, and never loop certificate issuance.

## Layers of validation

Keep these separate in reports; one does not imply the next.

1. **Static review** - read the scripts, trace `main`, check heredocs,
   quoting, function order, and generated configuration. This is the only
   layer required for documentation changes.
2. **Static tooling** - optional external tools such as `bash -n` and
   `shellcheck`. They are not project targets and are not installed by the
   repository.
3. **Build** - not applicable; there is no build system.
4. **Automated tests** - not available; there is no test suite or CI.
5. **Isolated integration** - the actual scripts in a disposable VM.

## Isolated test plan

1. Snapshot the VM. Record the base image (Debian, Ubuntu, or Devuan) and
   init system.
2. Set a fully qualified hostname and a test domain. For a LAN-only test,
   set `selfsigned="yes"` and avoid the public-DNS requirement. For a Certbot
   test, point a disposable domain's A record at the VM and use staging.
3. Run `emailwiz.bash` with a console you control, confirm the backup exists,
   and watch package/service output. Do not use a non-22 SSH session unless
   the detected port is allowed.
4. Inspect generated files before declaring success:
   `/etc/postfix/main.cf`, `/etc/postfix/master.cf`,
   `/etc/dovecot/dovecot.conf`, `/etc/opendkim.conf`,
   `/etc/fail2ban/jail.d/emailwiz*.local`, and `/etc/nftables.conf`.
5. Validate configuration with the real tools where available:
   - `postfix check`
   - `postconf -n`
   - `doveconf -n`
   - `nft -c -f /etc/nftables.conf`
   - `opendkim-testkey -d <domain> -s <selector> -k <key>`
   - `fail2ban-client -t`
   - `spamassassin --lint`
6. Start services and check status/logs. On systemd: `systemctl status` and
   `journalctl -u postfix -u dovecot -u opendkim -u fail2ban`. On
   Devuan/sysvinit/OpenRC/runit, use the init tool and `/var/log/mail.log`,
   `/var/log/syslog`, or service-specific logs.
7. Create a local test user and verify local delivery into
   `~/Mail/Inbox`, IMAP/POP3 login over TLS, authenticated submission on
   587, SMTPS on 465, and sender-login rejection for a mismatched sender.
8. Test `adddomain.bash` on a fresh snapshot, then run it twice and confirm
   that Postfix/DKIM entries and `~/dns_emailwizard_added` do not duplicate.
9. Check permissions on `/var/backups/emailwiz/*/mail-config.tar.gz`,
   DKIM keys, TLS keys, and the DNS output files.
10. Restore the snapshot after the test. Do not leave a test firewall or
    mail server running on a shared network.

## Expected outcomes

- The installer returns non-zero if validation or a tracked service
  operation fails; it should not print a clean success message after a
  failure.
- Backups are root-only (`0700` directory, `0600` archive).
- OpenDKIM keys are group-readable/traversable by `opendkim`, and `Mode sv`
  is active.
- Dovecot starts with the syntax for its installed major/minor version.
- The firewall includes the actual SSH port and does not open unmanaged
  services.
- Added domains produce one set of DNS records and preserve existing DKIM
  keys.

## Frequent testing mistakes

- Treating `bash -n` or a careful reading as proof that Postfix starts.
- Running a firewall test from an SSH session without an out-of-band console.
- Using a production domain for repeated Certbot issuance.
- Testing `adddomain.bash` against a host whose `MAIL_SUBDOM` differs from
  the original install.
- Forgetting that `emailwiz.bash` purges packages and overwrites
  `/etc/nftables.conf`; always snapshot first.
- Sending real mail to external addresses and polluting reputation.
- Assuming service restart failures are fatal; check the final exit status
  and logs.
- Leaving test users, DNS records, DKIM keys, or firewall rules behind.

## References

- `emailwiz.bash` - installer and validation points.
- `adddomain.bash` - domain helper and its backup.
- `README.md` - prerequisites, logs, client settings, and manual DNS.
- `.agents/skills/mail-stack-provisioning/SKILL.md` - installer safety.
- `.agents/skills/tls-certificates-and-firewall/SKILL.md` - firewall and
  certificate-specific risks.

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
