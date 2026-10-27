---
name: postfix-dovecot-integration
description: Work on Postfix and Dovecot configuration, authentication, mailboxes, aliases, and Dovecot 2.3/2.4 compatibility in emailwiz.
---

# Postfix-Dovecot Integration

## When to use

Use this skill when changing `configure_postfix`, `configure_dovecot`,
`main.cf`, `master.cf`, the Dovecot auth socket, login maps, mailbox layout,
Sieve, aliases, or the Postfix side of `adddomain.bash`.

## Integration map

- Postfix identity: `myhostname = <subdom>.<domain>`, `mydomain = <domain>`,
  and `mydestination` contains the base domain, the mail host, and localhost
  names. Hosted domains are local domains, not virtual domains.
- Inbound SMTP on port 25 uses `content_filter=spamassassin`.
- Submission on 587 requires TLS and SASL authentication.
- SMTPS on 465 enables wrapper mode and now requires SASL authentication.
- The managed `smtp`, `submission`, `smtps`, and `spamassassin` services run
  with chroot `n`. This keeps Let's Encrypt paths, `header_checks`, and PCRE
  login maps visible to Postfix.
- Postfix authenticates through Dovecot at `private/auth`, which Dovecot
  exposes at `/var/spool/postfix/private/auth` with mode `0660`, owner/group
  `postfix`.
- `login_maps.pcre` maps `user@domain` to the Unix login `user` for the base
  domain, the mail host, and every domain added later by `adddomain.bash`.
- `smtpd_sender_restrictions` includes `reject_sender_login_mismatch`;
  submission and SMTPS use the same login map.
- Mailboxes are Maildir under `~/Mail`, inbox `~/Mail/Inbox`, with
  `LAYOUT=fs`. Postfix uses `home_mailbox = Mail/Inbox/` and
  `mailbox_command = /usr/lib/dovecot/deliver`.
- Dovecot uses `userdb passwd` and `passdb pam`. Accounts are ordinary Unix
  users; there are no virtual users, per-domain accounts, or quotas.
- The default Sieve script moves messages with `X-Spam-Flag: YES` to `Junk`.
  The global sieve directory is world-traversable because the LDA runs as the
  recipient, not as `vmail`.
- `dmarc: postmaster` is ensured in `/etc/aliases`; the `postmaster` system
  user is created for DMARC reports and cron cleanup. Do not claim that
  arbitrary aliases or mailbox accounts are created automatically.

## Dovecot 2.3 versus 2.4

The script parses `dovecot --version` and emits one of two syntaxes.

| Concern | 2.3 branch | 2.4 branch |
| --- | --- | --- |
| Mail location | `mail_location = maildir:~/Mail:INBOX=~/Mail/Inbox:LAYOUT=fs` | `mail_driver`, `mail_path`, `mail_inbox_path`, `mailbox_list_layout` |
| TLS names | `ssl_cert`, `ssl_key`, `ssl_dh`, `ssl_prefer_server_ciphers` | `ssl_server_cert_file`, `ssl_server_key_file`, `ssl_server_dh_file`, `ssl_server_prefer_ciphers` |
| Auth format | `auth_username_format = %n` | `%{user|username}` plus `auth_allow_cleartext = no` |
| Sieve activation | `mail_plugins = $mail_plugins sieve` | `mail_plugins { sieve = yes }` |
| Sieve paths | `plugin { sieve = ... sieve_default = ... }` | `sieve_script personal/default` blocks |
| Passdb/userdb | `passdb { driver = pam }` | `passdb pam { }`, `userdb passwd { }` (driver in block name) |
| POP3 UIDL | `%08Xu%08Xv` | `%{uid|hex(8)}%{uidvalidity|hex(8)}` |

`protocols` is explicitly `imap pop3` in both branches. The configuration is
fully regenerated, so do not hand-edit generated `dovecot.conf`; change the
generator instead. The stock file is preserved once as
`dovecot.backup.conf`.

## Procedure

1. Read both Dovecot branches and `adddomain.bash` before changing shared
   behavior. A change to the auth socket or login map affects both scripts.
2. Prefer `postconf -e` for `main.cf`. For `master.cf`, remove managed service
   blocks and re-append them rather than layering duplicate blocks.
3. Keep the inbound/submission/SMTPS trust boundaries explicit. Any service
   that accepts authenticated users must require SASL and use the login map.
4. Preserve maildir paths (`~/Mail`, `~/Mail/Inbox`) across Postfix, Dovecot,
   the LDA, and README examples.
5. For aliases, append only when missing and run `newaliases` or `postalias`.
   Never replace the whole `/etc/aliases` file.
6. When changing Dovecot syntax, update both branches and keep the version
   gate accurate. Do not assume a 2.4 directive exists in 2.3.

## Validation

Static review:

- Confirm every `postconf -e` value is valid for the target Postfix version.
- Confirm each `master.cf` service has the right chroot and restriction
  columns, and that no block is duplicated.
- Check that login-map paths, socket paths, and maildir paths agree between
  Postfix and Dovecot.
- Confirm the 2.3 and 2.4 heredocs are balanced.

In an isolated VM only: `postfix check`, `postconf -n`, `doveconf -n`,
inspect `/var/spool/postfix/private/auth`, authenticate a test user with a
real client or `swaks` if installed, and check `/var/log/mail.log` (or the
init system's journal). Do not test against production mailboxes.

## Frequent problems

- Login-map entries missing for a domain added later, causing
  `reject_sender_login_mismatch`.
- Sending as `user@mail.example.org` without a mail-host login-map entry.
- Dovecot 2.4 `driver =` left inside `passdb pam`/`userdb passwd`.
- A 2.4 Sieve `path` pointing at a directory instead of
  `/var/lib/dovecot/sieve/default.sieve`.
- Global Sieve script unreadable by the recipient, so spam never reaches
  `Junk`.
- Postfix chroot hiding `/etc/letsencrypt`, `header_checks`, or login maps.
- Port 465 not requiring authentication.
- Assuming `adddomain.bash` creates users, mailboxes, or aliases. It does not.
- DMARC reports sent to a nonexistent `dmarc@` mailbox; keep the alias or
  provide a real mailbox.

## References

- `emailwiz.bash` - `configure_postfix`, `configure_dovecot`,
  `configure_opendkim`, alias helper.
- `adddomain.bash` - `mydestination` and login-map updates.
- `README.md` - account creation, client settings, and limitations.
- Postfix `postconf(5)`, `master(5)`, and Dovecot configuration docs.

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
