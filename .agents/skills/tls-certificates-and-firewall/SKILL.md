---
name: tls-certificates-and-firewall
description: Work on Certbot and self-signed TLS, Postfix/Dovecot TLS settings, nftables rules, SSH lockout avoidance, and fail2ban in emailwiz.
---

# TLS, Certificates, and Firewall

## When to use

Use this skill when changing `configure_ssl`, `configure_firewall`, TLS
parameters, certificate paths, renewal hooks, nftables, SSH port handling, or
fail2ban jails.

## Certificate behavior

- `certdir` is resolved once in `configure_ssl` and reused by Postfix and
  Dovecot. Certbot uses `/etc/letsencrypt/live/<subdom>.<domain>`; self-signed
  mode uses `/etc/ssl/emailwiz/<subdom>.<domain>` so it cannot clobber a
  Certbot lineage.
- Certbot reuses an existing lineage only when `fullchain.pem` and
  `privkey.pem` exist. A directory without usable files no longer suppresses
  issuance.
- If the existing certificate is self-signed (issuer equals subject), it is
  moved aside to `<certdir>.selfsigned.<timestamp>` before Certbot runs.
- Certbot plugin selection checks port 80: nginx, apache, or standalone. If
  another service owns port 80, the script warns and standalone may fail.
- Certbot uses `--register-unsafely-without-email --agree-tos`; no email or
  staging flag is exposed. Do not use production Certbot repeatedly while
  testing; use an isolated domain or a test CA.
- Self-signed mode skips the public IPv4 DNS requirement, which is required
  for isolated LAN/VPN deployments. It creates a 4096-bit RSA key and a
  36,500-day certificate with `subjectAltName`, `basicConstraints`,
  `keyUsage`, and `extendedKeyUsage=serverAuth`.
- Self-signed private keys are mode `0600` before group access is granted;
  the directory/key may be made group-readable by `postfix` so smtpd can load
  them after dropping privileges.
- The Certbot deploy hook reloads Postfix and Dovecot for the matching
  lineage, including wildcard renewals (`*.example.com`). It is not installed
  in self-signed mode, and only when `certbot` is present.

## TLS settings to preserve

- Postfix: certificate `fullchain.pem`, key `privkey.pem`,
  `smtpd_tls_security_level = may`, `smtp_tls_security_level = may`,
  `smtpd_tls_auth_only = yes`, TLS 1.2+ protocol exclusions. Optional weak
  cipher exclusion applies to both inbound and outbound when
  `allow_suboptimal_ciphers=no`.
- Postfix CA paths point at the system store. Opportunistic TLS does not
  verify peers; do not claim it does without a policy map or DANE.
- Dovecot: `ssl = required`, TLS 1.2 minimum, a restricted cipher list, DH
  parameters only when `/usr/share/dovecot/dh.pem` exists.
- Submission 587 requires TLS and auth; SMTPS 465 uses wrapper mode and
  requires auth.

## Firewall behavior

- The script writes `/etc/nftables.conf` and therefore replaces that file;
  the installer backs it up first. It manages a dedicated `inet emailwiz`
  table so other nftables tables can coexist. Do not claim the whole file is
  preserved.
- Input policy is `drop`, with established/related, loopback, ICMP, and TCP
  ports: selected SSH ports plus 22, 80, 443, 993, 465, 25, 587, 110, 995.
- SSH ports are read from `/etc/ssh/sshd_config` and
  `/etc/ssh/sshd_config.d/*.conf`, with a listening-socket fallback and 22 as
  the final fallback. Preserve this before applying a drop policy.
- The ruleset is syntax-checked with `nft -c -f` before restart. If the
  nftables service cannot restart, the script loads the file directly.
- Blocked packets are logged with prefix `emailwiz drop:`.
- fail2ban owns `emailwiz.local` and `emailwiz-backend.local`; jails are
  `postfix`, `postfix-sasl`, and `dovecot`. The obsolete inert `sieve` jail is
  removed on re-run. `ignoreip` includes loopback only. There is no explicit
  `sshd` jail or nftables-specific ban action.

## Procedure

1. Read `configure_ssl`, `configure_firewall`, `configure_fail2ban`, the
   Postfix and Dovecot TLS blocks, and `create_cronjob`.
2. Keep one `certdir` value flowing from TLS setup to both daemons. Do not
   hard-code a second path in Postfix or Dovecot.
3. Never require public DNS for self-signed mode; never reuse a self-signed
   certificate when `selfsigned=no`.
4. Preserve the SSH-port detection before any drop policy. Test firewall
   changes only with an out-of-band console.
5. Keep `/etc/nftables.conf` replacement and backup behavior documented.
6. When changing ports, update the README and the skill together. Port 143
   (plain IMAP) and 4190 (ManageSieve) are not opened; do not imply they are.
7. Keep fail2ban files deterministic and free of jails for services that do
   not listen.

## Validation

Static review:

- Confirm every certificate path used by Postfix/Dovecot matches `certdir`.
- Confirm self-signed mode has no Certbot dependency and Certbot mode has no
  stale self-signed reuse.
- Confirm the nftables port set includes every detected SSH port.
- Confirm fail2ban jails match enabled Dovecot protocols and Postfix.
- Confirm the renewal hook is skipped for self-signed mode.

In an isolated VM only: `openssl x509 -in <cert> -noout -subject -issuer
-dates`, `certbot certificates`, `nft -c -f /etc/nftables.conf`,
`nft list ruleset`, `ss -tlnp`, `fail2ban-client -t`, and service logs.
Test Certbot against a staging/test endpoint, never a production domain with
rate limits.

## Frequent problems

- Firewall applied before SSH port detection, locking out a non-22 daemon.
- `/etc/nftables.conf` overwritten with no backup.
- Certbot standalone fails because another web server owns port 80.
- A stale self-signed lineage prevents a trusted certificate from being
  issued, or a wildcard certificate is not reused by Postfix/Dovecot.
- Postfix chroot hides `/etc/letsencrypt` (managed services use chroot `n`).
- Port 465 accepts unauthenticated clients.
- fail2ban backend `systemd` without `python3-systemd`.
- Expecting fail2ban to whitelist an administrator automatically; only
  loopback is ignored by default.
- Opening 443 does not configure a web server for MTA-STS.

## References

- `emailwiz.bash` - `configure_ssl`, `configure_firewall`,
  `configure_fail2ban`, `create_cronjob`.
- `README.md` - certificates, self-signed mode, ports, MTA-STS, DANE.
- `nft(8)`, `nftables.conf(5)`, `certbot(1)`, Postfix TLS documentation,
  Dovecot SSL documentation, and fail2ban `jail.conf(5)`.
