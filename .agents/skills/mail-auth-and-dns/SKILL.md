---
name: mail-auth-and-dns
description: Work on OpenDKIM, SPF, DKIM, DMARC, MX, PTR, and the DNS output of emailwiz and adddomain.bash.
---

# Mail Authentication and DNS

## When to use

Use this skill when changing OpenDKIM key generation, DKIM tables, signing,
DMARC/SPF/MX record output, `adddomain.bash` DNS behavior, or documentation
about MTA-STS, DANE, and reverse DNS.

## What the scripts actually do

- OpenDKIM generates one 2048-bit RSA key per domain with selector
  `MAIL_SUBDOM` (default `mail`):
  `/etc/postfix/dkim/<domain>/<selector>.private` and `.txt`.
- Keys are created only when the private key is absent. Re-runs and repeated
  `adddomain.bash` calls do not rotate keys, because that would invalidate
  published DNS.
- DKIM directories are mode `0750`, private keys are mode `0640`, and the
  `opendkim` group gets read/traverse access. Do not restore the older
  `chmod 700` plus `g+r` combination, which leaves the group unable to
  traverse the directory.
- `keytable` maps `<selector>._domainkey.<domain>` to
  `<domain>:<selector>:<private-key-path>`.
- `signingtable` signs `*@<domain>` and the mail host
  `*@<subdom>.<domain>` with that domain's key.
- `trustedhosts` contains loopback ranges (`127.0.0.0/8` and `::1`); the
  old hard-coded `10.1.0.0/16` network is not added.
- `opendkim.conf` gets `KeyTable`, `SigningTable`, `InternalHosts`,
  `Mode sv`, canonicalization `relaxed/simple`, and
  `Socket inet:12301@localhost`. Postfix uses that milter socket with
  `milter_default_action = accept` (fail-open for availability).
- The generated records are:
  - `MX 10 <subdom>.<domain>` for the base domain.
  - `TXT v=spf1 mx a:<subdom>.<domain> -all`.
  - `TXT v=DMARC1; p=reject; rua=mailto:dmarc@<domain>; fo=1`.
  - `TXT v=DKIM1; k=rsa; p=<public-key>` at
    `<selector>._domainkey.<domain>`.
- Main records go to `~/dns_emailwizard`; added-domain records go to
  `~/dns_emailwizard_added`. Both are mode `0600` and use the invoking sudo
  user's home when available.
- `adddomain.bash` adds the new domain to `mydestination`, the PCRE login
  map, OpenDKIM key/signing tables, and appends only missing DNS lines.
  It does not create a user, mailbox, TLS certificate, or DNS provider
  record.
- PTR/rDNS, MTA-STS, TLS-RPT, CAA, and DANE are manual steps documented in
  `README.md`; the scripts do not publish them.
- `dmarc: postmaster` is ensured in `/etc/aliases` and a `postmaster` system
  user is created so aggregate reports have a local destination.

## Procedure

1. Read `configure_opendkim`, `generate_dns_entries` in both scripts, and the
   DNS section of `README.md`.
2. Keep selector, key path, keytable, signingtable, and DNS record consistent.
   A selector mismatch silently produces a key that no receiver can validate.
3. Never overwrite an existing private key. If a `.txt` file is missing,
   abort with a clear error instead of emitting `p=` with no key.
4. Parse the public key by concatenating the quoted TXT chunks and stripping
   quotes/whitespace. Validate that the result contains only base64
   characters before writing DNS output.
5. When changing SPF or DMARC, keep the README examples and the generated
   strings in sync. `p=reject` and `-all` are strict defaults; document the
   risk during rollout.
6. When changing `adddomain.bash`, check the installed Postfix
   `myhostname`/`mydomain` and `MAIL_SUBDOM` before writing records. Refuse to
   emit MX/SPF for the wrong mail host.
7. Keep DNS-file appends deduplicated. Re-running `adddomain.bash` must not
   duplicate records.

## Validation

Static review:

- Confirm key path, selector, and table entries agree.
- Confirm the DKIM TXT value starts with `v=DKIM1; k=rsa; p=` and the key is
  non-empty base64.
- Confirm DMARC `rua` has a deliverable alias/mailbox.
- Confirm `adddomain.bash` does not promise a key rotation or DNS API call.

In an isolated environment with the domain's DNS available:
`opendkim-testkey -d <domain> -s <selector> -k <private-key>` and
`dig +short TXT <selector>._domainkey.<domain>`; compare with the generated
record. Check `postfix check` and the OpenDKIM/Postfix logs. Never run these
against a production domain you do not control.

## Frequent problems

- OpenDKIM starts in verify-only mode because `Mode` was left as `v`; the
  script sets `Mode sv`.
- Key directory lacks group execute permission, so OpenDKIM cannot open the
  private key.
- `MAIL_SUBDOM` differs between installation and `adddomain.bash`, producing
  a selector or MX host that does not match.
- DKIM TXT extraction leaves quote fragments or spaces from a multi-line
  `opendkim-genkey` file.
- DMARC reports bounce because `dmarc@` has no alias or mailbox.
- SPF hard-codes the mail host while the actual MX points elsewhere.
- `adddomain.bash` appends the same DNS block on every run.
- Publishing `p=reject` before DKIM/SPF are verified, causing legitimate mail
  to be rejected.
- Forgetting PTR/rDNS; the script does not create it.

## References

- `emailwiz.bash` - `configure_opendkim`, `generate_dns_entries`.
- `adddomain.bash` - `create_dkim`, `update_dkim_tables`,
  `generate_dns_entries`.
- `README.md` - DNS records, PTR, MTA-STS, and DANE.
- OpenDKIM `opendkim.conf(5)`, `opendkim-genkey(8)`, and `opendkim-testkey(8)`.

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
