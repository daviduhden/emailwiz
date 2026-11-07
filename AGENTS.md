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

There is no Makefile, test suite, package manifest, or shared shell library.
The only CI configuration is the read-only pull-request workflow, which runs
the shared agent-validator contract suite and range gate. Do not describe
commands or files that do not exist.

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

## GitHub Actions pin maintenance

`.github/workflows/agent-knowledge-validation.yml` pins every external action
to an immutable 40-character commit SHA; tags and branches are not acceptable.
Update a pin only after verifying the release SHA, and change the `uses:` line
and its trailing `# vX.Y.Z` comment together. Do not change triggers,
permissions, concurrency, job names, or commands while updating a pin.

| Action | Version | Commit SHA |
| --- | --- | --- |
| `actions/checkout` | `v7.0.1` | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| `actions/upload-artifact` | `v7.0.2` | `cf430e030ddbb5b0abf93d22962f4752f3646cd9` |
| `actions/cache` | `v6.1.0` | `55cc8345863c7cc4c66a329aec7e433d2d1c52a9` |
| `actions/setup-java` | `v6.2.0` | `77dd5b2ce225ea11469928ac317850245a74ae78` |
| `actions/setup-node` | `v7.1.0` | `949feb2413d6458794dcd2491c4babbbce0c15c1` |

Validate a workflow edit with `actionlint .github/workflows/*.yml` and, when a
`yamllint` configuration exists, `yamllint -c <config> .github/workflows`.

## Continuous Agent & Skills Maintenance

Every repository change MUST trigger an Agent & Skills Maintenance Review.
Agent instructions and skills are living repository artifacts. Before
completing any repository modification, review all applicable `AGENTS.md`
files, specialized agents, and `SKILL.md` files. Update the affected knowledge
artifacts to reflect the implementation, correct outdated instructions, and
incorporate reusable knowledge. A task is incomplete until knowledge
synchronization has been performed and validated. Never skip synchronization
silently or claim that unexecuted checks have passed.

After each change:

1. Identify and review the applicable agents and skills, even when no update
   initially appears necessary.
2. Update relevant operational guidance, reusable procedures, references,
   commands, and paths; remove stale or contradictory instructions.
3. Do not use whitespace-only, timestamp-only, empty, or otherwise cosmetic
   edits to satisfy synchronization. For a project change, at least one
   relevant knowledge artifact must receive a substantive update.
4. Run `perl scripts/validate-agent-knowledge.pl --scope worktree` and the
   applicable project checks. For a pull request, CI compares the base and head
   revisions with `--scope range --base BASE_SHA --head HEAD_SHA`.
5. Review the validator output and final diff, then report the synchronization
   result. Warnings require human review; a structural pass does not establish
   semantic relevance.

Run the validator tests with
`prove tests/agent_knowledge_validator/test_validator.pl`.
The validator is read-only and uses Perl 5.14+ (JSON::PP core) and the standard library. It
must not be confused with project-specific validation or installation tools.
See [Agent Knowledge Validation Contract](docs/agent-knowledge-validation.md)
for AK001–AK006, JSON schema, exit codes, configuration, and maintenance rules.

All repositories must implement the same Agent Knowledge Validation CLI
contract, rule identifiers, output conventions and exit codes. Repository-
specific validations may extend the canonical behavior but must not silently
redefine it. Any change to the validator contract must be reflected in the
repository's agent instructions, related skills and tests.
