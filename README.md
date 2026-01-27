# Email Server Setup Script

This script provisions a production-ready email server with sensible defaults for contemporary internet use. Contributions are welcome.

During the initial Postfix dialog, choose "Internet Site" and enter the bare domain (no subdomain), for example `uhden.dev`.

## This Script Installs

- **Postfix** for sending and receiving mail.
- **Dovecot** for client mail retrieval (IMAP/POP3).
- Configuration that binds Postfix and Dovecot securely via PAM authentication.
- **Spamassassin** for spam detection with support for custom filters.
- **OpenDKIM** to authenticate outbound mail for delivery to major providers.
- **Certbot** for TLS certificates, when not already present.
- **fail2ban** to harden exposed services with relevant jails enabled.
- (optional) **self-signed certificate** flow that replaces OpenDKIM and Certbot for isolated deployments (e.g., LAN/VPN-only notification sinks or private messaging relays).

## This Script Does _Not_...

- Use a SQL database or external identity store. All accounts are standard Unix users with PAM auth.
- Provide a webmail frontend (Roundcube, SquirrelMail, etc.). Use a regular mail client such as Thunderbird, Claws Mail, or Mutt.

## Prerequisites for Installation

1. A Debian or Ubuntu server.
2. DNS records that point at least your domain's `mail.` subdomain to your server's IP (IPv4 and IPv6). This is required on the initial run for Certbot to obtain an SSL certificate for your `mail.` subdomain.

## Mandatory Finishing Touches

### Unblock Your Ports

The script opens the mail ports locally, but many VPS providers block them by default. File a support request to have ports 25/465/587/993/995 (and 110 if needed) unblocked.

### DNS Records

At completion, the script prints DNS records required for authentication and deliverability. You must publish:

1. An MX record directing to `mail.yourdomain.tld`.
2. A TXT record for SPF (to reduce mail spoofing).
3. A TXT record for DMARC policies.
4. A TXT record with your public DKIM key. This record is long and **uniquely generated** while running `emailwiz.sh` and must be added after installation.

They will look something like this:

```
@	MX	10	mail.example.org
mail._domainkey.example.org    TXT     v=DKIM1; k=rsa; p=anextremelylongsequenceoflettersandnumbersgeneratedbyopendkim
_dmarc.example.org     TXT     v=DMARC1; p=reject; rua=mailto:dmarc@example.org; fo=1
example.org    TXT     v=spf1 mx a: -all
```

The records are also written to `~/dns_emailwiz` for reference.

### Add a rDNS/PTR Record as Well!

Configure reverse DNS (PTR) for both IPv4 and IPv6 to `mail.yourdomain.tld` via your VPS provider to avoid spam classification.

## Creating New Users/Mail Accounts

To add a user named Billy and allow him to receive mail, run:

```
useradd -m -G mail billy
passwd billy
```

Any user added to the `mail` group will be able to receive mail. If a user named Cassie already exists and you want to allow her to receive mail, run:

```
usermod -a -G mail cassie
```

A user's mail resides in `~/Mail/`. For local inspection over SSH you can install mutt, add `set spoolfile="+Inbox"` to `~/.muttrc`, and read/reply there. Remote access is recommended for routine use.

## Installing with Self-Signed Certificate, in "Isolated" Mode

This mode omits OpenDKIM and Certbot and issues a 100‑year self-signed certificate. You can preseed country, state/province, and organization fields. It targets isolated/LAN/VPN deployments (notification sink or private relay). Such a setup will **not** deliver mail directly to public providers (Gmail, Outlook, etc.).

Open the script and change the following line:

```
selfsigned="no" # yes or no
```

to become:

```
selfsigned="yes" # yes or no
```

You can also customize and automate the self-signed certificate creation by changing:

```
use_cert_config="no" # yes or no
```

to:

```
use_cert_config="yes" # yes or no
```

Then provide the certificate fields:

```
country_name="" # IT US UK IN etc.
state_or_province_name=""
organization_name=""
```

## Logging in from Email Clients (Thunderbird/mutt/etc.)

To access mail with Thunderbird, mutt, or other clients, use:

- SMTP server: `mail.uhden.dev`
- SMTP port: 465
- IMAP server: `mail.uhden.dev`
- IMAP port: 993

## MTA-STS and DANE for Improved Security

### MTA-STS

SMTP does not offer built-in security against man-in-the-middle attacks. To mitigate this risk, you can implement the MTA-STS policy, which instructs compatible senders to use verified TLS encryption when communicating with your server.

To implement this, create a file named `mta-sts.txt` with the following content and host it at `https://mta-sts.example.org/.well-known/`:

```
version: STSv1
mode: enforce
max_age: 604800
mx: mail.example.org
```

Then, add the following DNS records:

```
_mta-sts.example.org.   TXT    "v=STSv1; id=<id>"
_smtp._tls.example.org. TXT    "v=TLSRPTv1;rua=mailto:postmaster@example.org"
```
`<id>` can be an arbitrary number, but it's recommended to use the current Unix timestamp (`date +%s`).

### DANE

It's also recommended to set up a TLSA (DNSSEC/DANE) record for further security enhancement. Go [here](https://ssl-tools.net/tlsa-generator) to generate a TLSA record. Set the port to 25, Transport Protocol to "tcp", and specify the MX hostname as the Domain Name.

After adding the TLSA DNS record, enable opportunistic DANE in Postfix by doing the following:

```
postconf -e 'smtpd_use_tls = yes'
postconf -e 'smtp_dns_support_level = dnssec'
postconf -e 'smtp_tls_security_level = dane'

echo "dane       unix  -       -       n       -       -       smtp
  -o smtp_dns_support_level=dnssec
  -o smtp_tls_security_level=dane" >> /etc/postfix/master.cf
```

## Sites for Troubleshooting

Can't send or receive mail? Getting marked as spam? There are tools to double-check your DNS records and more:

- Always check `journalctl -xe` first for specific errors.
- [Check your DNS](https://intodns.com/)
- [Test your TXT records via mail](https://appmaildev.com/en/dkim)
- [Is your IP blacklisted?](https://mxtoolbox.com/blacklists.aspx)
- [mxtoolbox](https://mxtoolbox.com/SuperTool.aspx)
- [Check overall mail/website](https://internet.nl/)
- [Another great mail checker](https://www.checktls.com/#Website)
- [Check DANE](https://www.huque.com/bin/danecheck)