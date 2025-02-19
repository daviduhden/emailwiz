# Email Server Setup Script

This script installs a fully-featured email server suitable for modern web use. Any contribution is highly appreciated.

When prompted by a dialog menu at the beginning, select "Internet Site" and enter your full domain without any subdomain, e.g., `uhden.dev`.

## This Script Installs

- **Postfix** for sending and receiving mail.
- **Dovecot** for retrieving mail to your email client (e.g., mutt, Thunderbird).
- Configuration files that securely link Postfix and Dovecot with native PAM logins.
- **Spamassassin** to prevent spam and allow custom filters.
- **OpenDKIM** to validate your emails so you can send to Gmail and other major providers.
- **Certbot** for SSL certificates, if not already present.
- **fail2ban** to enhance server security, with enabled modules for the above programs.

## This Script Does _Not_...

- Use a SQL database or similar. It keeps things simple by using standard Unix system users for accounts and passwords.
- Set up a graphical web interface for mail like Roundcube or Squirrel Mail. You are expected to use a standard mail client like Thunderbird, Claws Mail or Mutt.

## Prerequisites for Installation

1. A Debian or Ubuntu server.
2. DNS records that point at least your domain's `mail.` subdomain to your server's IP (IPv4 and IPv6). This is required on the initial run for Certbot to obtain an SSL certificate for your `mail.` subdomain.

## Mandatory Finishing Touches

### Unblock Your Ports

While the script enables your mail ports on your server, it is common practice for VPS providers to block mail ports by default. Open a help ticket with your VPS provider asking them to open your mail ports, and they will do so promptly.

### DNS Records

At the end of the script, you will be given some DNS records to add to your DNS server or registrar's website. These records are primarily for authenticating your emails as non-spam. The four records are:

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

The script will create a file, `~/dns_emailwiz`, that lists the records for your convenience and also prints them at the end of the script.

### Add a rDNS/PTR Record as Well!

Set a reverse DNS or PTR record to avoid getting marked as spam. You can do this at your VPS provider, and it should be set to `mail.yourdomain.tld`. Note that you should set this for both IPv4 and IPv6.

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

A user's mail will appear in `~/Mail/`. If you want to see your mail while SSH'd into the server, you could install mutt, add `set spoolfile="+Inbox"` to your `~/.muttrc`, and use mutt to view and reply to mail. However, you'll probably want to log in remotely:

## Logging in from Email Clients (Thunderbird/mutt/etc.)

To access your mail with Thunderbird, mutt, or another email program, use the following server information for your domain:

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