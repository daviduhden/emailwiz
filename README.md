# Email Server Setup Script

This script provisions a production-ready email server with sensible defaults for contemporary internet use. Contributions are welcome.

I've linked this file on Github to a shorter, more memorable address on my LARBS.xyz domain, so you can get it on your machine with this short command:

## This Script Installs

- **Postfix** for sending and receiving mail.
- **Dovecot** for client mail retrieval (IMAP/POP3).
- Configuration that binds Postfix and Dovecot securely via PAM authentication.
- **Spamassassin** for spam detection with support for custom filters.
- **OpenDKIM** to authenticate outbound mail for delivery to major providers.
- **Certbot** for TLS certificates, when not already present.
- **fail2ban** to harden exposed services with relevant jails enabled.
- (optional) **self-signed certificate** flow that replaces OpenDKIM and Certbot for isolated deployments (e.g., LAN/VPN-only notification sinks or private messaging relays).

## This script does _not_...

- use a SQL database or anything like that. We keep it simple and use normal
  Unix system users for accounts and passwords.
- set up a graphical web interface for mail like Roundcube or Squirrel Mail.
  You are expected to use a normal mail client like Thunderbird or K-9 for
  Android or good old mutt with
  [mutt-wizard](https://github.com/lukesmithxyz/mutt-wizard). Note that there
  is a guide for [Rainloop](https://landchad.net/rainloop/) on
  [LandChad.net](https://landchad.net) for those that want such a web
  interface.

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

Configuring an email server is a living nightmare and that's why I made this script so I wouldn't have to do it again.
Don't ask me to configure your email server unless you are paying me big bucks to do it.
With this script and the comments in it, I've given you way more than I owe you.

If something is broken, start a PR to fix it, but ***do not*** open Issues about some problem you have unless you have figured out a solution and are offering a way for me to add a small change that will make this script more robust.
Your mindset in running this script should be "Oh, look, it puts all the commands in a bash-readable format, so I can run it and troubleshoot errors as they come up.".
The script works for me and if it works for you without a problem, be thankful and feel lucky because setting up email is usually just so much less forgiving.

If you decide to start a VPS, specifically Vultr since I made this script and have tempered it most on their default setup,
use [this referal link of mine](https://www.vultr.com/?ref=7914655-4F) because you get a free $50 credit, and if you stay on the site, then eventually I'll get a kickback too.
I honestly don't have a really strong preference of Vultr over other VPS providers, but they're about as cheap and reliable as it gets and if we can get free money, lol whatever click the link 👏👏.

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
- Username `luke` (i.e. *not* `luke@lukesmith.xyz`)

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

## Benefited from this?

I am always glad to hear this script is still making life easy for people. If
this script or documentation has saved you some frustration, donate here:

- btc: `bc1qzw6mk80t3vrp2cugmgfjqgtgzhldrqac5axfh4`
- xmr: `8A5v4Ci11Lz7BDoE2z2oPqMoNHzr5Zj8B3Q2N2qzqrUKhAKgNQYGSSaZDnBUWg6iXCiZyvC9mVCyGj5kGMJTi1zGKGM4Trm`

- Always check `journalctl -xe` to see the specific problem.
- Check with your VPS host and ask them to enable mail ports. Some providers
  disable them by default. It shouldn't take any time.
- Go to [this site](https://appmaildev.com/en/dkim) to test your TXT records.
  If your DKIM, SPF or DMARC tests fail you probably copied in the TXT records
  incorrectly.
- If everything looks good and you *can* send mail, but it still goes to Gmail
  or another big provider's spam directory, your domain (especially if it's a
  new one) might be on a public spam list.  Check
  [this site](https://mxtoolbox.com/blacklists.aspx) to see if it is. Don't
  worry if you are: sometimes especially new domains are automatically assumed
  to be spam temporarily. If you are blacklisted by one of these, look into it
  and it will explain how to remove yourself.
