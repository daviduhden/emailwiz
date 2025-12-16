#!/bin/bash

if [[ -z ${ZSH_VERSION:-} ]] && command -v zsh >/dev/null 2>&1; then
	exec zsh "$0" "$@"
fi

set -euo pipefail

# Email Server Setup Script
# Copyright (C) 2019-2024 Luke Smith
# Copyright (C) 2025 David Uhden Collado
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Exit immediately if a command exits with a non-zero status,
# treat unset variables as an error, and prevent errors in a pipeline from being masked.

# Simple colored logging
if [[ -t 1 && ${NO_COLOR:-} != "1" ]]; then
	GREEN="\033[32m"
	YELLOW="\033[33m"
	RED="\033[31m"
	RESET="\033[0m"
else
	GREEN=""
	YELLOW=""
	RED=""
	RESET=""
fi

log() { printf '%s %b[INFO]%b ✅ %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$GREEN" "$RESET" "$*"; }
warn() { printf '%s %b[WARN]%b ⚠️ %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$YELLOW" "$RESET" "$*" >&2; }
error() { printf '%s %b[ERROR]%b ❌ %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$RED" "$RESET" "$*" >&2; }

# Function to ensure the script is run as root
check_root() {
	if [ "$(id -u)" -ne 0 ]; then
		error "This script must be run as root. Please run it again with 'sudo' or as the root user."
		exit 1
	fi
}

# Function to confirm installation instructions
confirm_installation() {
	cat <<EOF
BEFORE INSTALLING

Have a Debian or Ubuntu server with a static IP and DNS records (usually
A/AAAA) that point your domain name to it.

NOTE WHILE INSTALLING

On installation of Postfix, select "Internet Site" and put in TLD (without
\`mail.\` before it).

AFTER INSTALLING

More DNS records will be given to you to install. One of them will be
different for every installation and is uniquely generated on your machine.
EOF

	read -r -p "Have you read and understood the above instructions regarding the installation and configuration of the email server? (yes/no): " response
	if [ "$response" != "yes" ]; then
		error "Please read the instructions carefully before proceeding."
		exit 1
	fi
}

# Function to install required packages
install_packages() {
	umask 0022
	local packages=(postfix postfix-pcre dovecot-imapd dovecot-pop3d dovecot-sieve opendkim opendkim-tools spamassassin spamc net-tools fail2ban bind9-host)
	log "Stopping Dovecot and Postfix services..."
	systemctl -q stop dovecot
	systemctl -q stop postfix
	log "Purging existing packages..."
	apt-get purge --auto-remove -y "${packages[@]}"

	log "Installing required packages..."
	apt-get install -y "${packages[@]}"
}

# Function to configure SSL certificates
configure_ssl() {
	local domain="$1"
	local subdom="$2"
	local maildomain="$subdom.$domain"
	local certdir="/etc/letsencrypt/live/$maildomain"
	local selfsigned="no"
	local use_cert_config="no"
	local country_name=""
	local state_or_province_name=""
	local organization_name=""
	local common_name
	common_name=$(hostname -f | tr -d '[:space:]')

	if [ "$use_cert_config" = "yes" ]; then
		log "Creating certificate configuration..."
		mkdir -p "$certdir"
		chmod 700 "$certdir"
		echo "[req]
	default_bit = 4096
	distinguished_name = req_distinguished_name
	prompt = no

	[req_distinguished_name]
	countryName             = $country_name
	stateOrProvinceName     = $state_or_province_name
	organizationName        = $organization_name
	commonName              = $common_name " >"$certdir/certconfig.conf"
	fi

	log "Checking DNS records..."
	local ipv4
	ipv4=$(dig +short "$domain" | grep -m1 -Eo '([0-9]+\.){3}[0-9]+' | tr -d '[:space:]')
	[ -z "$ipv4" ] && {
		error "No IPv4 address found for the domain ($domain). Please ensure that your domain's DNS records are correctly configured to point to your server's IPv4 address."
		exit 1
	}
	local ipv6
	ipv6=$(dig +short "$domain" AAAA | grep -m1 -Eo '([0-9a-fA-F:]+)' | tr -d '[:space:]')
	[ -z "$ipv6" ] && {
		error "No IPv6 address found for your domain ($domain). Please ensure that your DNS records include an AAAA record pointing to your server's IPv6 address."
		exit 1
	}

	log "Opening required mail ports..."
	if command -v ufw >/dev/null 2>&1; then
		log "Opening required mail ports with ufw..."
		ufw allow 80,993,465,25,587,110,995/tcp 2>/dev/null
	else
		warn "ufw not found, opening required mail ports with iptables..."
		iptables -A INPUT -p tcp -m multiport --dports 80,993,465,25,587,110,995 -j ACCEPT
	fi

	if [ "$selfsigned" = "yes" ]; then
		log "Generating self-signed certificate..."
		mkdir -p "$certdir"
		chmod 700 "$certdir"
		rm -f "$certdir/privkey.pem"
		rm -f "$certdir/csr.pem"
		rm -f "$certdir/fullchain.pem"

		log "Generating a 4096 rsa key and a self-signed certificate that lasts 100 years"
		mkdir -p "$certdir"
		openssl genrsa -out "$certdir/privkey.pem" 4096

		if [ "$use_cert_config" = "yes" ]; then
			openssl req -new -key "$certdir/privkey.pem" -out "$certdir/csr.pem" -config "$certdir/certconfig.conf"
		else
			openssl req -new -key "$certdir/privkey.pem" -out "$certdir/csr.pem"
		fi
		openssl req -x509 -days 36500 -key "$certdir/privkey.pem" -in "$certdir/csr.pem" -out "$certdir/fullchain.pem"
	else
		log "Obtaining Let's Encrypt certificate..."
		ufw allow 80 2>/dev/null

		[ ! -d "$certdir" ] &&
			possiblecert="$(certbot certificates 2>/dev/null | grep "Domains:\.* \(\*\.$domain\|$maildomain\)\(\s\|$\)" -A 2 | awk '/Certificate Path/ {print $3}' | head -n1 | tr -d '[:space:]')" &&
			certdir="${possiblecert%/*}"

		[ ! -d "$certdir" ] &&
			certdir="/etc/letsencrypt/live/$maildomain" &&
			case "$(ss -tulpn | grep ":80\s")" in
			*nginx*)
				apt install -y python3-certbot-nginx
				certbot -d "$maildomain" certonly --nginx --register-unsafely-without-email --agree-tos
				;;
			*apache*)
				apt install -y python3-certbot-apache
				certbot -d "$maildomain" certonly --apache --register-unsafely-without-email --agree-tos
				;;
			*)
				apt install -y python3-certbot
				certbot -d "$maildomain" certonly --standalone --register-unsafely-without-email --agree-tos
				;;
			esac
	fi

	[ ! -f "$certdir/fullchain.pem" ] && echo "Error locating or installing SSL certificate." && exit 1
	[ ! -f "$certdir/privkey.pem" ] && echo "Error locating or installing SSL certificate." && exit 1
	if [ "$selfsigned" != "yes" ]; then
		[ ! -f "$certdir/cert.pem" ] && echo "Error locating or installing SSL certificate." && exit 1
	fi
}

# Function to configure Postfix
configure_postfix() {
	local domain="$1"
	local subdom="$2"
	local maildomain="$subdom.$domain"
	local certdir="/etc/letsencrypt/live/$maildomain"
	local allow_suboptimal_ciphers="yes"

	echo "Configuring Postfix's main.cf..."

	# Adding additional vars to fix an issue with receiving emails (relay access denied) and adding it to mydestination.
	postconf -e "myhostname = $maildomain"
	postconf -e "mail_name = $domain" #This is for the smtpd_banner
	postconf -e "mydomain = $domain"
	postconf -e "mydestination = \$myhostname, \$mydomain, mail, localhost.localdomain, localhost, localhost.\$mydomain"

	# Change the cert/key files to the default locations of the Let's Encrypt cert/key
	postconf -e "smtpd_tls_key_file=$certdir/privkey.pem"
	postconf -e "smtpd_tls_cert_file=$certdir/fullchain.pem"
	if [ "$selfsigned" != "yes" ]; then
		postconf -e "smtp_tls_CAfile=$certdir/cert.pem"
	fi

	# Enable, but do not require TLS. Requiring it with other servers would cause
	# mail delivery problems and requiring it locally would cause many other
	# issues.
	postconf -e 'smtpd_tls_security_level = may'
	postconf -e 'smtp_tls_security_level = may'

	# TLS required for authentication.
	postconf -e 'smtpd_tls_auth_only = yes'

	# Exclude insecure and obsolete encryption protocols.
	postconf -e 'smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1'
	postconf -e 'smtp_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1'
	postconf -e 'smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1'
	postconf -e 'smtp_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1'

	# Exclude suboptimal ciphers.
	if [ "$allow_suboptimal_ciphers" = "no" ]; then
		postconf -e 'tls_preempt_cipherlist = yes'
		postconf -e 'smtpd_tls_exclude_ciphers = aNULL, LOW, EXP, MEDIUM, ADH, AECDH, MD5, DSS, ECDSA, CAMELLIA128, 3DES, CAMELLIA256, RSA+AES, eNULL'
	fi

	# Here we tell Postfix to look to Dovecot for authenticating users/passwords.
	# Dovecot will be putting an authentication socket in /var/spool/postfix/private/auth
	postconf -e 'smtpd_sasl_auth_enable = yes'
	postconf -e 'smtpd_sasl_type = dovecot'
	postconf -e 'smtpd_sasl_path = private/auth'

	# helo, sender, relay and recipient restrictions
	postconf -e "smtpd_sender_login_maps = pcre:/etc/postfix/login_maps.pcre"
	postconf -e 'smtpd_sender_restrictions = permit_sasl_authenticated, permit_mynetworks, reject_sender_login_mismatch, reject_unknown_reverse_client_hostname, reject_unknown_sender_domain'
	postconf -e 'smtpd_recipient_restrictions = permit_sasl_authenticated, permit_mynetworks, reject_unauth_destination, reject_unknown_recipient_domain'
	postconf -e 'smtpd_relay_restrictions = permit_sasl_authenticated, reject_unauth_destination'
	postconf -e 'smtpd_helo_required = yes'
	postconf -e 'smtpd_helo_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_invalid_helo_hostname, reject_non_fqdn_helo_hostname, reject_unknown_helo_hostname'

	# NOTE: the trailing slash here, or for any directory name in the home_mailbox
	# command, is necessary as it distinguishes a maildir (which is the actual
	# directory that we want) from a spoolfile (which is what old unix boomers want
	# and no one else).
	postconf -e 'home_mailbox = Mail/Inbox/'

	# Prevent "Received From:" header in sent emails in order to prevent leakage of public ip addresses
	postconf -e "header_checks = regexp:/etc/postfix/header_checks"

	# strips "Received From:" in sent emails
	echo "/^Received:.*/     IGNORE
	/^X-Originating-IP:/    IGNORE" >>/etc/postfix/header_checks

	# Create a login map file that ensures that if a sender wants to send a mail from a user at our local
	# domain, they must be authenticated as that user
	echo "/^(.*)@${domain//./\.}$/   \${1}" >/etc/postfix/login_maps.pcre

	echo "Configuring Postfix's master.cf..."

	# Remove existing configurations from master.cf
	sed -i '
	/^\s*-o\s\+syslog_name=postfix\/submission/d
	/^\s*-o\s\+smtpd_tls_security_level=encrypt/d
	/^\s*-o\s\+smtpd_tls_auth_only=yes/d
	/^\s*-o\s\+smtpd_enforce_tls=yes/d
	/^\s*-o\s\+smtpd_client_restrictions=permit_sasl_authenticated,reject/d
	/^\s*-o\s\+smtpd_sender_restrictions=reject_sender_login_mismatch/d
	/^\s*-o\s\+smtpd_sender_login_maps=pcre:\/etc\/postfix\/login_maps.pcre/d
	/^\s*-o\s\+smtpd_recipient_restrictions=permit_sasl_authenticated,reject_unauth_destination/d
	' /etc/postfix/master.cf

	cat >>/etc/postfix/master.cf <<'EOF'
smtp unix - - n - - smtp
smtp inet n - y - - smtpd
	-o content_filter=spamassassin
submission inet n       -       y       -       -       smtpd
	-o syslog_name=postfix/submission
	-o smtpd_tls_security_level=encrypt
	-o smtpd_tls_auth_only=yes
	-o smtpd_enforce_tls=yes
	-o smtpd_client_restrictions=permit_sasl_authenticated,reject
	-o smtpd_sender_restrictions=reject_sender_login_mismatch
	-o smtpd_sender_login_maps=pcre:/etc/postfix/login_maps.pcre
	-o smtpd_recipient_restrictions=permit_sasl_authenticated,reject_unauth_destination
smtps     inet  n       -       y       -       -       smtpd
	-o syslog_name=postfix/smtps
	-o smtpd_tls_wrappermode=yes
	-o smtpd_sasl_auth_enable=yes
spamassassin unix -     n       n       -       -       pipe
	user=debian-spamd argv=/usr/bin/spamc -f -e /usr/sbin/sendmail -oi -f ${sender} ${recipient}
EOF
}

# Function to configure Dovecot
configure_dovecot() {
	local domain="$1"
	local subdom="$2"
	local maildomain="$subdom.$domain"
	local certdir="/etc/letsencrypt/live/$maildomain"
	local mailbox_format="maildir"
	local allowed_protocols=" imap pop3 "

	echo "Creating Dovecot config..."

	# By default, dovecot has a bunch of configs in /etc/dovecot/conf.d/ These
	# files have nice documentation if you want to read it, but it's a huge pain to
	# go through them to organize.  Instead, we simply overwrite
	# /etc/dovecot/dovecot.conf because it's easier to manage. You can get a backup
	# of the original in /usr/share/dovecot if you want.
	mv /etc/dovecot/dovecot.conf /etc/dovecot/dovecot.backup.conf

	echo "# Dovecot config
	# Note that in the dovecot conf, you can use:
	# %u for username
	# %n for the name in name@domain.tld
	# %d for the domain
	# %h the user's home directory

	ssl = required
	ssl_cert = <$certdir/fullchain.pem
	ssl_key = <$certdir/privkey.pem
	ssl_min_protocol = TLSv1.2
	ssl_cipher_list = "'EECDH+ECDSA+AESGCM:EECDH+aRSA+AESGCM:EECDH+ECDSA+SHA256:EECDH+aRSA+SHA256:EECDH+ECDSA+SHA384:EECDH+ECDSA+SHA256:EECDH+aRSA+SHA384:EDH+aRSA+AESGCM:EDH+aRSA+SHA256:EDH+aRSA:EECDH:!aNULL:!eNULL:!MEDIUM:!LOW:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS:!RC4:!SEED'"
	ssl_prefer_server_ciphers = yes
	ssl_dh = </usr/share/dovecot/dh.pem
	auth_mechanisms = plain login
	auth_username_format = %n

	protocols = \$protocols $allowed_protocols

	# Search for valid users in /etc/passwd
	userdb {
		driver = passwd
	}
	#Fallback: Use plain old PAM to find user passwords
	passdb {
		driver = pam
	}

	# Our mail for each user will be in ~/Mail, and the inbox will be ~/Mail/Inbox
	# The LAYOUT option is also important because otherwise, the boxes will be \`.Sent\` instead of \`Sent\`.
	mail_location = $mailbox_format:~/Mail:INBOX=~/Mail/Inbox:LAYOUT=fs
	namespace inbox {
		inbox = yes
		mailbox Drafts {
		special_use = \\Drafts
		auto = subscribe
	}
		mailbox Junk {
		special_use = \\Junk
		auto = subscribe
		autoexpunge = 30d
	}
		mailbox Sent {
		special_use = \\Sent
		auto = subscribe
	}
		mailbox Trash {
		special_use = \\Trash
	}
		mailbox Archive {
		special_use = \\Archive
	}
	}

	# Here we let Postfix use Dovecot's authentication system.
	service auth {
	  unix_listener /var/spool/postfix/private/auth {
		mode = 0660
		user = postfix
		group = postfix
	}
	}

	protocol lda {
	  mail_plugins = \$mail_plugins sieve
	}

	protocol lmtp {
	  mail_plugins = \$mail_plugins sieve
	}

	protocol pop3 {
	  pop3_uidl_format = %08Xu%08Xv
	  pop3_no_flag_updates = yes
	}

	plugin {
		sieve = ~/.dovecot.sieve
		sieve_default = /var/lib/dovecot/sieve/default.sieve
		#sieve_global_path = /var/lib/dovecot/sieve/default.sieve
		sieve_dir = ~/.sieve
		sieve_global_dir = /var/lib/dovecot/sieve/
	grep -q '^vmail:' /etc/passwd || useradd -r -m vmail || true
	" >/etc/dovecot/dovecot.conf

	# If using an old version of Dovecot, remove the ssl_dl line.
	case "$(dovecot --version)" in
	1 | 2.1* | 2.2*) sed -i '/^ssl_dh/d' /etc/dovecot/dovecot.conf ;;
	esac
	grep -q '^vmail:' /etc/passwd || useradd -r -m vmail
	mkdir -p /var/lib/dovecot/sieve/
	chmod 700 /var/lib/dovecot/sieve/

	echo 'require ["fileinto", "mailbox"];
	if header :contains "X-Spam-Flag" "YES"
		{
			fileinto "Junk";
		}' >/var/lib/dovecot/sieve/default.sieve

	chown -R vmail:vmail /var/lib/dovecot
	sievec /var/lib/dovecot/sieve/default.sieve

	echo 'Preparing user authentication...'
	grep -q 'auth    required        pam_unix.so nullok' /etc/pam.d/dovecot || echo 'auth    required        pam_unix.so nullok' >>/etc/pam.d/dovecot
	grep -q 'account required        pam_unix.so' /etc/pam.d/dovecot || echo 'account required        pam_unix.so' >>/etc/pam.d/dovecot
}

# Function to configure OpenDKIM
configure_opendkim() {
	local domain="$1"
	local subdom="$2"
	local maildomain="$subdom.$domain"

	echo "Generating OpenDKIM keys..."

	# A lot of the big name email services, like Google, will automatically reject
	# as spam unfamiliar and unauthenticated email addresses. As in, the server
	# will flatly reject the email, not even delivering it to someone's Spam
	# folder.

	# OpenDKIM is a way to authenticate your email so you can send to such services
	# without a problem.

	# Create an OpenDKIM key in the proper place with proper permissions.
	echo 'Generating OpenDKIM keys...'
	mkdir -p "/etc/postfix/dkim/$domain"
	sudo chmod 700 "/etc/postfix/dkim/$domain"
	sudo chmod -R g+r /etc/postfix/dkim/*

	echo "Configuring OpenDKIM..."

	# Generate the OpenDKIM info:
	echo 'Configuring OpenDKIM...'
	grep -q "$domain" /etc/postfix/dkim/keytable 2>/dev/null ||
		echo "$subdom._domainkey.$domain $domain:$subdom:/etc/postfix/dkim/$domain/$subdom.private" >>/etc/postfix/dkim/keytable

	grep -q "$domain" /etc/postfix/dkim/signingtable 2>/dev/null ||
		echo "*@$domain $subdom._domainkey.$domain" >>/etc/postfix/dkim/signingtable

	grep -q '127.0.0.1' /etc/postfix/dkim/trustedhosts 2>/dev/null ||
		echo '127.0.0.1
	10.1.0.0/16' >>/etc/postfix/dkim/trustedhosts

	# ...and source it from opendkim.conf
	grep -q '^KeyTable' /etc/opendkim.conf 2>/dev/null || echo 'KeyTable file:/etc/postfix/dkim/keytable
	SigningTable refile:/etc/postfix/dkim/signingtable
	InternalHosts refile:/etc/postfix/dkim/trustedhosts' >>/etc/opendkim.conf

	sed -i '/^#Canonicalization/s/simple/relaxed\/simple/' /etc/opendkim.conf
	sed -i '/^#Canonicalization/s/^#//' /etc/opendkim.conf

	sed -i '/Socket/s/^#*/#/' /etc/opendkim.conf
	grep -q '^Socket\s*inet:12301@localhost' /etc/opendkim.conf || echo 'Socket inet:12301@localhost' >>/etc/opendkim.conf

	# OpenDKIM daemon settings, removing previously activated socket.
	sed -i '/^SOCKET/d' /etc/default/opendkim && echo 'SOCKET="inet:12301@localhost"' >>/etc/default/opendkim

	echo "Configuring Postfix with OpenDKIM settings..."

	# Here we add to postconf the needed settings for working with OpenDKIM
	echo 'Configuring Postfix with OpenDKIM settings...'
	postconf -e 'smtpd_sasl_security_options = noanonymous, noplaintext'
	postconf -e 'smtpd_sasl_tls_security_options = noanonymous'
	postconf -e "myhostname = $maildomain"
	postconf -e 'milter_default_action = accept'
	postconf -e 'milter_protocol = 6'
	postconf -e 'smtpd_milters = inet:localhost:12301'
	postconf -e 'non_smtpd_milters = inet:localhost:12301'
	postconf -e 'mailbox_command = /usr/lib/dovecot/deliver'

	# Long-term fix to prevent SMTP smuggling
	postconf -e 'smtpd_forbid_bare_newline = normalize'
	postconf -e "smtpd_forbid_bare_newline_exclusions = \$mynetworks"

	# A fix for "Opendkim won't start: can't open PID file?", as specified here: https://serverfault.com/a/847442
	/lib/opendkim/opendkim.service.generate
	systemctl daemon-reload
}

# Function to configure fail2ban
configure_fail2ban() {
	echo "Enabling fail2ban security for dovecot and postfix..."

	# Enable fail2ban security for dovecot and postfix.
	[ ! -f /etc/fail2ban/jail.d/emailwiz.local ] && echo "[postfix]
enabled = true
[postfix-sasl]
enabled = true
[sieve]
enabled = true
[dovecot]
enabled = true" >/etc/fail2ban/jail.d/emailwiz.local

	sed -i "s|^backend = auto$|backend = systemd|" /etc/fail2ban/jail.conf
}

# Function to configure SpamAssassin
configure_spamassassin() {
	echo "Enabling SpamAssassin update cronjob..."

	# Enable SpamAssassin update cronjob.
	if [ -f /etc/default/spamassassin ]; then
		sed -i "s|^CRON=0|CRON=1|" /etc/default/spamassassin
		printf "Restarting spamassassin..."
		service spamassassin restart && printf ' ...done\n'
		systemctl enable spamassassin
	elif [ -f /etc/default/spamd ]; then
		sed -i "s|^CRON=0|CRON=1|" /etc/default/spamd
		printf "Restarting spamd..."
		service spamd restart && printf ' ...done\n'
		systemctl enable spamd
	else
		printf "!!! Neither /etc/default/spamassassin or /etc/default/spamd exists, this is unexpected and needs to be investigated"
	fi
}

# Function to restart services
restart_services() {
	echo "Restarting services..."
	for x in opendkim dovecot postfix fail2ban; do
		printf "Restarting %s..." "$x"
		service "$x" restart && printf ' ...done\n'
		systemctl enable "$x"
	done
}

# Function to create cronjob for postmaster
create_cronjob() {
	echo "Creating cronjob to delete month-old postmaster mails..."
	cat <<EOF >/etc/cron.weekly/postmaster-clean
#!/bin/sh

find /home/postmaster/Mail -type f -mtime +30 -name '*.mail*' -delete >/dev/null 2>&1
exit 0
EOF
	chmod 700 /etc/cron.weekly/postmaster-clean

	grep -q "^deploy-hook = echo \"\$RENEWED_DOMAINS\" | grep -q '$maildomain' && service postfix reload && service dovecot reload" /etc/letsencrypt/cli.ini ||
		echo "deploy-hook = echo \"\$RENEWED_DOMAINS\" | grep -q '$maildomain' && service postfix reload && service dovecot reload" >>/etc/letsencrypt/cli.ini
}

# Function to generate DNS entries
generate_dns_entries() {
	local domain="$1"
	local subdom="$2"
	local maildomain="$subdom.$domain"
	local pval
	pval=$(tr -d '\n' </etc/postfix/dkim/"$domain"/"$subdom".txt | sed "s/k=rsa.* \"p=/k=rsa; p=/;s/\"\s*\"//;s/\"\s*).*//" | grep -o 'p=.*')
	local dkimentry="$subdom._domainkey.$domain	TXT	v=DKIM1; k=rsa; $pval"
	local dmarcentry="_dmarc.$domain	TXT	v=DMARC1; p=reject; rua=mailto:dmarc@$domain; fo=1"
	local spfentry="$domain	TXT	v=spf1 mx a:$maildomain -all"
	local mxentry="$domain	MX	10	$maildomain"

	echo "Generating DNS entries..."
	if ! id -u postmaster >/dev/null 2>&1; then
		if ! sudo useradd -r -m -G mail postmaster; then
			echo "Error: Failed to create postmaster user."
			exit 1
		fi
	fi

	cat >"$HOME/dns_emailwizard" <<EOF
NOTE: Elements in the entries might appear in a different order in your registrar's DNS settings.
$dkimentry
$dmarcentry
$spfentry
$mxentry
EOF
}

# Function to display final output message
final_output_message() {
	local dkimentry="$1"
	local dmarcentry="$2"
	local spfentry="$3"
	local mxentry="$4"

	cat <<EOF
\033[31m
 _   _
| \ | | _____      ___
|  \| |/ _ \ \ /\ / (_)
| |\  | (_) \ V  V / _
|_| \_|\___/ \_/\_/ (_)\033[0m

Add these three records to your DNS TXT records on either your registrar's site
or your DNS server:
\033[32m
$dkimentry

$dmarcentry

$spfentry

$mxentry
\033[0m
NOTE: You may need to omit the \`.$domain\` portion at the beginning if
inputting them in a registrar's web interface.

Also, these are now saved to \033[34m~/dns_emailwizard\033[0m in case you want them in a file.

Once you do that, you're done! Check the README for how to add users/accounts
and how to log in.
EOF
}

# Main script execution
main() {
	check_root
	confirm_installation
	install_packages

	domain="$(hostname --domain | tr -d '[:space:]')"
	subdom=${MAIL_SUBDOM:-mail}
	maildomain="$subdom.$domain"

	configure_ssl "$domain" "$subdom"
	configure_postfix "$domain" "$subdom"
	configure_dovecot "$domain" "$subdom"
	configure_opendkim "$domain" "$subdom"
	configure_fail2ban
	configure_spamassassin
	restart_services
	create_cronjob
	generate_dns_entries "$domain" "$subdom"
	final_output_message "$dkimentry" "$dmarcentry" "$spfentry" "$mxentry"
}

main "$@"
