#!/bin/bash

set -euo pipefail

# Email Server Setup Script
# Copyright (C) 2019-2024 Luke Smith
# Copyright (C) 2025-2026 David Uhden Collado
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
# treat unset variables as an error, and prevent errors in a
# pipeline from being masked.

log() {
	printf '%s [INFO] %s\n' \
		"$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}
warn() {
	printf '%s [WARN] %s\n' \
		"$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2
}
error() {
	printf '%s [ERROR] %s\n' \
		"$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2
}
selfsigned="no"                # yes or no
allow_suboptimal_ciphers="yes" # yes = keep weak ciphers, no = exclude

# Init system detection for Devuan/Debian/Ubuntu compatibility
_init=""
detect_init() {
	if [ ! -f /proc/1/comm ]; then
		_init="unknown"
	elif grep -qFx 'systemd' /proc/1/comm 2>/dev/null; then
		_init="systemd"
	elif grep -qFx 'runit' /proc/1/comm 2>/dev/null; then
		_init="runit"
	elif grep -qFx 'init' /proc/1/comm 2>/dev/null; then
		if command -v rc-service >/dev/null 2>&1; then
			_init="openrc"
		else
			_init="sysvinit"
		fi
	else
		_init="unknown"
	fi
	log "Detected init system: $_init"
}

svc_stop() {
	case "$_init" in
	systemd) systemctl -q stop "$1" 2>/dev/null || true ;;
	openrc) rc-service "$1" stop 2>/dev/null || true ;;
	runit) sv stop "$1" 2>/dev/null || true ;;
	*) service "$1" stop 2>/dev/null || true ;;
	esac
}

svc_restart() {
	case "$_init" in
	systemd) systemctl restart "$1" ;;
	openrc) rc-service "$1" restart ;;
	runit) sv restart "$1" ;;
	*) service "$1" restart ;;
	esac
}

svc_reload() {
	local _svc
	for _svc in "$@"; do
		case "$_init" in
		systemd) systemctl reload "$_svc" 2>/dev/null ||
			systemctl restart "$_svc" ;;
		openrc) rc-service "$_svc" reload 2>/dev/null ||
			rc-service "$_svc" restart ;;
		runit) sv reload "$_svc" 2>/dev/null ||
			sv restart "$_svc" ;;
		*) service "$_svc" reload 2>/dev/null ||
			service "$_svc" restart ;;
		esac
	done
}

svc_enable() {
	case "$_init" in
	systemd) systemctl enable "$1" ;;
	openrc) rc-update add "$1" 2>/dev/null || true ;;
	runit)
		# Void and Alpine use /var/service; Devuan's runit uses
		# /etc/service. Enable in whichever directory exists.
		local _dir
		for _dir in /var/service /etc/service; do
			if [ -d "$_dir" ]; then
				[ -d "/etc/sv/$1" ] &&
					[ ! -L "$_dir/$1" ] &&
					ln -s "/etc/sv/$1" "$_dir/"
				return 0
			fi
		done
		if [ -d "/etc/sv/$1" ]; then
			mkdir -p /var/service
			ln -s "/etc/sv/$1" /var/service/
		fi
		;;
	*) update-rc.d "$1" defaults 2>/dev/null || true ;;
	esac
}

svc_daemon_reload() {
	case "$_init" in
	systemd) systemctl daemon-reload ;;
	*) : ;;
	esac
}

# Return the appropriate postfix/dovecot reload command for certbot hooks
svc_reload_cmd() {
	case "$_init" in
	systemd) printf '%s' 'systemctl reload' ;;
	runit) printf '%s' 'sv reload' ;;
	openrc) printf '%s' 'rc-service' ;;
	*) printf '%s' 'service' ;;
	esac
}

# Function to ensure the script is run as root
check_root() {
	if [ "$(id -u)" -ne 0 ]; then
		error "This script must be run as root." \
			"Please run it again with 'sudo' or as the root user."
		exit 1
	fi
}

# Function to confirm installation instructions
confirm_installation() {
	cat <<EOF
BEFORE INSTALLING

Have a Debian, Devuan or Ubuntu server with a static IP and DNS records
(usually A/AAAA) that point your domain name to it.

NOTE WHILE INSTALLING

On installation of Postfix, select "Internet Site" and put in \
TLD (without \`mail.\` before it).

AFTER INSTALLING

More DNS records will be given to you to install. One of them \
will be different for every installation and is uniquely \
generated on your machine.
EOF

	local _p="Have you read and understood the above"
	_p+=" instructions regarding the installation and"
	_p+=" configuration of the email server? (yes/no): "
	read -r -p "$_p" response
	if [ "$response" != "yes" ]; then
		error "Please read the instructions carefully before proceeding."
		exit 1
	fi
}

# Back up existing mail configuration before a destructive reinstall.
# The archive is stored under /var/backups so a purge does not wipe it.
backup_mail_config() {
	local _ts _bkdir _rel
	local -a _rels=()
	_ts="$(date '+%Y%m%d-%H%M%S')"
	_bkdir="/var/backups/emailwiz/$_ts"
	for _rel in etc/postfix etc/dovecot etc/opendkim \
		etc/opendkim.conf etc/nftables.conf etc/fail2ban \
		etc/letsencrypt; do
		[ -e "/$_rel" ] && _rels+=("$_rel")
	done
	[ ${#_rels[@]} -eq 0 ] && return 0
	if ! mkdir -p "$_bkdir"; then
		warn "Could not create backup directory $_bkdir."
		return 0
	fi
	if tar -czf "$_bkdir/mail-config.tar.gz" -C / "${_rels[@]}"; then
		log "Backed up existing configuration to" \
			"$_bkdir/mail-config.tar.gz"
	else
		warn "Could not archive existing configuration."
	fi
}

# Function to install required packages
install_packages() {
	umask 0022
	local _re
	local packages=(
		postfix postfix-pcre dovecot-imapd dovecot-pop3d
		dovecot-sieve opendkim opendkim-tools spamassassin
		spamc net-tools fail2ban bind9-host nftables
	)
	log "Stopping Dovecot and Postfix services..."
	svc_stop dovecot
	svc_stop postfix
	if dpkg -s postfix >/dev/null 2>&1; then
		warn "Existing mail server packages detected."
		warn "This will PURGE and reinstall all packages."
		warn "Configuration in /etc/postfix and /etc/dovecot"
		warn "  will be backed up before purge."
		backup_mail_config
		read -r -p "Continue with purge and reinstall? (yes/no): " _re
		if [ "$_re" != "yes" ]; then
			error "Aborting installation."
			exit 1
		fi
	fi
	log "Purging existing packages..."
	apt-get purge --auto-remove -y "${packages[@]}"
	log "Installing required packages..."
	apt-get install -y "${packages[@]}"
}

# Function to configure the firewall with nftables
configure_firewall() {
	log "Configuring firewall with nftables..."
	cat <<'NFTEOF' >/etc/nftables.conf
#!/usr/sbin/nft -f

# Manage a dedicated table instead of flushing the whole ruleset, so
# any other firewall (Docker, ufw, ...) keeps working. A packet that
# reaches the end of the input chain is still dropped.
add table inet emailwiz
delete table inet emailwiz
table inet emailwiz {
	chain input {
		type filter hook input priority 0; policy drop;
		ct state established,related accept
		iif lo accept
		tcp dport {22, 80, 993, 465, 25, 587, 110, 995} accept
		ip protocol icmp accept
		meta l4proto ipv6-icmp accept
		counter drop
	}
}
NFTEOF
	svc_enable nftables
	if ! svc_restart nftables; then
		warn "Could not (re)start the nftables service;" \
			"loading the ruleset directly."
		nft -f /etc/nftables.conf || {
			error "Failed to load the nftables ruleset."
			exit 1
		}
	fi
}

# Function to configure SSL certificates
configure_ssl() {
	local domain="$1"
	local subdom="$2"
	local maildomain="$subdom.$domain"
	local certdir="/etc/letsencrypt/live/$maildomain"
	local use_cert_config="no" # yes or no
	local country_name=""      # IT US UK IN etc.
	local state_or_province_name=""
	local organization_name=""
	local common_name
	local possiblecert
	local _dom_esc="${domain//./\\.}"
	local _mail_esc="${maildomain//./\\.}"
	common_name=$(hostname -f | tr -d '[:space:]')

	if [ "$use_cert_config" = "yes" ]; then
		log "Creating certificate configuration..."
		mkdir -p "$certdir"
		chmod 700 "$certdir"
		echo "[req]
	default_bit = 4096
	distinguished_name = req_distinguished_name
	question = no

	[req_distinguished_name]
	countryName             = $country_name
	stateOrProvinceName     = $state_or_province_name
	organizationName        = $organization_name
	commonName              = $common_name " >"$certdir/certconfig.conf"
	fi

	log "Checking DNS records for $maildomain..."
	local ipv4
	ipv4=$(dig +short "$maildomain" |
		grep -m1 -Eo '([0-9]+\.){3}[0-9]+' |
		tr -d '[:space:]')
	[ -z "$ipv4" ] && {
		error "No IPv4 address found for $maildomain." \
			"Please ensure that your domain's DNS records are" \
			"correctly configured to point to your server's" \
			"IPv4 address."
		exit 1
	}
	local ipv6
	ipv6=$(dig +short "$maildomain" AAAA |
		grep -m1 -Eo '([0-9a-fA-F:]+)' |
		tr -d '[:space:]')
	# IPv6 is optional: many providers do not offer it. Warn instead
	# of aborting so the server can still run over IPv4 only.
	if [ -z "$ipv6" ]; then
		warn "No AAAA record found for $maildomain; the server" \
			"will operate over IPv4 only. Add an AAAA record" \
			"(and IPv6 connectivity) for full dual-stack support."
	fi

	if [ "$selfsigned" = "yes" ]; then
		log "Generating self-signed certificate..."
		mkdir -p "$certdir"
		chmod 700 "$certdir"
		rm -f "$certdir/privkey.pem"
		rm -f "$certdir/csr.pem"
		rm -f "$certdir/fullchain.pem"

		log "Generating a 4096 rsa key and a" \
			"self-signed certificate that lasts 100 years"
		mkdir -p "$certdir"
		openssl genrsa -out "$certdir/privkey.pem" 4096

		if [ "$use_cert_config" = "yes" ]; then
			openssl req -new -key "$certdir/privkey.pem" \
				-out "$certdir/csr.pem" \
				-config "$certdir/certconfig.conf"
		else
			openssl req -new -key "$certdir/privkey.pem" \
				-subj "/CN=$maildomain" \
				-out "$certdir/csr.pem"
		fi
		# Modern TLS clients reject certificates that rely on the
		# Common Name, so an explicit subjectAltName is required.
		openssl req -x509 -days 36500 \
			-key "$certdir/privkey.pem" \
			-in "$certdir/csr.pem" \
			-addext "subjectAltName=DNS:$maildomain" \
			-out "$certdir/fullchain.pem"
	else
		log "Obtaining Let's Encrypt certificate..."

		[ ! -d "$certdir" ] &&
			possiblecert="$(certbot certificates 2>/dev/null |
				grep -E "Domains:.* (\*\.${_dom_esc}|${_mail_esc})" \
					-A 2 |
				awk '/Certificate Path/ {print $3}' |
				head -n1 |
				tr -d '[:space:]')" &&
			certdir="${possiblecert%/*}"

		[ ! -d "$certdir" ] &&
			certdir="/etc/letsencrypt/live/$maildomain" &&
			case "$(ss -tulpn | grep ":80\s")" in
			*nginx*)
				apt install -y python3-certbot-nginx
				certbot -d "$maildomain" certonly --nginx \
					--register-unsafely-without-email --agree-tos
				;;
			*apache*)
				apt install -y python3-certbot-apache
				certbot -d "$maildomain" certonly --apache \
					--register-unsafely-without-email --agree-tos
				;;
			*)
				apt install -y python3-certbot
				certbot -d "$maildomain" certonly --standalone \
					--register-unsafely-without-email --agree-tos
				;;
			esac
	fi

	[ ! -f "$certdir/fullchain.pem" ] && {
		error "Error locating or installing SSL certificate" \
			"(fullchain.pem not found)."
		exit 1
	}
	[ ! -f "$certdir/privkey.pem" ] && {
		error "Error locating or installing SSL certificate" \
			"(privkey.pem not found)."
		exit 1
	}
	if [ "$selfsigned" != "yes" ]; then
		[ ! -f "$certdir/cert.pem" ] && {
			error "Error locating or installing SSL certificate" \
				"(cert.pem not found)."
			exit 1
		}
	fi
}

# Function to configure Postfix
configure_postfix() {
	local domain="$1"
	local subdom="$2"
	local maildomain="$subdom.$domain"
	local certdir="/etc/letsencrypt/live/$maildomain"

	echo "Configuring Postfix's main.cf..."

	# Adding additional vars to fix an issue with receiving emails
	# (relay access denied) and adding it to mydestination.
	postconf -e "myhostname = $maildomain"
	postconf -e "mail_name = $domain" # This is for the smtpd_banner
	postconf -e "mydomain = $domain"
	# Postfix expands $myhostname/$mydomain itself, so the dollar
	# signs are literal here.
	# shellcheck disable=SC2016
	local _md='mydestination = $myhostname, $mydomain,'
	_md+=" mail, localhost.localdomain, localhost,"
	# shellcheck disable=SC2016
	_md+=' localhost.$mydomain'
	postconf -e "$_md"

	# Change the cert/key files to the default locations of the
	# Let's Encrypt cert/key
	postconf -e "smtpd_tls_key_file=$certdir/privkey.pem"
	postconf -e "smtpd_tls_cert_file=$certdir/fullchain.pem"
	# Trust the system CA store so outbound SMTP TLS certificates can
	# actually be verified. (Pointing smtp_tls_CAfile at the server's
	# own cert.pem, as an earlier version did, made verification
	# meaningless.)
	if [ -f /etc/ssl/certs/ca-certificates.crt ]; then
		postconf -e \
			"smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt"
	elif [ -d /etc/ssl/certs ]; then
		postconf -e "smtp_tls_CApath = /etc/ssl/certs"
	fi

	# Enable, but do not require TLS. Requiring it with other
	# servers would cause mail delivery problems and requiring it
	# locally would cause many other issues.
	postconf -e 'smtpd_tls_security_level = may'
	postconf -e 'smtp_tls_security_level = may'

	# TLS required for authentication.
	postconf -e 'smtpd_tls_auth_only = yes'

	# Exclude insecure and obsolete encryption protocols.
	postconf -e 'smtpd_tls_mandatory_protocols = ''!SSLv2, !SSLv3, !TLSv1, !TLSv1.1'
	postconf -e 'smtp_tls_mandatory_protocols = ''!SSLv2, !SSLv3, !TLSv1, !TLSv1.1'
	postconf -e 'smtpd_tls_protocols = ''!SSLv2, !SSLv3, !TLSv1, !TLSv1.1'
	postconf -e 'smtp_tls_protocols = ''!SSLv2, !SSLv3, !TLSv1, !TLSv1.1'

	# Exclude suboptimal ciphers.
	if [ "$allow_suboptimal_ciphers" = "no" ]; then
		postconf -e 'tls_preempt_cipherlist = yes'
		postconf -e 'smtpd_tls_exclude_ciphers = aNULL, ''LOW, EXP, MEDIUM, ADH, AECDH, MD5, DSS, ECDSA, ''CAMELLIA128, 3DES, CAMELLIA256, RSA+AES, eNULL'
	fi

	# Here we tell Postfix to look to Dovecot for authenticating
	# users/passwords. Dovecot will be putting an authentication
	# socket in /var/spool/postfix/private/auth
	postconf -e 'smtpd_sasl_auth_enable = yes'
	postconf -e 'smtpd_sasl_type = dovecot'
	postconf -e 'smtpd_sasl_path = private/auth'

	# helo, sender, relay and recipient restrictions
	postconf -e \
		"smtpd_sender_login_maps = pcre:/etc/postfix/login_maps.pcre"
	postconf -e 'smtpd_sender_restrictions = ''reject_sender_login_mismatch, permit_sasl_authenticated, ''permit_mynetworks, reject_unknown_reverse_client_hostname, ''reject_unknown_sender_domain'
	postconf -e 'smtpd_recipient_restrictions = ''permit_sasl_authenticated, permit_mynetworks, ''reject_unauth_destination, reject_unknown_recipient_domain'
	postconf -e 'smtpd_relay_restrictions = ''permit_sasl_authenticated, reject_unauth_destination'
	postconf -e 'smtpd_helo_required = yes'
	postconf -e 'smtpd_helo_restrictions = permit_mynetworks, ''permit_sasl_authenticated, reject_invalid_helo_hostname, ''reject_non_fqdn_helo_hostname, reject_unknown_helo_hostname'

	# NOTE: the trailing slash here, or for any directory name in
	# the home_mailbox command, is necessary as it distinguishes a
	# maildir (which is the actual directory that we want) from a
	# spoolfile (which is what old unix boomers want and no one
	# else).
	postconf -e 'home_mailbox = Mail/Inbox/'

	# Strip the "Received:" header that Postfix adds when a client
	# submits mail over an authenticated TLS connection (ESMTPSA).
	# This hides the client's public IP address from recipients.
	# Matching only ESMTPSA leaves the Received headers of inbound
	# mail intact, which are needed for troubleshooting and spam
	# analysis. See https://www.postfix.org/header_checks.5.html
	# NOTE: patterns must not be indented; a leading space would make
	# Postfix treat the line as a continuation of the previous one.
	postconf -e "header_checks = regexp:/etc/postfix/header_checks"
	printf '%s\n' \
		'/^Received:.*with ESMTPSA/ IGNORE' \
		'/^X-Originating-IP:/ IGNORE' \
		>/etc/postfix/header_checks

	# Create a login map file that ensures that if a sender wants
	# to send a mail from a user at our local domain, they must be
	# authenticated as that user
	local _lm="/^(.*)@${domain//./\\.}$/   \${1}"
	echo "$_lm" >/etc/postfix/login_maps.pcre

	echo "Configuring Postfix's master.cf..."

	# Remove existing configurations from master.cf
	sed -i \
		-e '/^\s*-o\s\+syslog_name=postfix\/submission/d' \
		-e '/^\s*-o\s\+smtpd_tls_security_level=encrypt/d' \
		-e '/^\s*-o\s\+smtpd_tls_auth_only=yes/d' \
		-e '/^\s*-o\s\+smtpd_enforce_tls=yes/d' \
		-e '/^\s*-o\s\+content_filter=spamassassin/d' \
		-e '/^\s*-o\s\+smtpd_client_restrictions=''permit_sasl_authenticated,reject/d' \
		-e '/^\s*-o\s\+smtpd_sender_restrictions=''reject_sender_login_mismatch/d' \
		-e '/^\s*-o\s\+smtpd_sender_login_maps=''pcre:\/etc\/postfix\/login_maps.pcre/d' \
		-e '/^\s*-o\s\+smtpd_recipient_restrictions=''permit_sasl_authenticated,''reject_unauth_destination/d' \
		-e '/^smtp[[:space:]]\+inet[[:space:]].*[[:space:]]smtpd[[:space:]]*$/s/^/#/' \
		-e '/^smtp[[:space:]]\+unix[[:space:]].*[[:space:]]smtp[[:space:]]*$/s/^/#/' \
		/etc/postfix/master.cf

	cat >>/etc/postfix/master.cf <<EOF
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
	-o smtpd_recipient_restrictions=\
permit_sasl_authenticated,reject_unauth_destination
smtps     inet  n       -       y       -       -       smtpd
	-o syslog_name=postfix/smtps
	-o smtpd_tls_wrappermode=yes
	-o smtpd_sasl_auth_enable=yes
spamassassin unix -     n       n       -       -       pipe
	user=debian-spamd argv=/usr/bin/spamc -f -e \
		/usr/sbin/sendmail -oi -f \${sender} \${recipient}
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

	# By default, dovecot has a bunch of configs in
	# /etc/dovecot/conf.d/ These files have nice documentation if
	# you want to read it, but it's a huge pain to go through them
	# to organize.  Instead, we simply overwrite
	# /etc/dovecot/dovecot.conf because it's easier to manage. You
	# can get a backup of the original in /usr/share/dovecot if you
	# want.
	# Keep a pristine backup of the stock config; do not overwrite it
	# with our generated config on subsequent runs.
	if [ -f /etc/dovecot/dovecot.conf ] &&
		[ ! -f /etc/dovecot/dovecot.backup.conf ]; then
		mv /etc/dovecot/dovecot.conf \
			/etc/dovecot/dovecot.backup.conf
	fi

	local _ciphers
	_ciphers='EECDH+ECDSA+AESGCM:EECDH+aRSA+AESGCM:'
	_ciphers+='EECDH+ECDSA+SHA256:EECDH+aRSA+SHA256:'
	_ciphers+='EECDH+ECDSA+SHA384:EECDH+ECDSA+SHA256:'
	_ciphers+='EECDH+aRSA+SHA384:EDH+aRSA+AESGCM:'
	_ciphers+='EDH+aRSA+SHA256:EDH+aRSA:EECDH:'
	_ciphers+='!aNULL:!eNULL:!MEDIUM:!LOW:!3DES:!MD5:'
	_ciphers+='!EXP:!PSK:!SRP:!DSS:!RC4:!SEED'

	# Dovecot fails to start if the DH parameters file is missing, so
	# only emit the setting when it actually exists.
	local _ssl_dh _ssl_dh24
	if [ -f /usr/share/dovecot/dh.pem ]; then
		_ssl_dh="ssl_dh = </usr/share/dovecot/dh.pem"
		_ssl_dh24="ssl_server_dh_file = /usr/share/dovecot/dh.pem"
	else
		_ssl_dh="# ssl_dh omitted (no dh.pem); ECDHE is still used"
		_ssl_dh24="# ssl_server_dh_file omitted (no dh.pem)"
		warn "No DH parameters at /usr/share/dovecot/dh.pem;" \
			"omitting ssl_dh (ECDHE will still be negotiated)."
	fi

	# Dovecot 2.4 reworked the configuration syntax: mail_location was
	# split into mail_* settings, the SSL settings were renamed and the
	# Sieve plugin moved to sieve_script blocks. Emit the syntax that
	# matches the installed version.
	local _dovecot_ver _maj _min
	_dovecot_ver="$(dovecot --version)"
	_maj="${_dovecot_ver%%.*}"
	_min="${_dovecot_ver#*.}"
	_min="${_min%%.*}"
	_min="${_min%% *}"
	case "$_maj" in '' | *[!0-9]*) _maj=0 ;; esac
	case "$_min" in '' | *[!0-9]*) _min=0 ;; esac
	log "Detected Dovecot $_dovecot_ver"

	if [ "$_maj" -gt 2 ] ||
		{ [ "$_maj" -eq 2 ] && [ "$_min" -ge 4 ]; }; then
		log "Using the Dovecot 2.4 configuration syntax."
		cat >/etc/dovecot/dovecot.conf <<DOVECOT24
# Dovecot 2.4 configuration (generated by emailwiz)

dovecot_config_version = 2.4.0
dovecot_storage_version = 2.4.0

ssl = required
ssl_server_cert_file = $certdir/fullchain.pem
ssl_server_key_file = $certdir/privkey.pem
ssl_min_protocol = TLSv1.2
ssl_cipher_list = $_ciphers
ssl_server_prefer_ciphers = client
$_ssl_dh24
auth_mechanisms = plain login
auth_allow_cleartext = no
auth_username_format = %{user|username}

protocols = imap pop3

mail_driver = $mailbox_format
mail_path = ~/Mail
mail_inbox_path = ~/Mail/Inbox
mailbox_list_layout = fs

# Search for valid users in /etc/passwd
userdb passwd {
	driver = passwd
}
# Fallback: Use plain old PAM to find user passwords
passdb pam {
	driver = pam
}

namespace inbox {
	inbox = yes
	mailbox Drafts {
		special_use = \Drafts
		auto = subscribe
	}
	mailbox Junk {
		special_use = \Junk
		auto = subscribe
		autoexpunge = 30d
	}
	mailbox Sent {
		special_use = \Sent
		auto = subscribe
	}
	mailbox Trash {
		special_use = \Trash
	}
	mailbox Archive {
		special_use = \Archive
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
	mail_plugins {
		sieve = yes
	}
}

protocol lmtp {
	mail_plugins {
		sieve = yes
	}
}

protocol pop3 {
	pop3_uidl_format = %{uid | hex(8)}%{uidvalidity | hex(8)}
	pop3_no_flag_updates = yes
}

sieve_script personal {
	driver = file
	path = ~/.sieve
	active_path = ~/.dovecot.sieve
}

sieve_script default {
	type = default
	name = default
	driver = file
	path = /var/lib/dovecot/sieve/
}
DOVECOT24
	else
		log "Using the Dovecot 2.3 configuration syntax."
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
	ssl_cipher_list = $_ciphers
	ssl_prefer_server_ciphers = yes
	$_ssl_dh
	auth_mechanisms = plain login
	auth_username_format = %n

	protocols = \$protocols $allowed_protocols

	# Search for valid users in /etc/passwd
	userdb {
		driver = passwd
	}
	# Fallback: Use plain old PAM to find user passwords
	passdb {
		driver = pam
	}

	# Our mail for each user will be in ~/Mail, and the inbox
	# will be ~/Mail/Inbox. The LAYOUT option is also important
	# because otherwise, the boxes will be \`.Sent\` instead of
	# \`Sent\`.
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
	}
	" >/etc/dovecot/dovecot.conf

		# If using an old version of Dovecot, remove the ssl_dh line.
		case "$_dovecot_ver" in
		1 | 2.1* | 2.2*) sed -i '/^ssl_dh/d' \
			/etc/dovecot/dovecot.conf ;;
		esac
	fi

	grep -q '^vmail:' /etc/passwd || useradd -r -m vmail
	mkdir -p /var/lib/dovecot/sieve/
	# The default Sieve script is read by the LDA, which runs as the
	# recipient user and not as vmail, so this directory must remain
	# world-traversable and the script world-readable. A 0700 mode here
	# prevents the spam-to-Junk rule from ever loading.
	chmod 755 /var/lib/dovecot/sieve/

	echo 'require ["fileinto", "mailbox"];
	if header :contains "X-Spam-Flag" "YES"
		{
			fileinto "Junk";
		}' >/var/lib/dovecot/sieve/default.sieve

	chown -R vmail:vmail /var/lib/dovecot
	sievec /var/lib/dovecot/sieve/default.sieve
	chmod 644 /var/lib/dovecot/sieve/default.sieve \
		/var/lib/dovecot/sieve/default.svbin
}

# Function to configure OpenDKIM
configure_opendkim() {
	local domain="$1"
	local subdom="$2"
	local maildomain="$subdom.$domain"

	echo "Generating OpenDKIM keys..."

	# A lot of the big name email services, like Google, will
	# automatically reject as spam unfamiliar and unauthenticated
	# email addresses. As in, the server will flatly reject the
	# email, not even delivering it to someone's Spam folder.
	#
	# OpenDKIM is a way to authenticate your email so you can send
	# to such services without a problem.

	# Create an OpenDKIM key in the proper place with proper permissions.
	mkdir -p "/etc/postfix/dkim/$domain"
	chmod 700 "/etc/postfix/dkim/$domain"

	if [ ! -f "/etc/postfix/dkim/$domain/$subdom.private" ]; then
		opendkim-genkey -b 2048 -D "/etc/postfix/dkim/$domain" \
			-d "$domain" -s "$subdom"
		chgrp -R opendkim /etc/postfix/dkim/*
		chmod -R g+r /etc/postfix/dkim/*
	fi

	echo "Configuring OpenDKIM..."

	# Generate the OpenDKIM info:
	grep -qF "$subdom._domainkey.$domain " \
		/etc/postfix/dkim/keytable 2>/dev/null ||
		{
			local _p
			_p="/etc/postfix/dkim/$domain/$subdom.private"
			printf '%s %s\n' "$subdom._domainkey.$domain" \
				"$domain:$subdom:$_p" \
				>>/etc/postfix/dkim/keytable
		}

	grep -qF "*@$domain " /etc/postfix/dkim/signingtable 2>/dev/null ||
		echo "*@$domain $subdom._domainkey.$domain" \
			>>/etc/postfix/dkim/signingtable

	grep -qF '127.0.0.1' /etc/postfix/dkim/trustedhosts 2>/dev/null ||
		printf '%s\n' '127.0.0.1' '10.1.0.0/16' \
			>>/etc/postfix/dkim/trustedhosts

	# ...and source it from opendkim.conf
	grep -q '^KeyTable' /etc/opendkim.conf 2>/dev/null || {
		printf '%s\n' \
			'KeyTable file:/etc/postfix/dkim/keytable' \
			'SigningTable refile:/etc/postfix/dkim/signingtable' \
			'InternalHosts refile:/etc/postfix/dkim/trustedhosts' \
			>>/etc/opendkim.conf
	}

	sed -i '/^#Canonicalization/s/simple/relaxed\/simple/' \
		/etc/opendkim.conf
	sed -i '/^#Canonicalization/s/^#//' /etc/opendkim.conf

	sed -i '/Socket/s/^#*/#/' /etc/opendkim.conf
	grep -q '^Socket\s*inet:12301@localhost' /etc/opendkim.conf ||
		echo 'Socket inet:12301@localhost' \
			>>/etc/opendkim.conf

	# OpenDKIM daemon settings, removing previously activated socket.
	if [ -f /etc/default/opendkim ]; then
		sed -i '/^SOCKET/d' /etc/default/opendkim
		echo 'SOCKET="inet:12301@localhost"' \
			>>/etc/default/opendkim
	else
		warn "No /etc/default/opendkim; skipping socket setting."
	fi

	echo "Configuring Postfix with OpenDKIM settings..."

	# Here we add to postconf the needed settings for working with OpenDKIM
	postconf -e 'smtpd_sasl_security_options = noanonymous, noplaintext'
	postconf -e 'smtpd_sasl_tls_security_options = noanonymous'
	postconf -e "myhostname = $maildomain"
	postconf -e 'milter_default_action = accept'
	postconf -e 'milter_protocol = 6'
	postconf -e 'smtpd_milters = inet:localhost:12301'
	postconf -e 'non_smtpd_milters = inet:localhost:12301'
	postconf -e 'mailbox_command = /usr/lib/dovecot/deliver'

	# Long-term fix to prevent SMTP smuggling. The parameter exists in
	# Postfix 3.9, 3.8.4, 3.7.9, 3.6.13 and 3.5.23 and later; skip it
	# on older releases that would reject the unknown setting.
	if postconf -d 2>/dev/null |
		grep -q '^smtpd_forbid_bare_newline '; then
		postconf -e 'smtpd_forbid_bare_newline = normalize'
		# shellcheck disable=SC2016
		postconf -e \
			'smtpd_forbid_bare_newline_exclusions = $mynetworks'
	else
		warn "This Postfix is too old to support" \
			"smtpd_forbid_bare_newline; upgrade it to mitigate" \
			"SMTP smuggling."
	fi

	# A fix for "Opendkim won't start: can't open PID file?",
	# as specified here: https://serverfault.com/a/847442
	case "$_init" in
	systemd)
		if [ -x /lib/opendkim/opendkim.service.generate ]; then
			/lib/opendkim/opendkim.service.generate
			svc_daemon_reload
		fi
		;;
	esac
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

	if [ "$_init" = "systemd" ]; then
		printf '[DEFAULT]\nbackend = systemd\n' \
			>/etc/fail2ban/jail.d/emailwiz-backend.local
	else
		printf '[DEFAULT]\nbackend = auto\n' \
			>/etc/fail2ban/jail.d/emailwiz-backend.local
	fi
}

# Function to configure SpamAssassin
configure_spamassassin() {
	echo "Enabling SpamAssassin update cronjob..."

	# Enable SpamAssassin update cronjob.
	if [ -f /etc/default/spamassassin ]; then
		sed -i 's|^CRON=0|CRON=1|' /etc/default/spamassassin
		printf 'Restarting spamassassin...'
		if svc_restart spamassassin; then
			printf ' ...done\n'
		else
			printf ' ...FAILED\n'
			warn "Could not restart spamassassin; check its logs."
		fi
		svc_enable spamassassin
	elif [ -f /etc/default/spamd ]; then
		sed -i 's|^CRON=0|CRON=1|' /etc/default/spamd
		printf 'Restarting spamd...'
		if svc_restart spamd; then
			printf ' ...done\n'
		else
			printf ' ...FAILED\n'
			warn "Could not restart spamd; check its logs."
		fi
		svc_enable spamd
	else
		error "Neither /etc/default/spamassassin nor" \
			"/etc/default/spamd exists; this is unexpected" \
			"and needs investigation."
	fi
}

# Function to restart services
restart_services() {
	echo "Restarting services..."
	for x in opendkim dovecot postfix fail2ban; do
		printf 'Restarting %s...' "$x"
		if svc_restart "$x"; then
			printf ' ...done\n'
		else
			printf ' ...FAILED\n'
			warn "Could not restart $x; check its logs."
		fi
		svc_enable "$x"
	done
}

# Function to configure cronjobs and renewal hook
create_cronjob() {
	local maildomain="$1"

	svc_enable nftables
	svc_restart nftables >/dev/null 2>&1 || true

	echo "Creating cronjob to delete month-old postmaster mails..."
	cat <<EOF >/etc/cron.weekly/postmaster-clean
#!/bin/sh

find /home/postmaster/Mail -type f -mtime +30 \
	-name '*.mail*' -delete >/dev/null 2>&1
exit 0
EOF
	chmod 700 /etc/cron.weekly/postmaster-clean

	local _hook_line _reload_cmd
	_reload_cmd="$(svc_reload_cmd)"
	# Certbot expands $RENEWED_DOMAINS at renewal time, so keep it
	# literal in the generated deploy hook.
	# shellcheck disable=SC2016
	_hook_line='deploy-hook = echo "$RENEWED_DOMAINS"'
	_hook_line+=" | grep -qF '$maildomain'"
	case "$_init" in
	systemd)
		_hook_line+=" && $_reload_cmd postfix"
		_hook_line+=" && $_reload_cmd dovecot"
		;;
	runit)
		_hook_line+=" && $_reload_cmd postfix"
		_hook_line+=" && $_reload_cmd dovecot"
		;;
	openrc)
		_hook_line+=" && $_reload_cmd postfix reload"
		_hook_line+=" && $_reload_cmd dovecot reload"
		;;
	*)
		_hook_line+=" && $_reload_cmd postfix reload"
		_hook_line+=" && $_reload_cmd dovecot reload"
		;;
	esac
	# The deploy hook only makes sense after Certbot has been used, so
	# skip it in isolated/self-signed mode where /etc/letsencrypt is
	# never created.
	if [ -d /etc/letsencrypt ]; then
		grep -qF -- "$_hook_line" /etc/letsencrypt/cli.ini \
			2>/dev/null ||
			echo "$_hook_line" >>/etc/letsencrypt/cli.ini
	fi
}

# Function to generate DNS entries
generate_dns_entries() {
	local domain="$1"
	local subdom="$2"
	local maildomain="$subdom.$domain"
	local pval
	pval=$(tr -d '\n' </etc/postfix/dkim/"$domain"/"$subdom".txt |
		sed "s/k=rsa.* \"p=/k=rsa; p=/;s/\"\s*\"//;s/\"\s*).*//" |
		grep -o 'p=.*' || true)
	if [ -z "$pval" ]; then
		warn "Could not extract the DKIM public key from" \
			"/etc/postfix/dkim/$domain/$subdom.txt; the DKIM" \
			"DNS record below will be incomplete."
	fi
	dkimentry="$subdom._domainkey.$domain	TXT	v=DKIM1; k=rsa; $pval"
	dmarcentry="_dmarc.$domain"
	dmarcentry+="	TXT	v=DMARC1; p=reject;"
	dmarcentry+=" rua=mailto:dmarc@$domain; fo=1"
	spfentry="$domain	TXT	v=spf1 mx a:$maildomain -all"
	mxentry="$domain	MX	10	$maildomain"

	echo "Generating DNS entries..."
	if ! id -u postmaster >/dev/null 2>&1; then
		if ! useradd -r -m -G mail postmaster; then
			error "Failed to create postmaster user."
			exit 1
		fi
	fi

	cat >"$HOME/dns_emailwizard" <<EOF
NOTE: Elements in the entries might appear in a different order \
in your registrar's DNS settings.
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
 _   _
| \ | | _____      ___
|  \| |/ _ \ \ /\ / (_)
| |\  | (_) \ V  V / _
|_| \_|\___/ \_/\_/ (_)

Add these four records to your DNS on either your registrar's \
site or your DNS server:
$dkimentry

$dmarcentry

$spfentry

$mxentry
NOTE: You may need to omit the \`.$domain\` portion at the beginning if
inputting them in a registrar's web interface.

Also, these are now saved to \
~/dns_emailwizard in case you want them in a file.

Once you do that, you're done! Check the README for how to add \
users/accounts and how to log in.
EOF
}

# Main script execution
main() {
	check_root
	detect_init
	confirm_installation
	install_packages

	domain="$(hostname --domain | tr -d '[:space:]')"
	subdom="${MAIL_SUBDOM:-mail}"
	if [ -z "$domain" ]; then
		error "No domain found. Set a fully qualified hostname" \
			"(e.g. 'mail.example.com') before running this script."
		exit 1
	fi
	case "$subdom" in
	'' | *[!A-Za-z0-9-]*)
		error "Invalid MAIL_SUBDOM value: '$subdom'" \
			"(letters, numbers and dashes only)."
		exit 1
		;;
	esac
	maildomain="$subdom.$domain"

	configure_firewall
	configure_ssl "$domain" "$subdom"
	configure_postfix "$domain" "$subdom"
	configure_dovecot "$domain" "$subdom"
	configure_opendkim "$domain" "$subdom"
	configure_fail2ban
	configure_spamassassin
	restart_services
	create_cronjob "$maildomain"
	generate_dns_entries "$domain" "$subdom"
	final_output_message "$dkimentry" "$dmarcentry" "$spfentry" "$mxentry"
}

main "$@"
