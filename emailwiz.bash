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
use_cert_config="no"           # yes = preseed self-signed certificate fields
country_name=""                # IT US UK IN etc.
state_or_province_name=""
organization_name=""

certdir=""
backup_dir=""
service_failures=0
ssh_ports=()

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

# Validate a DNS name without accepting leading/trailing dots or labels.
validate_domain() {
	local _name="$1"
	[ -n "$_name" ] || return 1
	case "$_name" in
	.* | *. | *..* | *[!A-Za-z0-9.-]*) return 1 ;;
	esac
	[[ "$_name" =~ ^([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]]
}

validate_subdom() {
	local _name="$1"
	[ -n "$_name" ] || return 1
	[[ "$_name" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]]
}

# Find every configured SSH port so the firewall never locks out a
# non-default SSH daemon. Fall back to the listening socket, then to 22.
detect_ssh_ports() {
	local _file _port
	ssh_ports=()
	for _file in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
		[ -r "$_file" ] || continue
		while IFS= read -r _port; do
			case "$_port" in '' | *[!0-9]*) continue ;; esac
			[ "$_port" -ge 1 ] && [ "$_port" -le 65535 ] || continue
			case " ${ssh_ports[*]} " in
			*" $_port "*) ;;
			*) ssh_ports+=("$_port") ;;
			esac
		done < <(awk 'tolower($1) == "port" && $2 ~ /^[0-9]+$/ {
			print $2
		}' "$_file" 2>/dev/null)
	done
	if [ ${#ssh_ports[@]} -eq 0 ] &&
		command -v ss >/dev/null 2>&1; then
		_port=$(ss -tlnp 2>/dev/null |
			awk '/sshd/ { n = split($4, a, ":"); print a[n]; exit }')
		case "$_port" in
		'' | *[!0-9]*) ;;
		*) ssh_ports+=("$_port") ;;
		esac
	fi
	[ ${#ssh_ports[@]} -eq 0 ] && ssh_ports=(22)
	case " ${ssh_ports[*]} " in
	*" 22 "*) ;;
	*) ssh_ports+=(22) ;;
	esac
}

build_firewall_ports() {
	local _port _ports=""
	for _port in "${ssh_ports[@]}" 80 443 993 465 25 587 110 995; do
		case " ${_ports} " in
		*" ${_port} "*) ;;
		*) _ports="${_ports:+$_ports, }$_port" ;;
		esac
	done
	printf '%s' "$_ports"
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

# Report a failed step and point at the backup. Do not attempt an automatic
# restore: replacing live package configuration while services are down is
# more dangerous than leaving a clear recovery path.
on_error() {
	local _status="$1"
	error "Installation failed (exit status $_status)."
	if [ -n "$backup_dir" ] &&
		[ -f "$backup_dir/mail-config.tar.gz" ]; then
		error "Configuration backup: $backup_dir/mail-config.tar.gz"
	fi
	error "Inspect the logs before retrying or restoring anything."
	exit "$_status"
}

# Function to confirm installation instructions
confirm_installation() {
	cat <<EOF
BEFORE INSTALLING

Have a Debian, Devuan or Ubuntu server with a static IP and DNS records
(usually A/AAAA) that point your domain name to it.

NOTE WHILE INSTALLING

The script preselects Postfix's "Internet Site" mode and sets the mail
name to the detected mail host. No interactive Postfix prompt is expected.

AFTER INSTALLING

More DNS records will be given to you to install. One of them \
will be different for every installation and is uniquely \
generated on your machine.
EOF

	local _p="Have you read and understood the above"
	local response=""
	_p+=" instructions regarding the installation and"
	_p+=" configuration of the email server? (yes/no): "
	read -r -p "$_p" response || true
	if [ "$response" != "yes" ]; then
		error "Please read the instructions carefully before proceeding."
		exit 1
	fi
}

# Back up existing mail configuration before a destructive reinstall.
# The archive is stored under /var/backups so a purge does not wipe it.
# It contains private TLS/DKIM material, so both the directory and the
# archive are kept private to root.
backup_mail_config() {
	local _ts _bkdir _rel _old_umask
	local -a _rels=()
	_ts="$(date '+%Y%m%d-%H%M%S')"
	_bkdir="/var/backups/emailwiz/$_ts"
	for _rel in etc/postfix etc/dovecot etc/opendkim \
		etc/opendkim.conf etc/nftables.conf etc/fail2ban \
		etc/letsencrypt etc/ssl/emailwiz etc/aliases etc/spamassassin \
		etc/default/opendkim etc/default/spamassassin \
		etc/default/spamd etc/cron.weekly/postmaster-clean; do
		if [ -e "/$_rel" ]; then
			_rels+=("$_rel")
		fi
	done
	if [ ${#_rels[@]} -eq 0 ]; then
		log "No existing mail configuration to back up."
		return 0
	fi
	_old_umask="$(umask)"
	umask 0077
	if ! mkdir -p "$_bkdir"; then
		warn "Could not create backup directory $_bkdir."
		umask "$_old_umask"
		return 1
	fi
	chmod 700 "$_bkdir"
	if tar -czf "$_bkdir/mail-config.tar.gz" -C / "${_rels[@]}"; then
		chmod 600 "$_bkdir/mail-config.tar.gz"
		backup_dir="$_bkdir"
		log "Backed up existing configuration to" \
			"$_bkdir/mail-config.tar.gz"
	else
		warn "Could not archive existing configuration."
		umask "$_old_umask"
		return 1
	fi
	umask "$_old_umask"
}

# Function to install required packages
install_packages() {
	local maildomain="$1"
	local _re="" _existing="no" _pkg _rel
	local packages=(
		postfix postfix-pcre dovecot-imapd dovecot-pop3d
		dovecot-sieve opendkim opendkim-tools spamassassin
		spamc net-tools fail2ban bind9-host nftables
	)
	umask 0022
	for _pkg in "${packages[@]}"; do
		if dpkg -s "$_pkg" >/dev/null 2>&1; then
			_existing="yes"
			break
		fi
	done
	for _rel in etc/postfix etc/dovecot etc/opendkim \
		etc/opendkim.conf etc/nftables.conf etc/fail2ban; do
		if [ -e "/$_rel" ]; then
			_existing="yes"
		fi
	done
	if [ "$_existing" = "yes" ]; then
		warn "Existing mail server packages or configuration detected."
		warn "This will PURGE and reinstall all packages."
		warn "Configuration will be backed up before the purge."
		if ! backup_mail_config; then
			error "Backup failed; aborting before the purge."
			exit 1
		fi
		read -r -p "Continue with purge and reinstall? (yes/no): " \
			_re || true
		if [ "$_re" != "yes" ]; then
			error "Aborting installation; services were not stopped."
			exit 1
		fi
	fi
	log "Updating package lists..."
	apt-get update
	log "Stopping Dovecot and Postfix services..."
	svc_stop dovecot
	svc_stop postfix
	export DEBIAN_FRONTEND=noninteractive
	if command -v debconf-set-selections >/dev/null 2>&1; then
		printf '%s\n' \
			'postfix postfix/main_mailer_type select Internet Site' \
			"postfix postfix/mailname string $maildomain" |
			debconf-set-selections
	fi
	log "Purging existing packages..."
	apt-get purge --auto-remove -y "${packages[@]}"
	log "Installing required packages..."
	apt-get install -y "${packages[@]}"
	if [ "$_init" = "systemd" ]; then
		# fail2ban's systemd backend needs this module. Its absence is
		# reported later if the service cannot start.
		apt-get install -y python3-systemd ||
			warn "Could not install python3-systemd."
	fi
}

# Function to configure the firewall with nftables
configure_firewall() {
	local _ports
	_ports="$(build_firewall_ports)"
	log "Configuring firewall with nftables (ports: $_ports)..."
	cat <<NFTEOF >/etc/nftables.conf
#!/usr/sbin/nft -f

# Manage a dedicated table without flushing the whole ruleset, so
# other nftables tables (Docker, ufw, ...) keep working. This file
# itself is replaced; the installer backs up the previous version.
# The SSH port is detected to avoid locking out a non-default daemon.
add table inet emailwiz
delete table inet emailwiz
table inet emailwiz {
	chain input {
		type filter hook input priority 0; policy drop;
		ct state established,related accept
		iif lo accept
		tcp dport { $_ports } accept
		ip protocol icmp accept
		meta l4proto ipv6-icmp accept
		log prefix "emailwiz drop: " counter drop
	}
}
NFTEOF
	if command -v nft >/dev/null 2>&1; then
		nft -c -f /etc/nftables.conf || {
			error "Invalid nftables ruleset; refusing to apply it."
			exit 1
		}
	fi
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
	local default_certdir="/etc/letsencrypt/live/$maildomain"
	local possiblecert="" ipv4="" ipv6="" _port80
	local common_name="$maildomain"
	local _dom_esc="${domain//./\\.}"
	local _mail_esc="${maildomain//./\\.}"

	# Certbot needs a public A record. Self-signed mode is explicitly for
	# isolated networks, so it must not require public DNS.
	if [ "$selfsigned" != "yes" ]; then
		log "Checking DNS records for $maildomain..."
		ipv4=$(dig +short "$maildomain" |
			grep -m1 -Eo '([0-9]+\.){3}[0-9]+' |
			tr -d '[:space:]')
		if [ -z "$ipv4" ]; then
			error "No IPv4 address found for $maildomain." \
				"Please ensure that your domain's DNS records are" \
				"correctly configured to point to your server's" \
				"IPv4 address."
			exit 1
		fi
		if ! hostname -I 2>/dev/null | tr ' ' '\n' |
			grep -qxF "$ipv4"; then
			warn "The A record for $maildomain ($ipv4) is not one" \
				"of this host's addresses. This is normal behind" \
				"NAT, but Certbot will fail if the record is wrong."
		fi
		ipv6=$(dig +short "$maildomain" AAAA |
			grep -m1 -Eo '([0-9a-fA-F:]+)' |
			tr -d '[:space:]')
		# IPv6 is optional: many providers do not offer it.
		if [ -z "$ipv6" ]; then
			warn "No AAAA record found for $maildomain; the server" \
				"will operate over IPv4 only. Add an AAAA record" \
				"(and IPv6 connectivity) for full dual-stack support."
		fi
	else
		log "Self-signed mode: skipping the public DNS requirement."
	fi

	certdir="$default_certdir"
	if [ "$selfsigned" = "yes" ]; then
		# Keep private-CA material out of the Certbot live tree so a
		# later trusted-certificate run cannot be overwritten.
		certdir="/etc/ssl/emailwiz/$maildomain"
		log "Generating self-signed certificate..."
		mkdir -p "$certdir"
		chmod 700 "$certdir"
		rm -f "$certdir/privkey.pem"
		rm -f "$certdir/csr.pem"
		rm -f "$certdir/fullchain.pem"

		# The configuration block is only meaningful for the
		# self-signed path. Certbot obtains its own subject fields.
		if [ "$use_cert_config" = "yes" ]; then
			log "Creating certificate configuration..."
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

		log "Generating a 4096 rsa key and a" \
			"self-signed certificate that lasts 100 years"
		umask 0077
		openssl genrsa -out "$certdir/privkey.pem" 4096
		chmod 600 "$certdir/privkey.pem"

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
			-addext "basicConstraints=critical,CA:FALSE" \
			-addext "keyUsage=critical,digitalSignature,keyEncipherment" \
			-addext "extendedKeyUsage=serverAuth" \
			-out "$certdir/fullchain.pem"
		chmod 644 "$certdir/fullchain.pem"
		chmod 600 "$certdir/privkey.pem"
		# Postfix reads the key after dropping privileges on some
		# distributions; grant its group traverse/read without making
		# the key world-readable.
		if chgrp postfix "$certdir" "$certdir/privkey.pem" \
			2>/dev/null; then
			chmod 750 "$certdir"
			chmod 640 "$certdir/privkey.pem"
		fi
		umask 0022
	else
		if [ "$use_cert_config" = "yes" ]; then
			warn "use_cert_config only applies to self-signed mode;" \
				"ignoring it because selfsigned=no."
		fi
		log "Obtaining Let's Encrypt certificate..."

		# A self-signed certificate left by a previous isolated run
		# must not silently prevent Certbot from issuing a trusted one.
		if [ -f "$certdir/fullchain.pem" ]; then
			local _issuer _subject
			_issuer=$(openssl x509 -in "$certdir/fullchain.pem" \
				-noout -issuer 2>/dev/null || true)
			_subject=$(openssl x509 -in "$certdir/fullchain.pem" \
				-noout -subject 2>/dev/null || true)
			_issuer="${_issuer#issuer=}"
			_subject="${_subject#subject=}"
			if [ -n "$_issuer" ] && [ "$_issuer" = "$_subject" ]; then
				local _oldcert
				_oldcert="$certdir.selfsigned.$(date +%s)"
				warn "Existing certificate is self-signed;" \
					"moving it to $_oldcert before Certbot."
				mv "$certdir" "$_oldcert"
			fi
		fi

		# Reuse a valid lineage only when the certificate files really
		# exist. An empty live/ directory must not skip issuance.
		if [ -f "$certdir/fullchain.pem" ] &&
			[ -f "$certdir/privkey.pem" ]; then
			log "Using existing certificate at $certdir."
		else
			possiblecert="$(certbot certificates 2>/dev/null |
				grep -E "Domains:.* (\*\.${_dom_esc}|${_mail_esc})" \
					-A 2 |
				awk '/Certificate Path/ {print $3}' |
				head -n1 |
				tr -d '[:space:]' || true)"
			if [ -n "$possiblecert" ] &&
				[ -f "${possiblecert%/*}/fullchain.pem" ]; then
				certdir="${possiblecert%/*}"
				log "Using existing certificate at $certdir."
			else
				certdir="$default_certdir"
				# A leftover live/ directory without usable files
				# makes Certbot refuse to create a new lineage.
				if [ -d "$certdir" ] &&
					[ ! -f "$certdir/fullchain.pem" ]; then
					mv "$certdir" \
						"$certdir.incomplete.$(date +%s)"
				fi
				_port80="$(ss -tulpn 2>/dev/null || true)"
				case "$_port80" in
				*nginx*)
					apt-get install -y python3-certbot-nginx
					certbot -d "$maildomain" certonly --nginx \
						--register-unsafely-without-email --agree-tos
					;;
				*apache*)
					apt-get install -y python3-certbot-apache
					certbot -d "$maildomain" certonly --apache \
						--register-unsafely-without-email --agree-tos
					;;
				*)
					if printf '%s\n' "$_port80" |
						grep -q ':80 '; then
						warn "Port 80 is in use by a service that" \
							"is not nginx or apache; Certbot" \
							"standalone may fail. Free port 80 or" \
							"use a supported web server."
					fi
					apt-get install -y python3-certbot
					certbot -d "$maildomain" certonly --standalone \
						--register-unsafely-without-email --agree-tos
					;;
				esac
			fi
		fi
	fi

	if [ ! -f "$certdir/fullchain.pem" ]; then
		error "Error locating or installing SSL certificate" \
			"(fullchain.pem not found)."
		exit 1
	fi
	if [ ! -f "$certdir/privkey.pem" ]; then
		error "Error locating or installing SSL certificate" \
			"(privkey.pem not found)."
		exit 1
	fi
	if [ "$selfsigned" != "yes" ] && [ ! -f "$certdir/cert.pem" ]; then
		error "Error locating or installing SSL certificate" \
			"(cert.pem not found)."
		exit 1
	fi
}

# Add a local alias only when it is missing; never overwrite site policy.
ensure_mail_alias() {
	local _alias="$1"
	local _target="$2"
	[ -f /etc/aliases ] || : >/etc/aliases
	if ! grep -qE "^${_alias}:" /etc/aliases; then
		printf '%s: %s\n' "$_alias" "$_target" >>/etc/aliases
		if command -v newaliases >/dev/null 2>&1; then
			newaliases
		elif command -v postalias >/dev/null 2>&1; then
			postalias /etc/aliases
		fi
	fi
}

# Replace the services managed by this script without duplicating blocks.
# Continuation lines start with whitespace, so they are removed with their
# service header. Other master.cf services are left untouched.
rewrite_master_cf() {
	local _tmp
	_tmp="$(mktemp)"
	awk '
		/^(smtp|submission|smtps|spamassassin)[[:space:]]/ {
			skip = 1
			next
		}
		skip && /^[[:space:]]/ { next }
		skip && /^$/ { skip = 0; print; next }
		{ skip = 0; print }
	' /etc/postfix/master.cf >"$_tmp"
	cat "$_tmp" >/etc/postfix/master.cf
	rm -f "$_tmp"
}

# Function to configure Postfix
configure_postfix() {
	local domain="$1"
	local subdom="$2"
	local maildomain="$subdom.$domain"
	local _lmfile="/etc/postfix/login_maps.pcre"
	local _line _esc _d

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
	# Provide a real CA store for policy maps and future verification.
	# Opportunistic TLS (security_level=may) does not verify peers, so
	# this setting alone does not authenticate remote servers.
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

	# Exclude suboptimal ciphers on both inbound and outbound SMTP.
	if [ "$allow_suboptimal_ciphers" = "no" ]; then
		local _weak_ciphers
		_weak_ciphers='aNULL, LOW, EXP, MEDIUM, ADH, AECDH, MD5, DSS, '
		_weak_ciphers+='ECDSA, CAMELLIA128, 3DES, CAMELLIA256, RSA+AES, eNULL'
		postconf -e 'tls_preempt_cipherlist = yes'
		postconf -e "smtpd_tls_exclude_ciphers = $_weak_ciphers"
		postconf -e "smtp_tls_exclude_ciphers = $_weak_ciphers"
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
	# authenticated as that user. Preserve entries added by
	# adddomain.bash instead of truncating the file on every run.
	touch "$_lmfile"
	for _d in "$domain" "$maildomain"; do
		_esc="${_d//./\\.}"
		_line="/^(.*)@${_esc}$/   \${1}"
		grep -qxF "$_line" "$_lmfile" ||
			printf '%s\n' "$_line" >>"$_lmfile"
	done

	# Alias local mail so DMARC reports have a deliverable mailbox.
	postconf -e 'alias_maps = hash:/etc/aliases'
	postconf -e 'alias_database = hash:/etc/aliases'
	ensure_mail_alias dmarc postmaster

	echo "Configuring Postfix's master.cf..."

	# Remove our previous service blocks (including stock smtp entries)
	# before appending a fresh set. This makes repeated runs idempotent.
	rewrite_master_cf

	cat >>/etc/postfix/master.cf <<EOF
smtp unix - - n - - smtp
smtp inet n - n - - smtpd
	-o content_filter=spamassassin
submission inet n       -       n       -       -       smtpd
	-o syslog_name=postfix/submission
	-o smtpd_tls_security_level=encrypt
	-o smtpd_tls_auth_only=yes
	-o smtpd_client_restrictions=permit_sasl_authenticated,reject
	-o smtpd_sender_restrictions=reject_sender_login_mismatch,reject_unknown_sender_domain
	-o smtpd_sender_login_maps=pcre:/etc/postfix/login_maps.pcre
	-o smtpd_recipient_restrictions=\
permit_sasl_authenticated,reject_unauth_destination,reject_unknown_recipient_domain
smtps     inet  n       -       n       -       -       smtpd
	-o syslog_name=postfix/smtps
	-o smtpd_tls_wrappermode=yes
	-o smtpd_tls_auth_only=yes
	-o smtpd_sasl_auth_enable=yes
	-o smtpd_client_restrictions=permit_sasl_authenticated,reject
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
	local mailbox_format="maildir"

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

# Search for valid users in /etc/passwd. Dovecot 2.4 selects the
# driver from the block name; the old "driver =" setting is not valid.
userdb passwd {
}
# Fallback: Use plain old PAM to find user passwords
passdb pam {
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
	path = /var/lib/dovecot/sieve/default.sieve
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

	protocols = imap pop3

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
		1 | 2.1* | 2.2*) sed -i '/^[[:space:]]*ssl_dh/d' \
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

# OpenDKIM runs as the unprivileged opendkim user on Debian. Directories
# must be traversable by its group; private keys only need group read.
fix_dkim_permissions() {
	local _root="/etc/postfix/dkim"
	[ -d "$_root" ] || return 0
	chgrp -R opendkim "$_root"
	find "$_root" -type d -exec chmod 750 {} +
	find "$_root" -type f -name '*.private' -exec chmod 640 {} +
	find "$_root" -type f ! -name '*.private' -exec chmod 640 {} +
}

# Append a line only when the exact line is absent.
append_unique_line() {
	local _file="$1"
	local _line="$2"
	touch "$_file"
	grep -qxF "$_line" "$_file" || printf '%s\n' "$_line" >>"$_file"
}

# Function to configure OpenDKIM
configure_opendkim() {
	local domain="$1"
	local subdom="$2"
	local maildomain="$subdom.$domain"
	local _p _keyname

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

	if [ ! -f "/etc/postfix/dkim/$domain/$subdom.private" ]; then
		opendkim-genkey -b 2048 -D "/etc/postfix/dkim/$domain" \
			-d "$domain" -s "$subdom"
	fi
	fix_dkim_permissions

	echo "Configuring OpenDKIM..."

	# Generate the OpenDKIM info. Use a whitespace-tolerant check so an
	# entry written with tabs is not duplicated.
	_keyname="$subdom._domainkey.$domain"
	_p="/etc/postfix/dkim/$domain/$subdom.private"
	if ! grep -qE "^${_keyname//./\\.}([[:space:]]|$)" \
		/etc/postfix/dkim/keytable 2>/dev/null; then
		printf '%s %s\n' "$_keyname" \
			"$domain:$subdom:$_p" \
			>>/etc/postfix/dkim/keytable
	fi

	append_unique_line /etc/postfix/dkim/signingtable \
		"*@$domain $_keyname"
	# Mail generated by the system uses mail.$domain as its sender; sign
	# it with the same key instead of leaving it unauthenticated.
	append_unique_line /etc/postfix/dkim/signingtable \
		"*@$maildomain $_keyname"

	append_unique_line /etc/postfix/dkim/trustedhosts '127.0.0.0/8'
	append_unique_line /etc/postfix/dkim/trustedhosts '::1'
	fix_dkim_permissions

	# ...and source it from opendkim.conf. Check each directive so a
	# partial pre-existing configuration is repaired.
	grep -q '^KeyTable' /etc/opendkim.conf 2>/dev/null ||
		echo 'KeyTable file:/etc/postfix/dkim/keytable' \
			>>/etc/opendkim.conf
	grep -q '^SigningTable' /etc/opendkim.conf 2>/dev/null ||
		echo 'SigningTable refile:/etc/postfix/dkim/signingtable' \
			>>/etc/opendkim.conf
	grep -q '^InternalHosts' /etc/opendkim.conf 2>/dev/null ||
		echo 'InternalHosts refile:/etc/postfix/dkim/trustedhosts' \
			>>/etc/opendkim.conf

	# Debian ships Mode v (verify only) by default; signing requires s.
	if grep -qE '^[[:space:]]*Mode[[:space:]]' /etc/opendkim.conf; then
		sed -i -E 's|^[[:space:]]*Mode[[:space:]].*|Mode sv|' \
			/etc/opendkim.conf
	else
		echo 'Mode sv' >>/etc/opendkim.conf
	fi

	# Normalize the stock commented directive instead of assuming a
	# particular comment prefix or value.
	if grep -qE '^[[:space:]]*#?[[:space:]]*Canonicalization' \
		/etc/opendkim.conf; then
		sed -i -E \
			's|^[[:space:]]*#?[[:space:]]*Canonicalization.*|Canonicalization relaxed/simple|' \
			/etc/opendkim.conf
	else
		echo 'Canonicalization relaxed/simple' >>/etc/opendkim.conf
	fi

	# Remove every old Socket directive, including a previously added
	# one, then add the loopback milter socket exactly once.
	sed -i -E '/^[[:space:]]*#?[[:space:]]*Socket[[:space:]]/d' \
		/etc/opendkim.conf
	echo 'Socket inet:12301@localhost' >>/etc/opendkim.conf

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

	# These files belong to emailwiz, so rewrite them on every run. This
	# removes stale jails (for example the inert sieve jail used by older
	# versions) and makes the result deterministic.
	cat >/etc/fail2ban/jail.d/emailwiz.local <<'EOF'
[postfix]
enabled = true
[postfix-sasl]
enabled = true
[dovecot]
enabled = true
EOF

	if [ "$_init" = "systemd" ]; then
		printf '%s\n' \
			'[DEFAULT]' \
			'backend = systemd' \
			'ignoreip = 127.0.0.1/8 ::1' \
			>/etc/fail2ban/jail.d/emailwiz-backend.local
	else
		printf '%s\n' \
			'[DEFAULT]' \
			'backend = auto' \
			'ignoreip = 127.0.0.1/8 ::1' \
			>/etc/fail2ban/jail.d/emailwiz-backend.local
	fi
}

# Function to configure SpamAssassin
configure_spamassassin() {
	local _file _svc
	echo "Enabling SpamAssassin..."

	# Enable both the daemon and its update cronjob. Setting only CRON
	# leaves spamd disabled on systems that ship ENABLED=0.
	if [ -f /etc/default/spamassassin ]; then
		_file=/etc/default/spamassassin
		_svc=spamassassin
	elif [ -f /etc/default/spamd ]; then
		_file=/etc/default/spamd
		_svc=spamd
	else
		error "Neither /etc/default/spamassassin nor" \
			"/etc/default/spamd exists; this is unexpected" \
			"and needs investigation."
		exit 1
	fi

	sed -i -E 's|^CRON=.*|CRON=1|; s|^ENABLED=.*|ENABLED=1|' "$_file"
	grep -q '^CRON=' "$_file" || echo 'CRON=1' >>"$_file"
	grep -q '^ENABLED=' "$_file" || echo 'ENABLED=1' >>"$_file"

	printf 'Restarting %s...' "$_svc"
	if svc_restart "$_svc"; then
		printf ' ...done\n'
	else
		printf ' ...FAILED\n'
		warn "Could not restart $_svc; check its logs."
		service_failures=$((service_failures + 1))
	fi
	if ! svc_enable "$_svc"; then
		warn "Could not enable $_svc."
		service_failures=$((service_failures + 1))
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
			service_failures=$((service_failures + 1))
		fi
		if ! svc_enable "$x"; then
			warn "Could not enable $x."
			service_failures=$((service_failures + 1))
		fi
	done
}

# Function to configure cronjobs and renewal hook
create_cronjob() {
	local maildomain="$1"

	echo "Creating cronjob to delete month-old postmaster mails..."
	cat <<EOF >/etc/cron.weekly/postmaster-clean
#!/bin/sh

find /home/postmaster/Mail -type f -mtime +30 \
	-delete >/dev/null 2>&1
exit 0
EOF
	chmod 700 /etc/cron.weekly/postmaster-clean

	# Self-signed mode creates /etc/letsencrypt too, but there is no
	# Certbot lineage to renew. Only install the hook for Certbot.
	if [ "$selfsigned" = "yes" ] || ! command -v certbot >/dev/null 2>&1; then
		return 0
	fi

	local _hook_line _reload_cmd
	_reload_cmd="$(svc_reload_cmd)"
	# Certbot expands $RENEWED_DOMAINS at renewal time, so keep it
	# literal in the generated deploy hook.
	# shellcheck disable=SC2016
	_hook_line='deploy-hook = echo "$RENEWED_DOMAINS"'
	_hook_line+=" | grep -qF"
	_hook_line+=" -e '$maildomain'"
	# A wildcard renewal lists *.example.com, not mail.example.com.
	_hook_line+=" -e '*.$domain'"
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
	# Only write the hook when a Certbot configuration directory
	# exists; a certificate may already be managed outside this run.
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
	local pval _out="$HOME" _owner=""
	if [ ! -f "/etc/postfix/dkim/$domain/$subdom.txt" ]; then
		error "Missing DKIM public key file:" \
			"/etc/postfix/dkim/$domain/$subdom.txt"
		exit 1
	fi
	pval=$(tr -d '\n' </etc/postfix/dkim/"$domain"/"$subdom".txt |
		sed -e 's/.*p=//' -e 's/).*//' \
			-e 's/["[:space:]]//g')
	case "$pval" in
	'' | *[!A-Za-z0-9+/=]*)
		error "Could not extract a valid DKIM public key from" \
			"/etc/postfix/dkim/$domain/$subdom.txt."
		error "Refusing to write an incomplete DNS record."
		exit 1
		;;
	esac
	dkimentry="$subdom._domainkey.$domain	TXT	v=DKIM1; k=rsa; p=$pval"
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
	ensure_mail_alias dmarc postmaster

	# Under sudo, write the records to the invoking user's home so the
	# documented "~/" path is useful, then restore that ownership.
	if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
		if command -v getent >/dev/null 2>&1; then
			_out=$(getent passwd "$SUDO_USER" | cut -d: -f6)
		fi
		if [ -z "$_out" ] || [ ! -d "$_out" ]; then
			_out="$HOME"
		else
			_owner="$SUDO_USER"
		fi
	fi

	cat >"$_out/dns_emailwizard" <<EOF
NOTE: Elements in the entries might appear in a different order \
in your registrar's DNS settings.
$dkimentry
$dmarcentry
$spfentry
$mxentry
EOF
	chmod 600 "$_out/dns_emailwizard"
	if [ -n "$_owner" ]; then
		chown "$_owner" "$_out/dns_emailwizard" 2>/dev/null || true
	fi
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

Once you do that, check the README for how to add \
users/accounts and how to log in.
EOF
	if [ "$service_failures" -gt 0 ]; then
		error "$service_failures service operation(s) failed."
		error "Do not treat this installation as complete until the" \
			"logs and service status have been checked."
		exit 1
	fi
}

# Validate generated configuration before restarting daemons.
validate_configs() {
	log "Validating generated configuration..."
	if command -v postfix >/dev/null 2>&1; then
		postfix check || {
			error "Postfix configuration check failed."
			exit 1
		}
	fi
	if command -v doveconf >/dev/null 2>&1; then
		doveconf -n >/dev/null || {
			error "Dovecot configuration check failed."
			exit 1
		}
	fi
	if command -v nft >/dev/null 2>&1; then
		nft -c -f /etc/nftables.conf || {
			error "nftables ruleset check failed."
			exit 1
		}
	fi
	if command -v spamassassin >/dev/null 2>&1; then
		spamassassin --lint >/dev/null 2>&1 || {
			warn "SpamAssassin configuration lint reported problems."
		}
	fi
}

# Main script execution
main() {
	check_root
	detect_init
	detect_ssh_ports

	domain="$(hostname --domain | tr -d '[:space:]')"
	subdom="${MAIL_SUBDOM:-mail}"
	if [ -z "$domain" ]; then
		error "No domain found. Set a fully qualified hostname" \
			"(e.g. 'mail.example.com') before running this script."
		exit 1
	fi
	if ! validate_domain "$domain"; then
		error "Invalid domain detected from the hostname: '$domain'."
		exit 1
	fi
	if ! validate_subdom "$subdom"; then
		error "Invalid MAIL_SUBDOM value: '$subdom'" \
			"(letters, numbers and internal dashes only)."
		exit 1
	fi
	maildomain="$subdom.$domain"
	certdir="/etc/letsencrypt/live/$maildomain"

	confirm_installation
	install_packages "$maildomain"

	configure_firewall
	configure_ssl "$domain" "$subdom"
	configure_postfix "$domain" "$subdom"
	configure_dovecot "$domain" "$subdom"
	configure_opendkim "$domain" "$subdom"
	configure_fail2ban
	configure_spamassassin
	validate_configs
	restart_services
	generate_dns_entries "$domain" "$subdom"
	create_cronjob "$maildomain"
	final_output_message "$dkimentry" "$dmarcentry" "$spfentry" "$mxentry"
}

trap 'on_error $?' ERR
main "$@"
