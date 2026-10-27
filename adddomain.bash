#!/bin/bash

set -euo pipefail

# Email Server Add Domain Script
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

backup_dir=""

# Validate a DNS name without accepting leading/trailing dots or labels.
validate_domain() {
	local _name="$1"
	[ -n "$_name" ] || return 1
	case "$_name" in
	.* | *. | *..* | *[!A-Za-z0-9.-]*) return 1 ;;
	esac
	[[ $_name =~ ^([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]]
}

validate_subdom() {
	local _name="$1"
	[ -n "$_name" ] || return 1
	[[ $_name =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]]
}

on_error() {
	local _status="$1"
	error "Adding the domain failed (exit status $_status)."
	if [ -n "$backup_dir" ] && [ -f "$backup_dir/postfix-state.tar.gz" ]; then
		error "Configuration backup: $backup_dir/postfix-state.tar.gz"
	fi
	error "Inspect the logs before retrying or restoring anything."
	exit "$_status"
}

# Save the small set of files this helper mutates. The archive is root-only.
backup_adddomain_state() {
	local _ts _dir _rel _old_umask
	local -a _rels=()
	_ts="$(date '+%Y%m%d-%H%M%S')"
	_dir="/var/backups/emailwiz/adddomain-$_ts"
	for _rel in etc/postfix/main.cf etc/postfix/login_maps.pcre \
		etc/postfix/dkim/keytable etc/postfix/dkim/signingtable \
		etc/aliases; do
		if [ -e "/$_rel" ]; then
			_rels+=("$_rel")
		fi
	done
	if [ ${#_rels[@]} -eq 0 ]; then
		return 0
	fi
	_old_umask="$(umask)"
	umask 0077
	if ! mkdir -p "$_dir"; then
		warn "Could not create backup directory $_dir."
		umask "$_old_umask"
		return 1
	fi
	chmod 700 "$_dir"
	if tar -czf "$_dir/postfix-state.tar.gz" -C / "${_rels[@]}"; then
		chmod 600 "$_dir/postfix-state.tar.gz"
		backup_dir="$_dir"
		log "Backed up Postfix state to" \
			"$_dir/postfix-state.tar.gz"
	else
		warn "Could not archive Postfix state."
		umask "$_old_umask"
		return 1
	fi
	umask "$_old_umask"
}

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

append_unique_line() {
	local _file="$1"
	local _line="$2"
	[ -f "$_file" ] || : >"$_file"
	grep -qxF "$_line" "$_file" || printf '%s\n' "$_line" >>"$_file"
}

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

# Function to ensure the script is run as root
check_root() {
	if [ "$(id -u)" -ne 0 ]; then
		error "This script must be run as root." \
			"Please run it again with 'sudo' or as the root user."
		exit 1
	fi
}

# Function to validate input parameters
validate_input() {
	if [ "$#" -ne 2 ]; then
		cat <<EOF
This script adds a new domain to the email server configuration.
Usage: ./adddomain.bash <new_domain> <mail_service_domain>

<new_domain>: The new domain you want to add.
<mail_service_domain>: The existing mail service domain (the base
domain used when emailwiz.bash ran, for example example.org).
EOF
		exit 1
	fi

	if ! validate_domain "$1"; then
		error "Provide a valid fully qualified domain as the first" \
			"argument (for example new.example.org)."
		exit 1
	fi

	if ! validate_domain "$2"; then
		error "Provide a valid mail service domain as the second" \
			"argument (for example example.org)."
		exit 1
	fi

	if [ "$1" = "$2" ]; then
		error "The new domain must differ from the mail service domain."
		exit 1
	fi

	local subdom="${MAIL_SUBDOM:-mail}"
	local response=""
	if ! validate_subdom "$subdom"; then
		error "Invalid MAIL_SUBDOM value: '$subdom'" \
			"(letters, numbers, and internal dashes only)."
		exit 1
	fi

	cat <<EOF
This will:
  - add $1 to Postfix's local destinations
  - add a sender-login entry for $1
  - create DKIM key material if it does not exist
  - reload OpenDKIM and Postfix
  - print DNS records for $1

The mail host must be $subdom.$2. No mailbox or user is created.
EOF

	read -r -p \
		"Have you read and understood the above instructions? (yes/no): " \
		response || true
	if [ "$response" != "yes" ]; then
		error "Please read the instructions carefully before proceeding."
		exit 1
	fi
}

# Function to add new domain to Postfix configuration
add_domain_to_postfix() {
	local new_domain="$1"
	local _esc="${new_domain//./\\.}"
	log "Adding the new domain to the valid Postfix addresses..."
	if [ ! -f /etc/postfix/main.cf ]; then
		error "/etc/postfix/main.cf not found; run emailwiz.bash first."
		exit 1
	fi
	if ! grep -q '^mydestination[[:space:]]*=' /etc/postfix/main.cf; then
		error "No mydestination setting in /etc/postfix/main.cf;" \
			"run emailwiz.bash first."
		exit 1
	fi
	# Only append when the domain is not already a token in the list.
	if ! grep -qE "^mydestination.*[ ,]${_esc}([ ,]|$)" \
		/etc/postfix/main.cf; then
		sed -i "/^mydestination/s/$/, $new_domain/" /etc/postfix/main.cf
	fi

	# Let authenticated users of the new domain send mail as it.
	# Without this entry, smtpd_sender_restrictions'
	# reject_sender_login_mismatch rejects every sender in the new
	# domain because smtpd_sender_login_maps has no match.
	local _lmfile="/etc/postfix/login_maps.pcre"
	if [ ! -f "$_lmfile" ]; then
		error "$_lmfile not found; run emailwiz.bash first."
		exit 1
	fi
	local _line="/^(.*)@${_esc}$/   \${1}"
	grep -qF "@${_esc}\$/" "$_lmfile" ||
		printf '%s\n' "$_line" >>"$_lmfile"
}

# Function to create DKIM for the new domain
create_dkim() {
	local new_domain="$1"
	local subdom="${MAIL_SUBDOM:-mail}"
	log "Creating DKIM for the new domain..."
	mkdir -p "/etc/postfix/dkim/$new_domain"
	# Do not overwrite an existing key: replacing it would invalidate
	# any DKIM record already published in DNS.
	if [ ! -f "/etc/postfix/dkim/$new_domain/$subdom.private" ]; then
		opendkim-genkey -b 2048 -D "/etc/postfix/dkim/$new_domain" \
			-d "$new_domain" -s "$subdom"
	fi
	chgrp -R opendkim /etc/postfix/dkim
	find /etc/postfix/dkim -type d -exec chmod 750 {} +
	find /etc/postfix/dkim -type f -name '*.private' \
		-exec chmod 640 {} +
	find /etc/postfix/dkim -type f ! -name '*.private' \
		-exec chmod 640 {} +
}

# Function to update DKIM tables
update_dkim_tables() {
	local new_domain="$1"
	local subdom="${MAIL_SUBDOM:-mail}"
	log "Adding entries to keytable and signing table..."
	local _p="/etc/postfix/dkim/$new_domain/$subdom.private"
	local _keyname="$subdom._domainkey.$new_domain"
	if ! grep -qE "^${_keyname//./\\.}([[:space:]]|$)" \
		/etc/postfix/dkim/keytable 2>/dev/null; then
		printf '%s %s\n' "$_keyname" \
			"$new_domain:$subdom:$_p" \
			>>/etc/postfix/dkim/keytable
	fi
	append_unique_line /etc/postfix/dkim/signingtable \
		"*@$new_domain $_keyname"
	chgrp -R opendkim /etc/postfix/dkim
	find /etc/postfix/dkim -type d -exec chmod 750 {} +
	find /etc/postfix/dkim -type f -name '*.private' \
		-exec chmod 640 {} +
	find /etc/postfix/dkim -type f ! -name '*.private' \
		-exec chmod 640 {} +
}

# Function to validate and reload services
reload_services() {
	if command -v postfix >/dev/null 2>&1; then
		postfix check || {
			error "Postfix configuration check failed; not reloading."
			exit 1
		}
	fi
	log "Reloading OpenDKIM and Postfix services..."
	svc_reload opendkim postfix
}

# Function to generate DNS entries for the new domain
generate_dns_entries() {
	local new_domain="$1"
	local mail_service_domain="$2"
	local subdom="${MAIL_SUBDOM:-mail}"
	local maildomain="$subdom.$mail_service_domain"

	log "Generating DKIM TXT entry..."
	local pval _out="$HOME" _owner=""
	if [ ! -f "/etc/postfix/dkim/$new_domain/$subdom.txt" ]; then
		error "Missing DKIM public key file:" \
			"/etc/postfix/dkim/$new_domain/$subdom.txt"
		exit 1
	fi
	pval=$(tr -d '\n' \
		<"/etc/postfix/dkim/$new_domain/$subdom.txt" |
		sed -e 's/.*p=//' \
			-e 's/).*//' \
			-e 's/["[:space:]]//g')
	case "$pval" in
	'' | *[!A-Za-z0-9+/=]*)
		error "Could not extract a valid DKIM public key from" \
			"/etc/postfix/dkim/$new_domain/$subdom.txt."
		error "Refusing to write an incomplete DNS record."
		exit 1
		;;
	esac

	local dkimentry="$subdom._domainkey.$new_domain"
	dkimentry+="	TXT	v=DKIM1; k=rsa; p=$pval"
	local dmarcentry="_dmarc.$new_domain"
	dmarcentry+="	TXT	v=DMARC1; p=reject;"
	dmarcentry+=" rua=mailto:dmarc@$new_domain; fo=1"
	local spfentry="$new_domain	TXT	v=spf1 mx a:$maildomain -all"
	local mxentry="$new_domain	MX	10	$maildomain"

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

	local _dnsfile="$_out/dns_emailwizard_added"
	append_unique_line "$_dnsfile" "$dkimentry"
	append_unique_line "$_dnsfile" "$dmarcentry"
	append_unique_line "$_dnsfile" "$spfentry"
	append_unique_line "$_dnsfile" "$mxentry"
	chmod 600 "$_dnsfile"
	if [ -n "$_owner" ]; then
		chown "$_owner" "$_dnsfile" 2>/dev/null || true
	fi

	echo "=== ADD THE FOLLOWING TO YOUR DNS TXT RECORDS ==="
	cat <<EOF
$dkimentry
$dmarcentry
$spfentry
$mxentry
EOF
	echo "They have also been stored in $_dnsfile"
}

# Main script execution
main() {
	check_root
	detect_init
	validate_input "$@"
	local new_domain="$1"
	local mail_service_domain="$2"
	local subdom="${MAIL_SUBDOM:-mail}"
	local installed_domain installed_mailhost
	installed_domain=$(postconf -h mydomain 2>/dev/null || true)
	installed_mailhost=$(postconf -h myhostname 2>/dev/null || true)
	if [ -n "$installed_domain" ] &&
		[ "$installed_domain" != "$mail_service_domain" ]; then
		error "Postfix mydomain is '$installed_domain', not" \
			"'$mail_service_domain'. Refusing to emit records" \
			"for the wrong mail host."
		exit 1
	fi
	if [ -n "$installed_mailhost" ] &&
		[ "$installed_mailhost" != "$subdom.$mail_service_domain" ]; then
		error "Postfix myhostname is '$installed_mailhost', not" \
			"'$subdom.$mail_service_domain'. Check MAIL_SUBDOM."
		exit 1
	fi
	if ! backup_adddomain_state; then
		error "Backup failed; aborting before changing Postfix."
		exit 1
	fi
	add_domain_to_postfix "$new_domain"
	if ! id -u postmaster >/dev/null 2>&1; then
		if ! useradd -r -m -G mail postmaster; then
			error "Failed to create the postmaster user."
			exit 1
		fi
	fi
	ensure_mail_alias dmarc postmaster
	create_dkim "$new_domain"
	update_dkim_tables "$new_domain"
	reload_services
	generate_dns_entries "$new_domain" "$mail_service_domain"
}

trap 'on_error $?' ERR
main "$@"
