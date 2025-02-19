#!/bin/bash

# Email Server Add Domain Script
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

set -euo pipefail

ensure_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "This script must be run as root. Please run it again with 'sudo' or as the root user."
        exit 1
    fi
}

validate_input() {
    if [ "$#" -ne 2 ]; then
        cat <<EOF
This script adds a new domain to the email server configuration.
Usage: ./adddomain.sh <new_domain> <mail_service_domain>

<new_domain>: The new domain you want to add.
<mail_service_domain>: The existing mail service domain.
EOF
        exit 1
    fi

    read -p "Have you read and understood the above instructions? (yes/no): " response
    if [ "$response" != "yes" ]; then
        echo "Please read the instructions carefully before proceeding."
        exit 1
    fi
}

add_domain_to_postfix() {
    local new_domain="$1"
    echo "Adding the new domain to the valid Postfix addresses..."
    if ! grep -q "^mydestination.*$new_domain" /etc/postfix/main.cf; then
        sed -i "/^mydestination/s/$/, $new_domain/" /etc/postfix/main.cf
    fi
}

create_dkim() {
    local new_domain="$1"
    local subdom="mail"
    echo "Creating DKIM for the new domain..."
    mkdir -p "/etc/postfix/dkim/$new_domain"
    opendkim-genkey -D "/etc/postfix/dkim/$new_domain" -d "$new_domain" -s "$subdom"
    chgrp -R opendkim /etc/postfix/dkim/*
    chmod -R g+r /etc/postfix/dkim/*
}

update_dkim_tables() {
    local new_domain="$1"
    local subdom="mail"
    echo "Adding entries to keytable and signing table..."
    echo "$subdom._domainkey.$new_domain $new_domain:$subdom:/etc/postfix/dkim/$new_domain/$subdom.private" >> /etc/postfix/dkim/keytable
    echo "*@$new_domain $subdom._domainkey.$new_domain" >> /etc/postfix/dkim/signingtable
}

reload_services() {
    echo "Reloading OpenDKIM and Postfix services..."
    systemctl reload opendkim postfix
}

generate_dns_entries() {
    local new_domain="$1"
    local mail_service_domain="$2"
    local subdom="mail"
    local maildomain="$subdom.$mail_service_domain"

    echo "Generating DKIM TXT entry..."
    pval=$(sed -e '1d' -e ':a' -e 'N' -e '$!ba' -e 's/\n//g' "/etc/postfix/dkim/$new_domain/$subdom.txt" \
        | sed -e "s/k=rsa.* \"p=/k=rsa; p=/" \
              -e "s/\"\s*).*//" \
        | grep -o 'p=.*')

    local dkimentry="$subdom._domainkey.$new_domain	TXT	v=DKIM1; k=rsa; $pval"
    local dmarcentry="_dmarc.$new_domain	TXT	v=DMARC1; p=reject; rua=mailto:dmarc@$new_domain; fo=1"
    local spfentry="$new_domain	TXT	v=spf1 mx a:$maildomain -all"
    local mxentry="$new_domain	MX	10	$maildomain"

    cat <<EOF >> "$HOME/dns_emailwizard_added"
$dkimentry
$dmarcentry
$spfentry
$mxentry
EOF

    echo "=== ADD THE FOLLOWING TO YOUR DNS TXT RECORDS ==="
    cat <<EOF
$dkimentry
$dmarcentry
$spfentry
$mxentry
EOF
    echo "They have also been stored in $HOME/dns_emailwizard_added"
}

main() {
    ensure_root
    validate_input "$@"
    local new_domain="$1"
    local mail_service_domain="$2"
    add_domain_to_postfix "$new_domain"
    create_dkim "$new_domain"
    update_dkim_tables "$new_domain"
    reload_services
    generate_dns_entries "$new_domain" "$mail_service_domain"
}

main "$@"