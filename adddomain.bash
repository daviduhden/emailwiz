#!/bin/bash -e

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

cat <<EOF
This script adds a new domain to the email server configuration.
Usage: ./adddomain.sh <new_domain> <mail_service_domain>

<new_domain>: The new domain you want to add.
<mail_service_domain>: The existing mail service domain.
EOF

read -p "Have you read and understood the above instructions? (yes/no): " response
if [ "$response" != "yes" ]; then
    echo "Please read the instructions carefully before proceeding."
    exit 1
fi

new_domain="$1"
mail_service_domain="$2"

# Check if both domains are provided
[ -z "$new_domain" ] || [ -z "$mail_service_domain" ] && { echo "Usage: $0 new_domain mail_service_domain"; exit 1; }

subdom="mail"
maildomain="$subdom.$mail_service_domain"

echo "Adding the new domain to the valid Postfix addresses..."
if ! grep -q "^mydestination.*$new_domain" /etc/postfix/main.cf; then
    sed -i "s/^mydestination.*/&, $new_domain/" /etc/postfix/main.cf
fi

echo "Creating DKIM for the new domain..."
mkdir -p "/etc/postfix/dkim/$new_domain"
opendkim-genkey -D "/etc/postfix/dkim/$new_domain" -d "$new_domain" -s "$subdom"
chgrp -R opendkim /etc/postfix/dkim/*
chmod -R g+r /etc/postfix/dkim/*

echo "Adding entries to keytable and signing table..."
echo "$subdom._domainkey.$new_domain $new_domain:$subdom:/etc/postfix/dkim/$new_domain/$subdom.private" >> /etc/postfix/dkim/keytable
echo "*@$new_domain $subdom._domainkey.$new_domain" >> /etc/postfix/dkim/signingtable

echo "Reloading OpenDKIM and Postfix services..."
systemctl reload opendkim postfix

echo "Generating DKIM TXT entry..."
pval="$(tr -d '\n' <"/etc/postfix/dkim/$new_domain/$subdom.txt" | sed "s/k=rsa.* \"p=/k=rsa; p=/;s/\"\s*\"//;s/\"\s*).*//" | grep -o 'p=.*')"

dkimentry="$subdom._domainkey.$new_domain	TXT	v=DKIM1; k=rsa; $pval"
dmarcentry="_dmarc.$new_domain	TXT	v=DMARC1; p=reject; rua=mailto:dmarc@$new_domain; fo=1"
spfentry="$new_domain	TXT	v=spf1 mx a:$maildomain -all"
mxentry="$new_domain	MX	10	$maildomain"

echo "$dkimentry
$dmarcentry
$spfentry
$mxentry" >> "$HOME/dns_emailwizard_added"

chmod 600 "$HOME/dns_emailwizard_added"

echo "=== ADD THE FOLLOWING TO YOUR DNS TXT RECORDS ==="
echo "$dkimentry
$dmarcentry
$spfentry
$mxentry"
echo "They have also been stored in $HOME/dns_emailwizard_added"