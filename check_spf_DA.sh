#!/bin/bash
LOG_FILE="/var/log/mail-checker/check_spf.log"
#exec 2>>"$LOG_FILE"
exec 2>> >(while read line; do echo "$(date '+%Y-%m-%d %H:%M:%S') $line"; done >> "$LOG_FILE")

HEADER_INPUT="$1"

if [[ -z "$HEADER_INPUT" ]]; then
    echo "Usage: $0 <header_file_or_text>"
    exit 1
fi

if [[ -f "$HEADER_INPUT" ]]; then
    header_content=$(cat "$HEADER_INPUT")
else
    header_content="$HEADER_INPUT"
fi

EXPECTED_HOST=$(hostname -f)

first_received_line=$(echo "$header_content" | grep -i '^Received:' | head -n 1)

if ! echo "$first_received_line" | grep -qi "$EXPECTED_HOST"; then
    echo "Non-local email detected based on first Received header, exiting with success." | tee -a "$LOG_FILE"
    exit 0
fi

message_id_line=$(echo "$header_content" | grep -i '^Message-Id:' | head -n 1)

if [[ -z "$message_id_line" ]]; then
    echo "Error: Message-ID not found in the header text."
    exit 1
fi

SENDER_DOMAIN=$(echo "$message_id_line" | grep -oP '@\K[^>]+' | head -n 1)

if [[ -z "$SENDER_DOMAIN" ]]; then
    echo "Error: Unable to extract domain from Message-ID. Exiting."
    exit 1
fi

# DirectAdmin SPF template path
TEMPLATE_PATH="/usr/local/directadmin/data/templates/custom/dns_spf.conf"

if [[ ! -f "$TEMPLATE_PATH" ]]; then
    echo "[$(date)] ERROR: SPF template not found at $TEMPLATE_PATH" | tee -a "$LOG_FILE"
    exit 1
fi

# Extract hostname part (value after a:) from DirectAdmin template
hostname=$(grep -oP 'a:([^\s]+)' "$TEMPLATE_PATH" | head -n 1 | cut -d':' -f2)

if [[ -z "$hostname" ]]; then
    # fallback to system hostname
    hostname=$(hostname -f)
fi

validate_spf() {
    local domain="$1"
    local record="$2"
    echo "[$(date)] Checking SPF for domain: $domain" | tee -a "$LOG_FILE"

    if [[ -z "$record" ]]; then
        echo "[$(date)] ERROR: Missing SPF record for $domain" | tee -a "$LOG_FILE"
        return 1
    fi

    # Convert the SPF record to lowercase for consistency
    record=$(echo "$record" | tr '[:upper:]' '[:lower:]')

    if [[ "$record" =~ "a:$hostname" && "$record" =~ "mx" && "$record" =~ "ip4" && "$record" =~ "~all" ]]; then
        echo "[$(date)] SUCCESS: SPF is valid for $domain" | tee -a "$LOG_FILE"
        echo "----------------------------------------------------------------" | tee -a "$LOG_FILE"
        return 0
    else
        echo "[$(date)] ERROR: Invalid SPF for $domain (Missing a:$hostname, MX, ip4 or ~all)" | tee -a "$LOG_FILE"
        return 1
    fi
}

# Get the SPF record for the sender domain using dig
spf=$(dig +trace TXT "$SENDER_DOMAIN" | grep 'v=spf1')

validate_spf "$SENDER_DOMAIN" "$spf"

if [[ $? -ne 0 ]]; then
    echo "[$(date)] CRITICAL: SPF record remains invalid for $SENDER_DOMAIN" | tee -a "$LOG_FILE"
    echo "----------------------------------------------------------------" | tee -a "$LOG_FILE"
    exit 1
else
    exit 0
fi
