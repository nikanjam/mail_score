#!/bin/bash
LOG_FILE="/var/log/mail_check_header/check_spf.log"
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

hostname=$(grep -oP 'a:[^\s]*' /var/cpanel/zonetemplates/standardvirtualftp | cut -d':' -f2)
#set -x
validate_spf() {
    local domain="$1"
    local record="$2"
    echo "[$(date)] Checking SPF for domain: $domain" | tee -a "$LOG_FILE"

    if [[ -z "$record" ]]; then
        echo "[$(date)] ERROR: Missing SPF record for $domain" | tee -a "$LOG_FILE"
        return 1
    fi

    if [[ "$record" =~ "a:$hostname" && "$record" =~ "mx" && "$record" =~ "+a" && "$record" =~ "~all" ]]; then
        echo "[$(date)] SUCCESS: SPF is valid for $domain" | tee -a "$LOG_FILE"
        echo "----------------------------------------------------------------" | tee -a "$LOG_FILE"
#set +x
        return 0
    else
        echo "[$(date)] ERROR: Invalid SPF for $domain (Missing a:$hostname, MX, +a, or ~all)" | tee -a "$LOG_FILE"
        return 1
    fi
}

spf=$(dig +trace TXT "$SENDER_DOMAIN" | grep 'v=spf1')
validate_spf "$SENDER_DOMAIN" "$spf"

if [[ $? -ne 0 ]]; then
    echo "[$(date)] CRITICAL: SPF record remains invalid for $SENDER_DOMAIN" | tee -a "$LOG_FILE"
    echo "----------------------------------------------------------------"  | tee -a "$LOG_FILE"
    exit 1
else
    exit 0
fi
