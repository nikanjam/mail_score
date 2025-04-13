#!/bin/bash
#set -x
LOG_FILE="/var/log/mail_check_header/check_dmarc.log"
#exec 2>>"$LOG_FILE"
exec 2>> >(while read line; do echo "$(date '+%Y-%m-%d %H:%M:%S') $line"; done >> "$LOG_FILE")
HEADER_INPUT="$1"

if [[ -z "$HEADER_INPUT" ]]; then
    echo "Usage: $0 <header_file_or-text>"
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

validate_dmarc() {
    local domain="$1"
    local record="$2"
    echo "[$(date)] Checking DMARC for domain: $domain" | tee -a "$LOG_FILE"

    if [[ -z "$record" ]]; then
        echo "[$(date)] ERROR: DMARC record not found for $domain" | tee -a "$LOG_FILE"
        return 1
    fi

    if ! echo "$record" | grep -qi "v=DMARC1"; then
        echo "[$(date)] ERROR: DMARC record for $domain does not contain v=DMARC1" | tee -a "$LOG_FILE"
        return 1
    fi

    dmarc_policy=$(echo "$record" | grep -oP 'p=\K[^;]+' | head -n 1 | tr -d ' ')
    if [[ -z "$dmarc_policy" ]]; then
        echo "[$(date)] ERROR: DMARC record for $domain does not have a p tag" | tee -a "$LOG_FILE"
        return 1
    fi

    if [[ "$dmarc_policy" == "reject" || "$dmarc_policy" == "quarantine" || "$dmarc_policy" == "none" ]]; then
        echo "[$(date)] SUCCESS: DMARC record is valid for $domain with policy $dmarc_policy" | tee -a "$LOG_FILE"
        echo "--------------------------------------------------------------------------------" | tee -a "$LOG_FILE"
        return 0
    else
        echo "[$(date)] ERROR: DMARC policy for $domain is invalid: $dmarc_policy (expected 'reject' or 'quarantine')" | tee -a "$LOG_FILE"
        return 1
    fi
}

dmarc_record=$(dig +trace TXT _dmarc."$SENDER_DOMAIN" | grep -i 'v=DMARC1')

if [ -z "$dmarc_record" ]; then
    echo "Default DMARC record not found. Trying with selector 'x'..." | tee -a "$LOG_FILE"
    dmarc_record=$(dig +trace TXT _dmarc.x."$SENDER_DOMAIN" | grep -i 'v=DMARC1')
fi

validate_dmarc "$SENDER_DOMAIN" "$dmarc_record"

if [[ $? -ne 0 ]]; then
    echo "[$(date)] CRITICAL: DMARC record validation failed for $SENDER_DOMAIN" | tee -a "$LOG_FILE"
    echo "--------------------------------------------------------------------------------" | tee -a "$LOG_FILE"
    exit 1
else
    exit 0
fi
