#!/bin/bash
set -euo pipefail

LOG_FILE="/var/log/mail-checker/check_dkim.log"
exec 2>> >(awk '{print strftime("[%Y-%m-%d %H:%M:%S]"), $0; fflush()}' >> "$LOG_FILE")

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

EXPECTED_HOST=$(hostname -f)

if [[ "$#" -lt 1 ]]; then
    log "Usage: $0 <header_file_or_text> [local_public_key_file]"
    exit 1
fi

HEADER_INPUT="$1"

if [[ -f "$HEADER_INPUT" ]]; then
    header_content=$(cat "$HEADER_INPUT")
else
    header_content="$HEADER_INPUT"
fi

first_received_line=$(echo "$header_content" | grep -i '^Received:' | head -n 1)
if ! echo "$first_received_line" | grep -qi "$EXPECTED_HOST"; then
    log "Non-local email detected based on first Received header (EXPECTED_HOST: $EXPECTED_HOST), exiting with success."
    exit 0
fi

# ------------------------------------------------------------------------------------------

message_id_line=$(echo "$header_content" | grep -i '^Message-Id:' | head -n 1)

if [[ -z "$message_id_line" ]]; then
    log "Error: Message-ID not found in the header text."
    exit 1
fi

SENDER_DOMAIN=$(echo "$message_id_line" | grep -oP '@\K[^>]+' | head -n 1)

if [[ -z "$SENDER_DOMAIN" ]]; then
    log "Error: Unable to extract domain from Message-ID. Exiting."
    exit 1
fi

log "Extracted domain: $SENDER_DOMAIN"

# ---------------------- DKIM CHECK ----------------------
SELECTOR="x"
DKIM_DNS_RECORD="${SELECTOR}._domainkey.${SENDER_DOMAIN}"
log "Checking DKIM record for selector 'x': ${DKIM_DNS_RECORD}"

DKIM_RECORD=$(dig +short TXT "$DKIM_DNS_RECORD" | tr -d '"' || true)

if [[ -z "$DKIM_RECORD" || ! "$DKIM_RECORD" =~ "v=DKIM1" ]]; then
    log "No valid DKIM record found with selector 'x'. Trying with 'default'..."
    SELECTOR="default"
    DKIM_DNS_RECORD="${SELECTOR}._domainkey.${SENDER_DOMAIN}"
    DKIM_RECORD=$(dig +short TXT "$DKIM_DNS_RECORD" | tr -d '"' || true)
fi

if [[ -z "$DKIM_RECORD" || ! "$DKIM_RECORD" =~ "v=DKIM1" ]]; then
    log "Error: No valid DKIM record found for ${SENDER_DOMAIN} (both 'x' and 'default' failed)."
    exit 1
fi

log "Found DKIM record: $DKIM_RECORD"

DKIM_RECORD_CLEAN=$(echo "$DKIM_RECORD" | tr -d '"')

if ! echo "$DKIM_RECORD_CLEAN" | grep -qi "v=DKIM1"; then
    log "Error: DKIM record format invalid for ${DKIM_DNS_RECORD}"
    log "--------------------------------------------------------------------------------"
    exit 1
fi

PUBLIC_KEY_DNS=$(echo "$DKIM_RECORD_CLEAN" | grep -oP 'p=\K[^;]+')

if [ -z "$PUBLIC_KEY_DNS" ]; then
    log "Error: p tag not found in DKIM record"
    exit 1
fi

PUBLIC_KEY_DNS=$(echo "$PUBLIC_KEY_DNS" | tr -d '\n ')
log "Public key from DNS (selector '$SELECTOR'):"
log "$PUBLIC_KEY_DNS"

if [ "$#" -ge 2 ]; then
    LOCAL_KEY_FILE="$2"
else
    LOCAL_KEY_FILE="/var/cpanel/domain_keys/public/${SENDER_DOMAIN}"
fi

if [ ! -f "$LOCAL_KEY_FILE" ]; then
    log "Error: Local public key file not found: $LOCAL_KEY_FILE"
    log "--------------------------------------------------------------------------------"
    exit 1
fi

log "Reading local public key file: $LOCAL_KEY_FILE"
LOCAL_PUBLIC_KEY=$(sed '/-----BEGIN PUBLIC KEY-----/d; /-----END PUBLIC KEY-----/d' "$LOCAL_KEY_FILE" | tr -d '\n ')
log "Local public key:"
log "$LOCAL_PUBLIC_KEY"

if [ "$PUBLIC_KEY_DNS" = "$LOCAL_PUBLIC_KEY" ]; then
    log "SUCCESS: DNS public key matches local public key"
    log "--------------------------------------------------------------------------------"
    exit 0
else
    log "FAIL: DNS public key does not match local public key"
    log "--------------------------------------------------------------------------------"
    exit 1
fi
