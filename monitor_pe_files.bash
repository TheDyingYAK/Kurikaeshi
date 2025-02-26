#!/bin/bash

WATCH_DIR="/home/user/target_directory"
LOG_FILE="/var/log/pe_hashes.log"

inotifywait -m -r -e close_write --format "%w%f" "$WATCH_DIR" | while read FILE; do
    if file "$FILE" | grep -q "PE32"; then
        HASH=$(sha256sum "$FILE")
        echo "$(date) - $HASH" >> "$LOG_FILE"
    fi
done
