#!/bin/bash

RAW_LOG="/var/log/mikrotik/raw.log"
LOG_LINE="2025-09-30T18:15:42+00:00 Rastronet input: in:bridge out:(unknown 0), connection-state:new src-mac 00:1c:2d:05:30:50, proto UDP, 192.168.1.225:4992->255.255.255.255:4992, len 712<30>Sep 30 18:15:43 Rastronet input: in:bridge out:(unknown 0), connection-state:new src-mac 4c:a9:19:77:ed:d9, proto UDP, 192.168.1.143:59733->255.255.255.255:6667, len 200"

mkdir -p "$(dirname "$RAW_LOG")"

# Ingest the log 20 times in 20 seconds
for i in {1..20}; do
    echo "$LOG_LINE" >> "$RAW_LOG"
    echo "[$i] Log written to $RAW_LOG"
    sleep 1
done

echo "Finished writing 20 logs in 20 seconds to $RAW_LOG"
