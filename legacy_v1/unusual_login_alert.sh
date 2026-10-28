#!/bin/bash

LOG_FILE="/var/log/auth.log"
ADMIN_EMAIL="ashikrasul888@gmail.com"

START_TIME=0
END_TIME=7

tail -Fn0 "$LOG_FILE" | while read line
do
    if echo "$line" | grep "Accepted"; then
        
        HOUR=$(date +"%H")

        if [ "$HOUR" -ge "$START_TIME" ] && [ "$HOUR" -lt "$END_TIME" ]; then
            
            USER=$(echo "$line" | awk '{print $9}')
            IP=$(echo "$line" | awk '{print $11}')
            LOG_TIME=$(echo "$line" | awk '{print $1, $2, $3}')

            MESSAGE="⚠️ ALERT: Unauthorized SSH Access Detected

Your server was accessed without permission at an unusual time.

User: $USER
IP Address: $IP
Time: $LOG_TIME

Log Entry:
$line

Please verify this activity immediately."

            echo "$MESSAGE" | mail -s "ALERT: Unusual SSH Login" "$ADMIN_EMAIL"

        fi
    fi
done
