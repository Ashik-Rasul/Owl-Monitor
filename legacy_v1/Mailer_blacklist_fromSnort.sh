#!/bin/bash

LOG_FILE="/var/log/snort/snort.alert.fast"
BLACKLIST="blacklist.txt"
ADMIN_EMAIL="ashikrasul888@gmail.com"

echo "Monitoring Snort alerts..."

tail -F $LOG_FILE | while read line
do

    if [[ -f "$BLACKLIST" ]]; then

        echo "New Snort alert detected"
        
        SUBJECT="Snort IDS Alert - Blacklist Update"

        mail -s "$SUBJECT" $ADMIN_EMAIL < $BLACKLIST

        echo "Blacklist sent to admin email"

    fi

done
