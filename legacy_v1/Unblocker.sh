#!/bin/bash

echo "Fetching DROP rules from iptables..."

# Get rule numbers of DROP entries in INPUT chain
RULES=$(sudo iptables -L INPUT --line-numbers -n | grep DROP | awk '{print $1}' | sort -rn)

for rule in $RULES
do
    echo "Deleting rule $rule"
    sudo iptables -D INPUT $rule
done

echo "All blocked IPs are now unblocked."
