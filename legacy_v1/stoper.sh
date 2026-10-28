#!/bin/bash

for pid in $(cat monitor_pids.txt)
do
    kill $pid
done

echo "All monitoring tools stopped"
