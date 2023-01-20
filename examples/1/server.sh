#!/bin/sh
while true; do
        num=`ps -ef | grep "socat" | grep -v "grep" | wc -l`
        if [ $num -lt 1 ]; then
                socat tcp4-listen:1337,reuseaddr,fork exec:./chall &
        fi
done
