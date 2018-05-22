#!/bin/bash

for host in $(seq 1 254); do 
ping -c 1 10.11.1.$host |grep "bytes from" |cut -d" " -f 4|cut -d":" -f1 &
done
