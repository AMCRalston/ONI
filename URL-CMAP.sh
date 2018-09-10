#!/bin/bash
logger "starting URL-Content Mapping"
# UCM Variables

RIP=$1 # remote target IP recieved from command line arg 1
OutputPath="/tmp"

echo "Attempting URL Enumeration" 

if [[ "$RIP" -le 0 ]]; then 
  CommandLineArgErrMsg+="\n  ERROR: ARG1 - File Size must be >0\n"
fi

curl --ssl -k $RIP -s -L | grep "title\|href" | sed -e 's/^[[:space:]]*//'
curl --ssl -k $RIP -s -L | html2text -width '99' | uniq
curl --ssl -k $RIP/README.md
curl --ssl -k $RIP/robots.txt -s | html2text
