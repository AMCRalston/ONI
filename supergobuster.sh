#!/bin/bash
set -eu

URL=$1

echo "super go bustering for super brute: $URL"

gobuster -u $URL -l -k -s 200,204,301,302,307,403 -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt
gobuster -u $URL -l -k -s 200,204,301,302,307,403 -w /usr/share/dirb/wordlists/small.txt
gobuster -u $URL -l -k -s 200,204,301,302,307,403 -w /opt/SecLists/Discovery/Web-Content/tomcat.txt
gobuster -u $URL -l -k -s 200,204,301,302,307,403 -w /opt/SecLists/Discovery/Web-Content/nginx.txt
gobuster -u $URL -l -k -s 200,204,301,302,307,403 -w /opt/SecLists/Discovery/Web-Content/apache.txt
gobuster -u $URL -l -k -s 200,204,301,302,307,403 -w /opt/RobotsDisallowed/Top1000-RobotsDisallowed.txt
gobuster -u $URL -l -k -s 200,204,301,302,307,403 -w /opt/SecLists/Discovery/Web-Content/ApacheTomcat.fuzz.txt
gobuster -u $URL -l -k -s 200,204,301,302,307,403 -w /usr/share/dirb/wordlists/vulns/sharepoint.txt
gobuster -u $URL -l -k -s 200,204,301,302,307,403 -w /opt/SecLists/Discovery/Web-Content/iis.txt
gobuster -u $URL -l -k -s 200,204,301,302,307,403 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
gobuster -u $URL -l -k -s 200,204,301,302,307,403 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e -x txt
gobuster -u $URL -l -k -s 200,204,301,302,307,403 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e -x php 
gobuster -u $URL -l -k -s 200,204,301,302,307,403 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e -x doc 
gobuster -u $URL -l -k -s 200,204,301,302,307,403 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e -x docx
