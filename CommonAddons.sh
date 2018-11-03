#!/bin/bash
apt-get -y install build-essential cgps cifs-utils cmake giskismet gpsd gpsd-clients kismet libpcap-dev libpq-dev libsqlite3-dev libssl-dev lsb-core mingw-w64 putty-tools smbclient sparta tree xrdp cifs-utils crackmapexec hostapd-WPE shellter
gem install gitrob pg ruby-nmap net-http-persistent mechanize text-table
cd /opt/
git clone https://github.com/lgandx/Responder.git
git clone https://github.com/0xsauby/yasuo.git
git clone https://github.com/danielmiessler/SecLists.git
git clone https://github.com/darryllane/Bluto.git
git clone https://github.com/Veil-Framework/Veil.git
git clone https://github.com/vysec/SprayingToolkit.git
git clone https://github.com/SecureAuthCorp/impacket.gi
git clone https://github.com/trustedsec/unicorn.git
git clone https://github.com/Screetsec/TheFatRat.git
git clone https://github.com/epinna/tplmap.git
git clone https://github.com/fuzzdb-project/fuzzdb.git
git clone https://github.com/GDSSecurity/Windows-Exploit-Suggester.git
git clone https://github.com/lanjelot/patator.git
git clone https://github.com/lanmaster53/NotaSCA.git
git clone https://github.com/Mebus/cupp.git
git clone https://github.com/ngalongc/AutoLocalPrivilegeEscalation.git
git clone https://github.com/orf/xcat.git
git clone https://github.com/pentestmonkey/unix-privesc-check.git
git clone https://github.com/pentestmonkey/windows-privesc-check.git
git clone https://github.com/PenturaLabs/Linux_Exploit_Suggester
git clone https://github.com/rebootuser/LinEnum.git
git clone https://github.com/TheRook/subbrute.git
git clone https://github.com/PowerShellMafia/PowerSploit.git
git clone https://github.com/D35m0nd142/LFISuite.git
git clone https://github.com/EmpireProject/Empire.git
/opt/Empire/setup/install.sh
pip install argparse
pip install blessings
pip install daemon
pip install git
pip install impacket
pip install pysmb
pip install requests
pip install urlparse
pip install -U websocket
pip install xlrd
pip install snallygaster
