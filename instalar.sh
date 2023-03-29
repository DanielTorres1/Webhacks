#!/bin/bash
OKBLUE='\033[94m'
OKRED='\033[91m'
OKGREEN='\033[92m'
RESET='\e[0m'


function print_ascii_art {
cat << "EOF"
   
 __          __  _     _    _            _        
 \ \        / / | |   | |  | |          | |       
  \ \  /\  / /__| |__ | |__| | __ _  ___| | _____ 
   \ \/  \/ / _ \ '_ \|  __  |/ _` |/ __| |/ / __|
    \  /\  /  __/ |_) | |  | | (_| | (__|   <\__ \
     \/  \/ \___|_.__/|_|  |_|\__,_|\___|_|\_\___/
                                                  

					daniel.torres@owasp.org
					https://github.com/DanielTorres1

EOF
}


print_ascii_art

echo -e "$OKBLUE [+] Instalando WEB hacks $RESET" 

cp hackWeb.pl /usr/bin/
cp webData.pl /usr/bin/
cp passWeb.pl /usr/bin/
cp web-buster.pl /usr/bin/
cp get_ssl_cert.py /usr/bin/

mkdir /usr/share/webhacks 2>/dev/null
cp -R wordlist /usr/share/webhacks

chmod a+x /usr/bin/hackWeb.pl
chmod a+x /usr/bin/passWeb.pl
chmod a+x /usr/bin/webData.pl
chmod a+x /usr/bin/web-buster.pl
chmod a+x /usr/bin/get_ssl_cert.py

echo -e "$OKGREEN [+] Instalando librerias perl necesarias $RESET" 

apt-get install -y  python3-m2crypto libcrypt-ssleay-perl
pip3 install M2Crypto pyopenssl scapy --break-system-packages

#echo -e "$OKGREEN [+] Instalando wappalyzer $RESET" 
#npm i -g wappalyzer


cpan E/ET/ETHER/B-Hooks-OP-Check-0.22.tar.gz
cpan X/XA/XAOC/ExtUtils-Depends-0.405.tar.gz
cpan O/OA/OALDERS/LWP-Protocol-https-6.10.tar.gz
#cpan N/NA/NANIS/Crypt-SSLeay-0.72.tar.gz
cd webHacks/ 
cpan .

echo -e "$OKRED [+] INSTALACION COMPLETA - (Abre otra consola para que el sistema reconozca los nuevos comandos ) $RESET" 
