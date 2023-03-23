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

sudo cp hackWeb.pl /usr/bin/
sudo cp webData.pl /usr/bin/
sudo cp passWeb.pl /usr/bin/
sudo cp web-buster.pl /usr/bin/
sudo cp get_ssl_cert.py /usr/bin/

mkdir /usr/share/webhacks 2>/dev/null
sudo cp -R wordlist /usr/share/webhacks

sudo chmod a+x /usr/bin/hackWeb.pl
sudo chmod a+x /usr/bin/passWeb.pl
sudo chmod a+x /usr/bin/webData.pl
sudo chmod a+x /usr/bin/web-buster.pl
sudo chmod a+x /usr/bin/get_ssl_cert.py

echo -e "$OKGREEN [+] Instalando librerias perl necesarias $RESET" 

sudo apt-get install -y  python3-m2crypto libcrypt-ssleay-perl cmdtest
sudo pip3 install M2Crypto pyopenssl scapy

docker pull wappalyzer/cli


cpan E/ET/ETHER/B-Hooks-OP-Check-0.22.tar.gz
cpan X/XA/XAOC/ExtUtils-Depends-0.405.tar.gz
cpan O/OA/OALDERS/LWP-Protocol-https-6.07.tar.gz

cd webHacks/ 
sudo cpan .

echo -e "$OKRED [+] INSTALACION COMPLETA - (Abre otra consola para que el sistema reconozca los nuevos comandos ) $RESET" 
