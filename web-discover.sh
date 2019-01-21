#!/bin/bash

THREADS="30"
OKBLUE='\033[94m'
OKRED='\033[91m'
OKGREEN='\033[92m'
OKORANGE='\033[93m'
RESET='\e[0m'

while getopts ":d:p:a:" OPTIONS
do
            case $OPTIONS in
            d)     DOMAIN=$OPTARG;;
            p)     PORT=$OPTARG;;
            a)     MYPATH=$OPTARG;;
            ?)     printf "Opcion Invalida: -$OPTARG\n" $0
                          exit 2;;
           esac
done

MYPATH=${MYPATH:=NULL}
PORT=${PORT:=NULL}
DOMAIN=${DOMAIN:=NULL}

##################
#  ~~~ Menu ~~~  #
##################

if [ $DOMAIN = NULL ] ; then

echo " USO: web-discover.sh -d [dominio] -p [port] -a MYPATH"
echo ""
exit
fi
######################

mkdir web-discover 
cd web-discover 

echo "Testing $DOMAIN$MYPATH "

echo -e "$OKBLUE [+] Lanzando whatweb ... $RESET"
whatweb $DOMAIN$MYPATH > whatweb.txt
echo ""

echo -e "$OKBLUE [+] Clonando el sitio web... $RESET"  
wget -m -k -U "Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0" -T 5 -K -E  http://$DOMAIN$MYPATH 
echo ""

echo -e "$OKBLUE [+] Lanzando wig ... $RESET"  
wig -a -v $DOMAIN > wig.txt
echo ""

echo -e "$OKBLUE [+] Lanzando wafw00f ... $RESET"  
wafw00f $DOMAIN > wafw00f.txt
echo ""

echo -e "$OKBLUE [+] Lanzando lbd ... $RESET"  
lbd $DOMAIN  > loadbalancer.
echo ""

echo -e "$OKBLUE [+] Lanzando web-buster ... $RESET"  
web-buster.pl -s $DOMAIN  -p $PORT -a $MYPATH  -t 25 -m completo > web-buster.txt
echo ""

find . -type f -iname '*.pdf' -exec cp {} ../../../coop-sanjoaquin.com/archivos \;

cd ../../../coop-sanjoaquin.com/archivos
for f in *; do mv "$f" `echo $f | tr '%20' '-'`; done











