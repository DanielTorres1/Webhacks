#!/usr/bin/python3
from socket import socket
import ssl
import M2Crypto
import OpenSSL
import sys
from logging import getLogger, ERROR # Import Logging Things
getLogger("scapy.runtime").setLevel(ERROR) # Get Rid if IPv6 Warning
from scapy.all import * # The One and Only Scapy


SYNACK = 0x12 # Set flag values for later reference

	

ip=sys.argv[1]
port=int(sys.argv[2])
pktflags=0;
#print ssl.OPENSSL_VERSION
 

# Sync scan
#srcport = RandShort() # Generate Port Number
#conf.verb = 0 # Hide output
#SYNACKpkt = sr1(IP(dst = ip)/TCP(sport = srcport, dport = port, flags = "S"),timeout=5) 
#try:
	#pktflags = SYNACKpkt.getlayer(TCP).flags # Extract flags of recived packet
#except:
#	print ""
	
#if pktflags == SYNACK: # Cross reference Flags
	# M2Crypto	
cert = ssl.get_server_certificate((ip, port))
x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
print (x509.get_subject().get_components())
