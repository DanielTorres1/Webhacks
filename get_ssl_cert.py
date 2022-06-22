#!/usr/bin/python3
from socket import socket
import ssl
import M2Crypto
import OpenSSL
import sys
from logging import getLogger, ERROR # Import Logging Things
getLogger("scapy.runtime").setLevel(ERROR) # Get Rid if IPv6 Warning
from scapy.all import * # The One and Only Scapy

from cryptography import x509
from cryptography.hazmat.backends import default_backend
import re



SYNACK = 0x12 # Set flag values for later reference


ip=sys.argv[1]
port=int(sys.argv[2])
pktflags=0;
#print ssl.OPENSSL_VERSION
 
certificate_data_json = {} 

certificate: bytes = ssl.get_server_certificate((ip, port)).encode('utf-8')
loaded_cert = x509.load_pem_x509_certificate(certificate, default_backend())

subject = loaded_cert.subject
for item in subject:
	name_str = str(item.oid)
	nameRegex = re.compile(r'name=(.*)\)')
	mo = nameRegex.search(name_str)
	name=mo.group(1) 
	certificate_data_json[name] = item.value


try:
	san = loaded_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
	dns_names = san.value.get_values_for_type(x509.DNSName)
	i=0
	for dns in dns_names:
		certificate_data_json[f'subdomain{i}'] = dns
		i=i+1
except:
  print("")


print(certificate_data_json)


