#!/usr/bin/python
from socket import socket
import ssl
import M2Crypto
import OpenSSL
import sys

ip=sys.argv[1]
port=sys.argv[2]

#print ssl.OPENSSL_VERSION
 
# M2Crypto
cert = ssl.get_server_certificate((ip, port))
x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
print x509.get_subject().get_components()
