#!/usr/bin/python3 

import sys
from scapy.all import *


def packet_handler(pck):

#	if(pck.haslayer(Dot11)):
	print(pck.summary())
#	else : 
#		print("IT IS NOT DOT 802.11 packet")
	return 

sniff(iface=sys.argv[1],count=int(sys.argv[2]),prn=packet_handler)

