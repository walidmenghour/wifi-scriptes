#!/usr/bin/python3 
### run the command : sudo airodump-ng wlan0 ### to generate all the devices :)
### sudo ./alldevices.py wlan0 1000


import sys
from scapy.all import *

devices=set()
def packet_handler(pck):
	if(pck.haslayer(Dot11)):
		if pck.addr2 and pck.addr2 not in devices:
			devices.add(pck.addr2)
			print(len(devices),pck.addr2)

sniff(iface=sys.argv[1],count=int(sys.argv[2]),prn=packet_handler)

