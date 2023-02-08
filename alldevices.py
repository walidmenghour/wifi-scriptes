#!/usr/bin/python3 
### run the command : sudo airodump-ng wlan0 ### to generate all the devices :)
### sudo ./alldevices.py wlan0 1000


import sys
from scapy.all import *

devices=set()
def packet_handler(pck):
	if(pck.haslayer(Dot11)):
		dot11_layer=pck.getlayer(Dot11)
		if dot11_layer.addr2 and dot11_layer.addr2 not in devices:
			devices.add(dot11_layer.addr2)
			print(len(devices),dot11_layer.addr2)

sniff(iface=sys.argv[1],count=int(sys.argv[2]),prn=packet_handler)

