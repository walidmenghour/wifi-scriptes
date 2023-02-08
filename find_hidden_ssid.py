#!/usr/bin/python3

from scapy.all import *
import sys


hidden_ssid_aps=set()

def PacketHandler(pck):
	if pck.haslayer(Dot11Beacon):
		if not pck.info :
			if pck.addr3 not in hidden_ssid_aps:
				hidden_ssid_aps.add(pck.addr3) 
				print(pck.addr3)

	elif pck.haslayer(Dot11ProbeResp) and ( pck.addr3 in hidden_ssid_aps ):
		print("Hidden SSID UNCOVER : ",pck.info , pck.addr3)
			


sniff(iface=sys.argv[1],count=int(sys.argv[2]),prn=PacketHandler)
