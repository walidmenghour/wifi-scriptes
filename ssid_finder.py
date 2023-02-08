#!/usr/bin/python3

from scapy.all import *
import sys 


ssids=set()
def handlerssid(pck):
	if(pck.haslayer(Dot11Beacon)):
		if pck.info not in ssids:
			ssids.add(pck.info)
			print(len(ssids),pck.addr2,pck.info)
 



sniff(iface=sys.argv[1],count=int(sys.argv[2]),prn=handlerssid)
