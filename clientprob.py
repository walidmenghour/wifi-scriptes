#!/usr/bin/python3 

from scapy.all import *
import sys

clientprobs=set()

def PacketHandler(pck):
	if pck.haslayer(Dot11ProbeReq):
		if len(pck.info)> 0 :
			testcase = pck.addr2 + ' --- ' + pck.info
			if testcase not in clientprobs :
				clientprobs.add(testcase)
				print(testcase)


sniff(iface=sys.argv[1],count=int(sys.argv[2]),prn=PacketHandler)
