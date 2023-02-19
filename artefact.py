#!/usr/bin/env python3
from scapy.all import *

def pktHandle(i):
        if i.haslayer("IP"):
            sourceIP = i["IP"].src
        else:
            sourceIP = i.src
        if sourceIP == "172.217.169.46":
            print("SENT PACKET")
        else:
            print("Recieved Packet")
        print(sourceIP)



def scTest():
    print("scTest")
    conf.verb = 0 
    pkt = sniff(iface=r'enp0s3', prn=pktHandle)


print("TEST")


#Testing

scTest()

