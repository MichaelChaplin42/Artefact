#!/usr/bin/env python3
from scapy.all import *
from netaddr import *
import os
import time
def firstStart():
    try:
        os.system("ipset creat black_list hash:ip")
    except:
        print("SET EXISTS")
    try:
        os.system("iptables -A INPUT -m set --match-set black_list src -j DROP")
    except:
        print("IPTABLES RULE EXISTS")
def pktHandle(i):
        if i.haslayer("IP"):
            sourceIP = i["IP"].src
        else:
            sourceIP = i.src
        #if sourceIP == "172.217.169.46":
            #print("SENT PACKET")
        #else:
            #print("Recieved Packet")
        if sourceIP == "192.168.129.191":
            print("PING DETECTED")
            os.system("ipset add black_list "+sourceIP)
            time.sleep(5)
            os.system("ipset del black_list "+sourceIP)
            exit()
        print(sourceIP)



def scTest():
    print("scTest")
    conf.verb = 0 
    pkt = sniff(iface=r'enp0s3', prn=pktHandle)


print("TEST")


#Testing


run = True
while run == True:
    ans = int(input("Press 1 for first setup. Press 2 for start. Press 3 for exit. >"))
    if ans == 1:
        firstStart()
    elif ans == 2:
        scTest()
    else:
        exit()