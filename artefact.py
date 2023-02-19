from scapy.all import *

def pktHandle(i):
        if i.haslayer("IP"):
            sourceIP = i["IP"].src
            return True
        else:
            sourceIP = i.src
            print(sourceIP)
            print(i)
            print(i.show())


def scTest():
    print("scTest")
    conf.verb = 0 
    pkt = sniff(iface=r'Ethernet', prn=pktHandle)





#Testing

scTest()

