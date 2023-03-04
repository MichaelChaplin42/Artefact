#!/usr/bin/env python3
from scapy.all import sniff
import subprocess
import checks

def exit():
    print("EXITING")
    quit()

def firstSetup():
    print("Running First Setup")
    subprocess.check_call(['apt-get','update'])
    subprocess.check_call(['apt-get','upgrade','-y'])
    subprocess.check_call(['pip','install','--pre','scapy[basic]'])
    subprocess.check_call(['apt','install','ipset'])
    try:
        subprocess.check_call(['ipset','create','black_list','hash:ip'])
    except:
        print("IPSET EXISTS")
    try:
        subprocess.check_call(['iptables','-A','INPUT','-m','set','--match-set','black_list','src' ,'-j','DROP'])
    except:
        print("IPTABLES RULE EXISTS")

def sniffer():
    print("SNIFFING")
    sniff(prn=checks.light)

def testing():
    print("TESTING")

run = True
print("AUTOMATED DDOS PROTECTION TOOL")
while run == True:
    print("Enter EXIT to EXIT")
    print("Enter 1 for first time set up. This will create the IP table rule and the IPSET blacklist")
    print("Enter 2 to run.")
    print("Enter 3 to run testing.")
    ans = str(input(">"))
    if ans == "EXIT":
        exit()
    if ans == "1":
        firstSetup()
    if ans == "2":
        sniffer()
    if ans == "3":
        testing()