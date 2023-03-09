#!/usr/bin/env python3
from scapy.all import sniff
import subprocess
import checks
import time

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
    global run 
    run = time.time() + 8000
    sniff(prn=pkthandle)

def pkthandle(pkt):
    global logtime
    global logtime2
    sec = int(run-time.time())
    sec1 = sec % 60
    min = sec / 60 
    print(int(min), "Minutes and",sec1,"Seconds left")
    if sec < 0:
        exit()
    if (time.time()-logtime) >60:
        logtime = time.time()
        checks.log(checks.record)
    if (time.time()-logtime2) > 600:
        logtime2 = time.time()
        checks.thresholdLog()
    ipcheck = checks.track(pkt)
    if ipcheck != "Clear":
        checks.incidentLog(ipcheck,blocked=False)
        checks.volAttackCheck(ipcheck,checks.record)

def testing():
    print("TESTING")

run = True
print("AUTOMATED DDOS PROTECTION TOOL")
while run == True:
    logtime = time.time()
    logtime2 = time.time()
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