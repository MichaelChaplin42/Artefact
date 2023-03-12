#!/usr/bin/env python3

# Import necessary modules
from scapy.all import sniff
import subprocess
import checks
import time

# Define function to exit program
def exit():
    print("EXITING")
    quit()

# Function to run first setup 
def firstSetup():
    print("Running First Setup")
    # Update packages and install necessary packages
    subprocess.check_call(['apt-get','update'])
    subprocess.check_call(['apt-get','upgrade','-y'])
    subprocess.check_call(['pip','install','--pre','scapy[basic]'])
    subprocess.check_call(['apt','install','ipset'])
    # Create IP set if it does not exist and add it to iptables
    try:
        subprocess.check_call(['ipset','create','black_list','hash:ip'])
    except:
        print("IPSET EXISTS")
    try:
        subprocess.check_call(['iptables','-A','INPUT','-m','set','--match-set','black_list','src' ,'-j','DROP'])
    except:
        print("IPTABLES RULE EXISTS")


# Define function to start sniffing traffic
def sniffer():
    print("SNIFFING")
    global run 
    run = time.time() + 36000
    sniff(prn=pkthandle)

# Function to handle each packet
def pkthandle(pkt):
    global logtime
    global logtime2
    sec = int(run-time.time())
    sec1 = sec % 60
    min = sec / 60 
    # Print time remaining before program exits due to time limit Just for testing
    print(int(min), "Minutes and",sec1,"Seconds left")
    # Exit program if time limit is reached
    if sec < 0:
        exit()
    # Logs the information that the system is actively tracking every 60 seconds
    if (time.time()-logtime) >60:
        logtime = time.time()
        checks.log(checks.record)
    # Create a backup log of the current log every 600 seconds that does not get replaced 
    if (time.time()-logtime2) > 600:
        logtime2 = time.time()
        checks.thresholdLog()
    ipcheck = checks.track(pkt)
    # If packet is flagged as a potential attack, log it and check for a volumetric attack
    if ipcheck != "Clear":
        checks.incidentLog(ipcheck,blocked=False)
        checks.volAttackCheck(ipcheck,checks.record)
# Function for testing purposes only
def testing():
    print("TESTING")


# Start loop to prompt user for input and run appropriate functions
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