#!/usr/bin/env python3

# Import necessary modules
import json
import time
import subprocess
from datetime import date
from scapy.all import *

# Load the previous records from a JSON file
f = open('Record.json')
record = json.load(f)
f.close()
threshold = 1400
# Define a function to track incoming packets
def track(pkt):

    # Set the threshold for attack detection
    

    # Check if the packet has an IP layer
    if pkt.haslayer("IP"):

        # Get the source IP address of the packet
        sourceIP = pkt["IP"].src

        # If the packet was sent from this computer, ignore it
        if sourceIP == get_if_addr(conf.iface):
            pass
        else:
            # Check if the system has any records
            if record['Records']:
                ipfound = False
                # Loop through the previous records to find the source IP address
                for i in record['Records']:
                    if i['IP'] == sourceIP:
                        ipfound = True
                        # If the IP address has not been blocked
                        if i['Blocked'] == False:
                            # Increase the packet count for the IP address
                            i.update({'Count':i['Count']+1})
                            # If more than 1 minute has passed since the last count reset
                            if time.time()-i['startTime'] > 60:
                                # If the packet count is above the threshold, return the IP address for further processing
                                if i['Count'] > threshold :
                                    print(i['IP'])
                                    return(i)
                                # If the packet count is below the threshold, reset the count and start a new timer
                                elif i['Count'] < threshold:
                                    i.update({'Count':1})
                                    i.update({'startTime':time.time()})
                        break
                # If the source IP address is not found in previous records, add a new record for it
                if ipfound == False:
                    data = {
                            'IP': sourceIP,
                            'Count': 1,
                            'startTime': time.time(),
                            'Blocked': False
                        }
                    record['Records'].append(data)
            # If there are no previous records, add a new record for the source IP address
            else:
                data = {
                    'IP': sourceIP,
                    'Count': 1,
                    'startTime': time.time(),
                    'Blocked': False
                }
                record['Records'].append(data)
    else:
        pass
    # Return "Clear" if no IP address is returned for further processing
    return("Clear")

# Define a function to write the updated records to a JSON file
def log(record):
    json_object = json.dumps(record, indent=4)
    with open("Record.json","w") as file:
        file.write(json_object)
    # Reload the updated records from the JSON file
    f = open('Record.json')
    record = json.load(f)
    f.close()

# Define a function to log an incident in a text file
def incidentLog(ip,blocked):
    with open("LOG.txt",'a+') as f:
        # Get the current time and date
        t = time.time()
        currentTime = time.strftime("%H:%M:%S",time.gmtime(t))
        # Format and write the incident log message to the text file
        info = str(date.today())+": "+ip['IP']+" Flagged at "+str(currentTime)+" With "+str(ip['Count'])+' Packets per minute. INVESTIGATING'
        f.write(info+" "+str(blocked)+'\n')

# Define a function to check for volumetric attacks
def volAttackCheck(ip):
    isAttack = False
    # Check if the IP has sent more than a set threshold packets in the last minute
    if ip['Count'] > threshold:
        print(ip['Count'])
        isAttack == True
        # Add the IP to the blacklist using the 'ipset' command
        try:
            subprocess.check_call(['ipset','add','black_list',ip['IP']])
        except:
            pass
        # Log the incident in the 'LOG.txt' file
        incidentLog(ip,blocked=True)
    # Check if the IP is already in the record dictionary
    for i in record['Records']:        
        if ip['IP'] == i['IP']:
            # If the IP is not an attacker, update the count and start time
            if isAttack == False:
                i.update({'Count':1})
                i.update({'startTime':time.time()})
            # If the IP is an attacker, mark it as blocked
            elif isAttack == True:
                i.update({'Blocked':True})
    log(record)


def thresholdLog():
    print("Logging")
    # Load the contents of the JSON file into a dictionary
    with open('Record.json', 'r') as file:
        data = json.load(file)

    # Load the contents of a different JSON file into a dictionary
    with open('data.json', 'r') as file:
        data2 = json.load(file)
    # For each record in the first JSON file, add a new record to the second JSON file
    for record in data['Records']:
        count = record['Count']
        ip = record['IP']
        new = {
                'IP':ip,
                'Count':count
            }
        data2['Records'].append(new)
    # Overwrite the contents of the second JSON file with the updated dictionary
    with open('data.json', 'w') as file:
        json.dump(data2, file,indent=4)
