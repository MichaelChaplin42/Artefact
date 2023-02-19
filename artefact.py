#!/usr/bin/env python3
from scapy.all import *
from netaddr import *
import os
import time
import json
Threshold = 20

info = {"Vectors": [{
    'IP': 0,
    'Count': 0,
    'startTime': 0
}]}
record = {"Records": []}
def firstStart():
    try:
        os.system("ipset creat black_list hash:ip")
    except:
        print("SET EXISTS")
    try:
        os.system("iptables -A INPUT -m set --match-set black_list src -j DROP")
    except:
        print("IPTABLES RULE EXISTS")
#Creates iptables rule and ipset on first start
def ipFound(dict):
    dict.update({'Count':dict['Count']+1})
    #print("COUNT UPDATED")
    diff = time.time() - dict['startTime']
    if diff > 60:
        print
        record["Records"].append(dict)
        dict.update({'Count':1})
        dict.update({'startTime':time.time()})
        
    else:
        if dict['Count'] >= Threshold:
            print("Greater than threshold Blocking")
            #dict.update({'Blocked':True})
            #os.system("ipset add black_list "+dict['IP'])


def pktHandle(i):
        if i.haslayer("IP"):
            sourceIP = i["IP"].src
        else:
            sourceIP = i.src
        print("PACKET DETECTED")
        ipPresent = False
        for i in info["Vectors"]: # iterates through dictionary
            if i['IP']== sourceIP: # if ip is found
                ipPresent = True
                if i['Blocked'] == False:
                    #print("True")
                    ipFound(i)
                    break
            
        if ipPresent == False:   #Below creates an entry into the dictionaryj with the ip time and count if the ip is not found within the dictionary    
            data = {
            'IP': sourceIP,
            'Count': 1,
            'startTime': time.time(),
            'Blocked': False
            }
            info["Vectors"].append(data)
            
        #print(info)




def scTest():
    print("scTest")
    conf.verb = 0 
    pkt = sniff( prn=pktHandle)


print("TEST")


#Testing
def test():
    print("Test")
    f = open('Record.json')
    data = json.load(f)
    for i in data['Records']:
        if i['Count'] > 20:
            print(i)


run = True
while run == True:
    ans = int(input("Press 1 for first setup. Press 2 for start. Press 3 for exit. >"))
    if ans == 1:
        firstStart()
    elif ans == 2:
        scTest()
    elif ans == 3:
        json_object = json.dumps(record, indent=4)
        with open("Record.json","a+") as outfile:
            outfile.write(json_object)
        os.system("ipset del black_list 192.168.129.191")
        exit()
    else:
        test()
