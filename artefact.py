#!/usr/bin/env python3
from scapy.all import *
from netaddr import *
import os
import time
import json
Threshold = 52

info = {"Vectors": [{
    'IP': 0,
    'Count': 0,
    'startTime': 0
}]}
l = open('Record.json')
record = json.load(l)
l.close
#Creates iptables rule and ipset on first start
def ipFound(dict):
    dict.update({'Count':dict['Count']+1})
    #print("COUNT UPDATED")
    diff = time.time() - dict['startTime']
    if diff > 60:
        record["Records"].append(dict)
        dict.update({'Count':1})
        dict.update({'startTime':time.time()})
        
    else:
        if dict['Count'] >= Threshold:
            print("Greater than threshold Blocking")
            t = dict['startTime']
            t = t.strftime("%H:%M:%S")
            dict.update({'startTime':t})
            #dict.update({"Blocked":True})
            #os.system("ipset add black_list "+dict['IP'])


def pktHandle(i):
        now = datetime.now()
        current_time = now.strftime("%H:%M:%S")
        if current_time >= "17:00:00":
            with open('Record.json','w') as file:
                json.dump(record,file,indent=4)
            exit()
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
    with open("Record.json","r") as file:
        data = json.load(file)
        for i in data["Records"]:
            if i['Count'] > 40:
                print(i)


run = True
while run == True:
    ans = int(input("Press 1 for first setup. Press 2 for start. Press 3 for exit. Press 0 for Testing >"))
    if ans == 1:
        print("T")
        
    elif ans == 2:
        scTest()
    elif ans == 3:
        json_object = json.dumps(record, indent=4)
        with open("Record.json","w") as outfile:
            outfile.seek(0)
            outfile.write(json_object)
        os.system("ipset del black_list 192.168.129.191")
        exit()
    elif ans == 0:
        test()
