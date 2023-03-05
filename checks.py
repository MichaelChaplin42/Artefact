#!/usr/bin/env python3
import json
import time
import subprocess
from datetime import date
f = open('Record.json')
record = json.load(f)
f.close()
def track(pkt):
    threshold = 200
    if pkt.haslayer("IP"):
        sourceIP = pkt["IP"].src
        if sourceIP == "192.168.139.110":
            pass
        else:
            if record['Records']:
                ipfound = False
                for i in record['Records']:
                    if i['IP'] == sourceIP:
                        ipfound = True
                        if i['Blocked'] == False:
                            i.update({'Count':i['Count']+1})
                            if time.time()-i['startTime'] > 60:
                                if i['Count'] > threshold :
                                    return(i)
                                elif i['Count'] < threshold:
                                    i.update({'Count':1})
                                    i.update({'startTime':time.time()})
                        break
                if ipfound == False:
                    data = {
                            'IP': sourceIP,
                            'Count': 1,
                            'startTime': time.time(),
                            'Blocked': False
                        }
                    record['Records'].append(data)
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
    return("Clear")

def log(record):
    json_object = json.dumps(record, indent=4)
    with open("Record.json","w") as file:
        file.write(json_object)
    f = open('Record.json')
    record = json.load(f)
    f.close()

def incidentLog(ip,blocked):
    with open("LOG.txt",'a+') as f:
        t = time.time()
        currentTime = time.strftime("%H:%M:%S",time.gmtime(t))
        info = str(date.today())+": "+ip['IP']+" Flagged at "+str(currentTime)+" With "+str(ip['Count'])+' Packets per minute. INVESTIGATING'
        f.write(info+" "+str(blocked)+'\n')

def volAttackCheck(ip,record):
    isAttack = False
    if ip['Count'] > 100:
        isAttack == True
        subprocess.check_call(['ipset','add','black_list',ip['IP']])
        incidentLog(ip,blocked=True)
    for i in record['Records']:        
        if ip['IP'] == i['IP']:
            if isAttack == False:
                i.update({'Count':1})
                i.update({'startTime':time.time()})
            elif isAttack == True:
                i.update({'Blocked':True})
