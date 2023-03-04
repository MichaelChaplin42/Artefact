#!/usr/bin/env python3
import json
import time
f = open('Record.json')
record = json.load(f)
f.close()
def track(pkt):
    if pkt.haslayer("IP"):
        sourceIP = pkt["IP"].src
        if record['Records']:
            for i in record['Records']:
                if i['IP'] == sourceIP:
                    if i['Blocked'] == False:
                        #print(i['Count'])
                        i.update({'Count':i['Count']+1})
                else:
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

def log(record):
    json_object = json.dumps(record, indent=4)
    with open("Record.json","w") as file:
        file.write(json_object)
    f = open('Record.json')
    record = json.load(f)
    f.close()