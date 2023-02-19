# Artefact

Can create dictionary with count
    ip 192.168.0.14
    count = 2
    starttime = 17:20:00
upon packet recieve
check if ip is logged - done
if no log ip, time,count =1 - done
if yes check start time is > 1 minute from current time - done
    if yes reset count and start time - done
    if no add 1 to count and check if count is greater than threshold - done
        if yes add to black list - done
        if no continue - done

need to iterate through entire dictionary before adding to dictionary

Bodge fixes to find better 
- iterate through dict - created blank entry to make it start
- add new entry to dict - made it check entire dict before entering through true/false condition

Random stuff
    Needs scapy and ipset to work
    