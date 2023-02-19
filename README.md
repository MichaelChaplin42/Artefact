# Artefact

Can create dictionary with count
    ip 192.168.0.14
    count = 2
    starttime = 17:20:00
upon packet recieve
check if ip is logged
if no log ip, time,count =1
if yes check start time is > 1 minute from current time
    if yes reset count and start time
    if no add 1 to count and check if count is greater than threshold
        if yes add to black list
        if no continue