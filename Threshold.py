import json
  
# Opening JSON file
f = open('data.json')
  
# returns JSON object as 
# a dictionary
data = json.load(f)
  
# Iterating through the json
# list
max = 0
for i in data['Records']:
    #print(i['Count'])
    if i['Count'] > max:
        max = i['Count']
print(max)
  
# Closing file
f.close()