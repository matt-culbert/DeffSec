import json
import requests
import hashlib
import time
import os
import sys 

key = ''

with open('apikey.key') as APIKey:
    for line in APIKey:
        key += line 

i = 0

choice = input("Submit hashes from files in a directory, enter directory in format C:/place/directory/here >   ")

api_url = 'https://www.virustotal.com/vtapi/v2/file/report'
for root, dirs,files in os.walk(choice, topdown=True):
    for name in files:
        
        FileName = (os.path.join(root, name)) # get the file 

        hasher = hashlib.md5() # initialize the hasher we want to use 
        with open(str(FileName), 'rb') as afile:
            buf = afile.read()
            hasher.update(buf)
        hashed = hasher.hexdigest() # hashed file 
        
        params = dict(apikey=key, resource=hashed) # load params for API call 

        response = requests.get(api_url, params=params) # send it up 

        if response.status_code == 200:
           result=response.json()
           print(json.dumps(result, sort_keys=False, indent=4))
           
        i+=1
        if i > 3: # counts our current requests to stay under the rate limit 
            print("Hit rate limit")
            time.sleep(60)
            i = 0
            
