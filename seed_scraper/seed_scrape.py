import subprocess
import time
import sys
import json
import requests
#import socket
from Initializer import Initializer, WebCheck, Login
from selenium import webdriver


image_location = "/home/ubuntu/FYP/extracted_image/813c23b285d234785f1c4ce19c76bf76d148e06977b6f016f6590e59d6d17f65/D7000v2_FW_V1.0.0.52_1.0.1/debug"
#image_location = sys.argv[1]
config_location = image_location[:-5] + "config.json"
print("in python")

#subprocess.Popen(['bash', 'docker_compose.sh',image_location]) #run script to docker compose with image location
#time.sleep(15) #sleep to wait for docker compose to setup
print(image_location)
print(config_location)
with open(config_location, 'r') as config:
    config_json = json.load(config)

print(config_json)

#Initialize()
brand = config_json['brand']
target = config_json['targetip']
port = config_json['targetport']
user = config_json['loginuser']
passwd = config_json['loginpassword']
creds_dump_path = "/home/ubuntu/FYP/NTU-FYP/seed_scraper/creds.json"
full_run = Initializer.full_run(brand,target,port,user,passwd,creds_dump_path)



#s = socket.socket()
#s.connect((config_json['targetip'],int(config_json['targetport'])))

'''session = requests.Session()
initializer = Initializer(brand,target,port,user,passwd)
firmware_url = initializer.url
print("\n\nfirmware_url",firmware_url)
print("\n\n")
Login.login(session,brand,initializer.url,Login.check_login_type(initializer.url,brand),user,passwd)

#get_message = "GET / HTTP1.1\r\n\r\n"
#r = session.get("https://HTTP/1.1")
print("\nreply from firmware: \n")
#print(r.text)
print()

print("after sleep")'''


