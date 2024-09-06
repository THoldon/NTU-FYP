import subprocess
import time
import sys
import json
import socket

image_location = sys.argv[1]
config_location = image_location[:-5] + "config.json"
print("in python")

#subprocess.Popen(['bash', 'docker_compose.sh',image_location]) #run script to docker compose with image location
time.sleep(15) #sleep to wait for docker compose to setup
print(image_location)
print(config_location)
with open(config_location, 'r') as config:
    config_json = json.load(config)

print(config_json)
s = socket.socket()
s.connect((config_json['targetip'],int(config_json['targetport'])))
get_message = "GET / HTTP1.1\r\n\r\n"
s.sendall(get_message.encode())
val = s.recv(10000)

print(val)

print("after sleep")


