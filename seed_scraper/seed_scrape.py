import subprocess
import time
import sys
import json
import requests
import os
#import socket
from Initializer import Initializer, WebCheck, Login
from selenium import webdriver
from scapy.all import *
from scapy.layers.http import *

def get_seed():
    os.chdir(sys.argv[2])
    image_location = "/home/ubuntu/FYP/extracted_image/813c23b285d234785f1c4ce19c76bf76d148e06977b6f016f6590e59d6d17f65/D7000v2_FW_V1.0.0.52_1.0.1/debug"
    #image_location = "/home/ubuntu/FYP/extracted_image/2fda6a93fda4a3468688dcfe57980e118aebe9f6016e2e83c8ccf4d47e7123af/N150_N300_FW_V1.1.0.31_1.0.1/debug"
    #image_location = sys.argv[1] #uncomment for full run with tar_loop and comment out above image_location
    config_location = image_location[:-5] + "config.json"

    with open(config_location, 'r') as config:
        config_json = json.load(config)

    #Initialize()
    brand = config_json['brand']
    target = config_json['targetip']
    port = config_json['targetport']
    user = config_json['loginuser']
    passwd = config_json['loginpassword']
    creds_dump_path = "/home/ubuntu/FYP/NTU-FYP/seed_scraper/creds.json"
    time.sleep(7)
    full_run = Initializer.full_run(brand,target,port,user,passwd,creds_dump_path)

def extract_post():
    http_pcap = PcapReader('seed.pcap')
    num_seed = 0
    for pkt in http_pcap:
        if HTTP in pkt:
            if HTTPRequest in pkt:
                        if pkt[HTTPRequest].Method == b'POST':
                            post_req = pkt[HTTPRequest]
                            if "Authorization" in post_req.fields and pkt.haslayer(Raw):
                                raw_seed = raw(pkt)
                                count = 0
                                while (count < len(raw_seed)):
                                    count += 1
                                    if(raw_seed[count] == 80  and raw_seed[count+1] == 79 and raw_seed[count+2] == 83 and raw_seed[count+3] == 84):
                                        raw_seed = raw_seed[count:]
                                        break
                                if(count < len(raw_seed)):
                                    num_seed += 1
                                    post_seed = open("seed%s" % num_seed,"wb")
                                    post_seed.write(raw_seed)
                                    post_seed.close()
                                
                                if(num_seed >=5):
                                    print("5 seeds written")
                                    return
    print("<5 seeds written")
    return

get_seed()
time.sleep(5)
extract_post()
