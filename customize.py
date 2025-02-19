from idstools import rule
import sys
from pypacker import ppcap
from pypacker.layer12 import ethernet
from pypacker.layer3 import ip
from pypacker.layer4 import tcp
from pypacker.layer4 import udp
import numpy as np
import base64
import re
import os
import random
from datetime import datetime

def packet_generation(sourceFilename, saveFilename, saveFilename2, maxi, duration, sampleRate, sliceRate=0.8, repeat=5):
    print("packet_generation...")
    random.seed(datetime.now())

    pcap_out = ppcap.Writer(filename=saveFilename)
    pcap_out2 = ppcap.Writer(filename=saveFilename2)
    sliceNum = int(duration* sliceRate)
    cnt = 0
    total_cnt =0
    train_cnt = 0
    test_cnt = 0
    fin = False
    # vari_port = 101
    while fin != True:
        cnt = 0
        pcap = ppcap.Reader(filename=sourceFilename)
        for ts, buf in pcap:
            r = random.random()
            if r <= sampleRate:
                # print("random = %s" % r)
                if total_cnt >= maxi:
                    fin = True
                    break
                elif (cnt < sliceNum):
                    train_cnt += 1
                    
                    # eth = ethernet.Ethernet(buf)
                    # eth[ip.IP].src_s = "192.168.1.1"
                    # # eth[tcp.TCP].sport = vari_port
                    # # vari_port = vari_port +1
                    # eth[ip.IP].dst_s = "192.168.1.2"
                    # eth[tcp.TCP].dport = 502
                    for i in range(0,repeat):
                        # pcap_out.write(eth.bin())
                        pcap_out.write(buf)
                elif (cnt >= sliceNum):
                    test_cnt +=1
                    
                    # eth = ethernet.Ethernet(buf)
                    for i in range(0,repeat):
                        # pcap_out.write(eth.bin())
                        pcap_out2.write(buf)
                else:
                    break
                cnt = cnt +1
                total_cnt = total_cnt +1
    
    print("\ttrain_cnt", str(train_cnt))
    print("\ttest_cnt", str(test_cnt))
    print("%s packets finished.\n==============" % (maxi*repeat))

    pcap.close()
    pcap_out.close()
    pcap_out2.close()


            