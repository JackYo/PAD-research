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

sourceFilename = "./data/normal_data/4SICS-Modbus.pcap"
saveFilename = "./data/4SICS_modbus_filter.pcap"

PROTOCOLS = [tcp.TCP, udp.UDP]

def packet_filter(sourceFilename, saveFilename, protocol=0):
    print("packet filtering...")

    his_buf = list()
    total_cnt = 0
    exc_cnt = 0
    check_value = 0

    
    pcap = ppcap.Reader(filename=sourceFilename)
    for ts, buf in pcap:

        total_cnt += 1
        if total_cnt % 1000 == 0:
            print(total_cnt)
        
        eth = ethernet.Ethernet(buf)

        if (eth[PROTOCOLS[protocol]] is not None) and (eth[PROTOCOLS[protocol]].body_bytes != b''):
            feature_bytes = eth[PROTOCOLS[protocol]].body_bytes

            # print(feature_bytes)
            s = bytes.hex(feature_bytes) 
            # print(s)
            byte_seq = ' '.join(a+b for a,b in zip(s[::2], s[1::2]))
            # print(byte_seq)
            byte_seq_int = [int(i,16) for i in byte_seq.split()]
            # print(byte_seq_int)
            check_value = byte_seq_int[7] & 0x80
            # print(check_value)
            next_src_ip = eth[ip.IP].src_s
            next_src_port = eth[tcp.TCP].sport

            if check_value == 128:
                for index, buf in reversed(list(enumerate(his_buf))):

                    his_eth = ethernet.Ethernet(buf)
                    his_dst_ip = his_eth[ip.IP].dst_s
                    his_dst_port = his_eth[tcp.TCP].dport
                    if (his_dst_ip == next_src_ip) and (his_dst_port == next_src_port):
                        pop_index = index
                        his_buf.pop(pop_index)
                        break
                
                
            else:
                his_buf.append(buf)

    pcap_out = ppcap.Writer(filename=saveFilename)
    for buf in his_buf:
        pcap_out.write(buf)
     
    print("%s packets kept.\n==============" % (exc_cnt))

    pcap.close()
    pcap_out.close()

packet_filter(sourceFilename,saveFilename)

            