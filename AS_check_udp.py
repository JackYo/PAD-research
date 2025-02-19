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
from datetime import datetime
import json

def transfer_to_rule(s):
    out_string = ' '.join(a+b for a,b in zip(s[::2], s[1::2]))
    # for j in range(2, len(hex_string),2):
    #     out_string = hex_string[0:j] + ' ' + hex_string[j:len(hex_string)]

    return '|'+out_string+'|'

ruleset = dict()
for rule in rule.parse_file("./data/bacnet_packet_AS_spec.txt"):
    print("[%d] %s ; %s ; %s" % (rule.sid, rule.content, rule.offset, rule.depth))
    if ruleset.get(rule.sid) is None:
        ruleset[rule.sid] = list()

    ruleset[rule.sid].append(dict({'content': rule.content, 'offset': rule.offset,'depth': rule.depth}))


pcap = ppcap.Reader(filename="./data/test_data/bacnet/bacnet_test.pcap")
abnormalSaveDir = "./output/AS_check/bacnet/bacnet_AS_check_ab_sig"
normalSaveDir = "./output/AS_check/bacnet/bacnet_AS_check_normal_subseq"
f_ab_sav = open(abnormalSaveDir, 'w', encoding='utf-8')
f_sus_sav = open(normalSaveDir, 'w', encoding='utf-8')
total_count = len(pcap)
normal_count = 0
match_count = 0
abnormal_count = 0
byteseq = dict()
byteseq['outlier'] = list()

for ts, buf in pcap:
    ts_datetime = datetime.fromtimestamp(ts/1000000000).strftime('%Y-%m-%dT%H:%M:%SZ')
    eth = ethernet.Ethernet(buf)

    if (eth[udp.UDP] is not None) and (eth[udp.UDP].body_bytes != b''):
        feature_bytes = eth[udp.UDP].body_bytes
        #("%d: %s:%s -> %s:%s (body: %s)" % (ts, eth[ip.IP].src_s, eth[udp.UDP].sport, eth[ip.IP].dst_s, eth[udp.UDP].dport, eth[udp.UDP].body_bytes))
        
        out = bytes.hex(feature_bytes)
        
        print("Now checking...")
        print("Origin byte string: %s" % out)
        #print(ruleset)
        match = False
        for ruleid, rule in ruleset.items():
            print("\t[%s]" % (ruleid))
            
            for sec in rule:
                refined_content = re.sub(r"['\"','\'','\s','|']",'',sec['content'])
                print("\t\t%s ; %s ; %s" % (refined_content, sec['offset'], sec['depth']))                
                
                content_len = int(len(refined_content))
                offset = int(sec['offset'])*2
                depth = int(sec['depth'])*2
                lowbound = offset
                upbound = offset + depth - content_len + 2 # content_len

                for i in range(lowbound, upbound, 2):
                    checkout = out[ i: i+ content_len]
                    print("\t\t%s <= checkout" % (checkout))
                    if checkout == refined_content:
                        print("\t\tSignature match. This packet would be seen as normal.")
                        match_count = match_count +1
                        if (not match):
                            normal_count = normal_count +1
                        
                        if out[0:i] != '':
                            rem1 = re.findall('..',out[0:i])
                            print("\t\t\t rem1 = %s" % rem1)

                            desc = " # L {} [{}] {} matched before? {} ; ts={} ; payload={}\n".format(ts_datetime,ruleid,refined_content,match,ts,out)
                            byteseq[ruleid].append([rem1,desc])

                            #f_sus_sav.write(str(rem1))
                            #f_sus_sav.write( " # ts={} [{}] {} matched before? {}\n".format(ts_datetime,ruleid,refined_content,match) )
                        if out[i +content_len : len(out)] != '':
                            rem2 = re.findall('..',out[i +content_len : len(out)])
                            print("\t\t\t rem2 = %s" % rem2)

                            desc = " # R {} [{}] {} matched before? {} ; ts={} ; payload={}\n".format(ts_datetime,ruleid,refined_content,match,ts,out)
                            byteseq[ruleid].append([rem2,desc])

                            #f_sus_sav.write(str(rem2))
                            #f_sus_sav.write( " # ts={} [{}] {} matched before? {}\n".format(ts_datetime,ruleid,refined_content,match) )
                        # alert  tcp any any -> 192.168.88.0/24 502  (sid: 1000004; content:"|01 00 00 00 01|";  offset:7; depth:5; )
                        match = True
                    print("\t\tSignature not match.")

        if match == False:
            print("\t\tAll signatures not match! This packet would be sent to do byte sequence classification.")
            abnormal_count = abnormal_count +1
            f_ab_sav.write( "alert  udp any any -> any 47808  (sid:{} ; content:\"{}\";  offset:0; depth:{}; )".format( 1000000 + abnormal_count, transfer_to_rule(out), int(len(out)/2) ) )
            f_ab_sav.write( "\tCounter packet ts={}\n".format(ts_datetime))

f_sus_sav.write(json.dumps(byteseq))
f_sus_sav.write("\n# normal_count = {}\n".format(normal_count) )
f_sus_sav.write("# match_count = {}\n".format(match_count) )
f_sus_sav.write("# total_packet = {}".format(total_count) )

f_ab_sav.write("\n#abnormal_count = {}\n".format(abnormal_count) )
f_ab_sav.write("# total_packet = {}".format(total_count) )

f_sus_sav.close()
f_ab_sav.close()

            