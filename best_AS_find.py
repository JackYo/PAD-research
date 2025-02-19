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
for rule in rule.parse_file("./data/normal_data/modbus_AS_fullfilesupport.txt"):
    print("[%d] %s ; %s ; %s" % (rule.sid, rule.content, rule.offset, rule.depth))
    if ruleset.get(rule.sid) is None:
        ruleset[rule.sid] = list()

    ruleset[rule.sid].append(dict({'content': rule.content, 'offset': rule.offset,'depth': rule.depth}))



abnormalSaveDir = "./output/AS_check/modbus/modbus_AS_check_ab_sig"
susSaveDir = "./output/AS_check/modbus/modbus_AS_check_sus_seq"
bestSaveDir = "./output/AS_check/modbus/modbus_AS_check_best_search"

# f_ab_sav = open(abnormalSaveDir, 'w', encoding='utf-8')
# f_sus_sav = open(susSaveDir, 'w', encoding='utf-8')

# summary = dict()
# summary['ab_ts'] = list()

ruleids = [1000004,1000005,1000006,1000012,1000011,1000000,1000001,1000003]
ruleids.reverse()

for j in range(0,len(ruleids)):
    total_count = 0
    normal_count = 0
    match_count = 0
    abnormal_count = 0
    pcap = ppcap.Reader(filename="./data/test_data/modbus/modbus_test_data_merge.pcap")
    print("Now computing ruleids: {}".format(str(ruleids)))
    for ts, buf in pcap:
        total_count = total_count +1
        if total_count % 1000 == 0:
            print(total_count)
        ts_datetime = datetime.fromtimestamp(ts/1000000000).strftime('%Y-%m-%dT%H:%M:%SZ')
        eth = ethernet.Ethernet(buf)

        if (eth[tcp.TCP] is not None) and (eth[tcp.TCP].body_bytes != b''):
            feature_bytes = eth[tcp.TCP].body_bytes
            #("%d: %s:%s -> %s:%s (body: %s)" % (ts, eth[ip.IP].src_s, eth[udp.UDP].sport, eth[ip.IP].dst_s, eth[udp.UDP].dport, eth[udp.UDP].body_bytes))
            
            out = bytes.hex(feature_bytes)
            
            # print("Now checking...")
            # print("Origin byte string: %s" % out)
            #print(ruleset)
            match = False
            for ruleid in ruleids:

                rule = ruleset[ruleid]
                # print("\t[%s]" % (ruleid))
                
                for sec in rule:
                    refined_content = re.sub(r"['\"','\'','\s','|']",'',sec['content'])
                    # print("\t\t%s ; %s ; %s" % (refined_content, sec['offset'], sec['depth']))                
                    
                    content_len = int(len(refined_content))
                    offset = int(sec['offset'])*2
                    depth = int(sec['depth'])*2
                    lowbound = offset
                    upbound = offset + depth - content_len + 2 # content_len

                    for i in range(lowbound, upbound, 2):
                        checkout = out[ i: i+ content_len]
                        # print("\t\t%s <= checkout" % (checkout))
                        if checkout == refined_content:
                            # print("\t\tSignature match. This packet would be seen as normal.")
                            match_count = match_count +1
                            desc = dict()
                            desc['ts'] = ts
                            desc['matched'] = match
                            desc['payload'] = out
                            desc['Lseq'] = None
                            desc['Rseq'] = None

                            if (not match):
                                normal_count = normal_count +1
                            
                            if out[0:i] != '':
                                rem1 = re.findall('..',out[0:i])
                                # print("\t\t\t rem1 = %s" % rem1)
            
                                desc['Lseq'] = rem1
                                
                                # f_sus_sav.write(desc)
                                #f_sus_sav.write( " # datetime={} [{}] {} matched before? {} ; ts={} ; payload={}\n".format(ts_datetime,ruleid,refined_content,match,ts,out) )
                            if out[i +content_len : len(out)] != '':
                                rem2 = re.findall('..',out[i +content_len : len(out)])
                                # print("\t\t\t rem2 = %s" % rem2)
                                
                                desc['Rseq'] = rem2
                                
                                #f_sus_sav.write(str(rem2))
                                #f_sus_sav.write( " # datetime={} [{}] {} matched before? {} ; ts={} ; payload={}\n".format(ts_datetime,ruleid,refined_content,match,ts,out) )
                            # alert  tcp any any -> 192.168.88.0/24 502  (sid: 1000004; content:"|01 00 00 00 01|";  offset:7; depth:5; )
                            #f_sus_sav.write("{}\n".format(str(desc)))
                            #byteseq[ruleid].append(desc)
                            match = True
                            break
                        # print("\t\tSignature not match.")

            if match == False:
                # print("\t\tAll signatures not match! This packet would be sent to do byte sequence classification.")
                abnormal_count = abnormal_count +1

                # summary['ab_ts'].append(ts)

                #byteseq['outlier'].append(desc)
                # f_ab_sav.write( "alert  tcp any any -> 192.168.88.0/24 502  (sid: 1000004; content:\"{}\";  offset:0; depth:{}; )".format(transfer_to_rule(out), int(len(out)/2) ) )
                # f_ab_sav.write( "\t# Counter packet datetime={} ; ts={} ; payload={}\n".format(ts_datetime,ts,out))

    f_best_search = open(bestSaveDir, 'a', encoding='utf-8')
    f_best_search.write("RuleIDs = {}\n".format(ruleids))
    f_best_search.write("\tnormal_pkt_count = {}\n".format(normal_count))
    f_best_search.write("\tabnormal_pkt_count = {}\n".format(abnormal_count))
    f_best_search.write("\ttest_pkt_total_count = {}\n".format(total_count))
    f_best_search.write("\tMatch ratio = {}\n\n".format(abnormal_count/total_count))

    f_best_search.close()

    ruleids.pop()




            