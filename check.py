from hier_cluster import distance

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
from customize import packet_generation
from FP import FP_generation

PROTOCOLS = [tcp.TCP, udp.UDP]

def total_check(pcapFilename, summarySaveDir, FPSaveDir, clusterCenSaveDir, clusterBound, debug = False, protocol = 0): # signatureDir

    print("Runing Final check...[" + pcapFilename + "]\n")
    pcap = ppcap.Reader(filename= pcapFilename) 

    def snort_content_parse(s):
        start = False
        out_string = ''
        for i in s:
            if i == '|':
                start = ~start
            elif i == '\"':
                pass
            elif i == ' ':
                if start:
                    pass
                else:
                    out_string = out_string + "%0.2x" % i #str(hex(ord(i)))
            elif not start:
                out_string = out_string + "%0.2x" % i #str(hex(ord(i))) 
            elif start:
                out_string = out_string + i
        if start:
            print("Error!")

        out_string = re.sub(r"0x",'',out_string)
        return out_string

    id_centroids = dict()
    with open(clusterCenSaveDir, 'r', encoding='utf-8') as cen_f:
        for line in cen_f:
            if (line not in ['\n', '\r\n', ' ']) and (line[0] != '#'):
                ruleid = int(line[0:7])
                centroids = eval(line[8:])
                if id_centroids.get(ruleid) is None:
                    id_centroids[ruleid] = centroids

    ruleset = dict()
    for ru in rule.parse_file(FPSaveDir):   #./data/normal_data/modbus_AS_test100.txt
        print("[%d] %s ; %s ; %s" % (ru.sid, ru.content, ru.offset, ru.depth))
        if ruleset.get(ru.sid) is None:
            ruleset[ru.sid] = list()

        ruleset[ru.sid].append(dict({'content': ru.content, 'offset': ru.offset,'depth': ru.depth}))

    total_count = 0
    normal_count = 0
    abnormal_count = 0
    ph1_ab_cnt = 0
    ph2_ab_cnt = 0

    f_sum_sav = open(summarySaveDir, 'w', encoding='utf-8')
    
    for ts, buf in pcap:
        ts_string = str(ts)
        ts_string = ts_string[0:-9] + '.' + ts_string[-9:]   
        total_count = total_count +1
        if total_count % 1000 == 0:
                print(total_count)
        #ts_datetime = datetime.fromtimestamp(ts/1000000000).strftime('%Y-%m-%dT%H:%M:%SZ')
        eth = ethernet.Ethernet(buf)

        if (eth[PROTOCOLS[protocol]] is not None) and (eth[PROTOCOLS[protocol]].body_bytes != b''):
            feature_bytes = eth[PROTOCOLS[protocol]].body_bytes
            #("%d: %s:%s -> %s:%s (body: %s)" % (ts, eth[ip.IP].src_s, eth[udp.UDP].sport, eth[ip.IP].dst_s, eth[udp.UDP].dport, eth[udp.UDP].body_bytes))
            
            out = bytes.hex(feature_bytes)
            
            
            if debug:
                print("Now checking Packet... ts = %s" % ts)
                print("Origin byte string: %s" % out)
            #print(ruleset)
            judged = False
            match = False
            for ruleid, ru in ruleset.items():

                if debug:
                    print("\t[%s]" % (ruleid))
                
                for sec in ru:
                    
                    refined_content = snort_content_parse(sec['content'])

                    if debug:
                        print("\t\t%s ; %s ; %s" % (refined_content, sec['offset'], sec['depth']))                
                    
                    content_len = int(len(refined_content))
                    offset = int(sec['offset'])*2
                    depth = int(sec['depth'])*2
                    lowbound = offset
                    upbound = offset + depth - content_len + 2 # content_len

                    for i in range(lowbound, upbound, 2):
                        checkout = out[ i: i+ content_len]
                        if debug:
                            print("\t\t%s <= checkout" % (checkout))
                        if checkout == refined_content:
                            match = True
                            
                            desc = dict()
                            desc['ts'] = ts
                            desc['rule_ID'] = ruleid
                            desc['rule_content'] = refined_content
                            desc['payload'] = out
                            desc['Lseq'] = None
                            desc['Rseq'] = None

                            #if out[0:i] != '':

                                # rem1 = re.findall('..',out[0:i])
                                # if debug:
                                #     print("\t\t\t rem1 = %s" % rem1)
            
                                # remseq = [0]*260
                                # for j in range(0,len(rem1)):
                                #     remseq[j] = int(rem1,16)
                                # cen = id_centroids[ruleid]
                                # dist = distance(remseq, cen)
                                # if dist < 20:                                   
                                #     normal_count = normal_count +1
                                # else:
                                #     abnormal_count = abnormal_count +1
                                
                            if out[i +content_len : len(out)] != '':
                                rem2 = re.findall('..',out[i +content_len : len(out)])
                                if debug:
                                    print("\t\t\t rem2 = %s" % rem2)
                                
                                if id_centroids[ruleid] is None:
                                    abnormal_count = abnormal_count +1
                                    ph2_ab_cnt += 1
                                    f_sum_sav.write("\n[phase 2] Abnormal. Condition: Signature right part is None.\n")
                                    f_sum_sav.write("  packet payload: {} ,rem: {} ,ts= {}\n".format(out,rem2,ts_string))
                                    
                                else:
                                    centroids = id_centroids[ruleid]
                                    remseq = [0]* len(rem2)
                                    for j in range(0,len(rem2)):
                                        remseq[j] = int(rem2[j],16)

                                    clu_check_normal = False
                                    for index,cen in enumerate(centroids):
                                        dist = distance(remseq, cen[1])
                                        if dist <= clusterBound:   
                                            normal_count = normal_count +1
                                            f_sum_sav.write("\n[All Pass] Normal. Condition: Signature right part match. Distance= {}\n".format(dist)) 
                                            f_sum_sav.write("  packet payload: {} ,rem: {} ,ts= {}\n".format(out,rem2,ts_string))
                                            f_sum_sav.write("  ruleID: {} ,content: {}\n".format(ruleid,refined_content))                    
                                            f_sum_sav.write("  centroid:[{}]--{}\n".format(index,cen[1]))
                                            clu_check_normal = True
                                            break
                                        else:
                                            f_sum_sav.write("\n[Info][phase 2] packet payload: {} ,rem: {} ,ts= {}\n".format(out,rem2,ts_string))
                                            f_sum_sav.write("  ruleID: {} ,content: {}\n".format(ruleid,refined_content)) 
                                            f_sum_sav.write("  centroid:[{}]--{}\n".format(index,cen[1]))

                                    if not clu_check_normal:
                                        abnormal_count = abnormal_count +1
                                        ph2_ab_cnt += 1
                                        f_sum_sav.write("\n[phase 2] Abnormal. Condition: All signatures right part not match.\n")
                                        f_sum_sav.write("  packet payload: {} ,ts= {}\n".format(out,ts_string))

                            else:
                                if id_centroids[ruleid] is None:
                                    normal_count = normal_count +1
                                    f_sum_sav.write("\n[All Pass] Normal. Condition: Both right parts of test-data and signature are both None. \n")
                                    f_sum_sav.write("  packet payload: {} ,rem: None ,ts= {}\n".format(out,ts_string))
                                else:
                                    abnormal_count = abnormal_count +1
                                    ph2_ab_cnt += 1
                                    f_sum_sav.write("\n[phase 2] Abnormal. Condition: Right part of test data is None.\n")
                                    f_sum_sav.write("  packet payload: {} ,rem: None ,ts= {}\n".format(out,ts_string))                                                  
                                    f_sum_sav.write("  ruleID: {} ,content: {}\n".format(ruleid,refined_content))                    
                                    # f_sum_sav.write("  centroid:[{}]--{}\n".format(index,cen))
                            judged = True 
                            break

                if judged == True:
                    break
            if not match:
                abnormal_count = abnormal_count +1
                ph1_ab_cnt += 1
                f_sum_sav.write("\n[phase 1] Abnormal.  Condition: All signatures not match.\n")
                f_sum_sav.write("  packet payload: {} ,ts= {}\n".format(out,ts_string))

    f_sum_sav.write("\n# abnormal_count = {}".format(abnormal_count))
    f_sum_sav.write("\n# normal_count = {}".format(normal_count))
    f_sum_sav.write("\n# total_count = {}".format(total_count))
    f_sum_sav.close()
    
    print("\tabnormal_count = %s" % abnormal_count)
    print("\tnormal_count = %s" % normal_count)
    print("\ttotal_count = %s" % total_count)
    print("\t\tabnormal_rate = %s" % (abnormal_count/total_count)) 

    print("AS_check finished.\n==============")

    return [abnormal_count, normal_count, total_count, ph1_ab_cnt, ph2_ab_cnt]

            
