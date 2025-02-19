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

def AS_check(pcapFilename, abnormalSaveDir, susSaveDir, summarySaveDir, FPSaveDir, debug = False, protocol = 0):

    print("Runing AS_check...[" + pcapFilename + "]\n")

    pcap = ppcap.Reader(filename= pcapFilename) 

    def transfer_to_rule(s):
        out_string = ' '.join(a+b for a,b in zip(s[::2], s[1::2]))
        # for j in range(2, len(hex_string),2):
        #     out_string = hex_string[0:j] + ' ' + hex_string[j:len(hex_string)]

        return '|'+out_string+'|'

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

    ruleset = dict()
    for ru in rule.parse_file(FPSaveDir):   #./data/normal_data/modbus_AS_test100.txt
        print("[%d] %s ; %s ; %s" % (ru.sid, ru.content, ru.offset, ru.depth))
        if ruleset.get(ru.sid) is None:
            ruleset[ru.sid] = list()

        ruleset[ru.sid].append(dict({'content': ru.content, 'offset': ru.offset,'depth': ru.depth}))



    f_ab_sav = open(abnormalSaveDir, 'w', encoding='utf-8')
    f_sus_sav = open(susSaveDir, 'w', encoding='utf-8')
    total_count = 0
    normal_count = 0
    match_count = 0
    abnormal_count = 0
    summary = dict()
    summary['ab_ts'] = list()

    for ts, buf in pcap:
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
                            # print("\t\tSignature match. This packet would be seen as normal.")
                            match_count = match_count +1
                            desc = dict()
                            desc['ts'] = ts
                            desc['matched'] = match
                            desc['rule_ID'] = ruleid
                            desc['rule_content'] = refined_content
                            desc['payload'] = out
                            desc['Lseq'] = None
                            desc['Rseq'] = None

                            if (not match):
                                normal_count = normal_count +1
                            
                            if out[0:i] != '':
                                rem1 = re.findall('..',out[0:i])
                                if debug:
                                    print("\t\t\t rem1 = %s" % rem1)
            
                                desc['Lseq'] = rem1
                                
                                # f_sus_sav.write(desc)
                                #f_sus_sav.write( " # datetime={} [{}] {} matched before? {} ; ts={} ; payload={}\n".format(ts_datetime,ruleid,refined_content,match,ts,out) )
                            if out[i +content_len : len(out)] != '':
                                rem2 = re.findall('..',out[i +content_len : len(out)])
                                if debug:
                                    print("\t\t\t rem2 = %s" % rem2)
                                
                                desc['Rseq'] = rem2
                                
                                #f_sus_sav.write(str(rem2))
                                #f_sus_sav.write( " # datetime={} [{}] {} matched before? {} ; ts={} ; payload={}\n".format(ts_datetime,ruleid,refined_content,match,ts,out) )
                            # alert  tcp any any -> 192.168.88.0/24 502  (sid: 1000004; content:"|01 00 00 00 01|";  offset:7; depth:5; )
                            f_sus_sav.write("{}\n".format(str(desc)))
                            #byteseq[ruleid].append(desc)
                            match = True
                            
                            break
                        # print("\t\tSignature not match.")
                    if match is True:
                        break

            if match == False:
                if debug:
                    print("\t\tAll signatures not match! This packet would be sent to do byte sequence classification.")
                abnormal_count = abnormal_count +1

                summary['ab_ts'].append(ts)

                #byteseq['outlier'].append(desc)
                f_ab_sav.write( "alert  tcp any any -> 192.168.88.0/24 502  (sid: 1000004; content:\"{}\";  offset:0; depth:{}; )\n".format(transfer_to_rule(out), int(len(out)/2) ) )
                # f_ab_sav.write( "\t# Counter packet datetime={} ; ts={} ; payload={}\n".format(ts_datetime,ts,out))

    summary['abnormal_count'] = abnormal_count
    summary['normal_count'] = normal_count
    summary['match_count'] = match_count
    summary['total_count'] = total_count
    print("\tabnormal_count = %s" % abnormal_count)
    print("\tnormal_count = %s" % normal_count)
    print("\tmatch_count = %s" % match_count)
    print("\ttotal_count = %s" % total_count)
    print("\t\tabnormal_rate = %s" % (abnormal_count/total_count)) 

    f_sum_sav = open(summarySaveDir, 'w', encoding='utf-8')
    f_sum_sav.write(str(summary))
    f_sum_sav.write("\nruleIDs:\n")
    for ruleid, ru in ruleset.items():
        f_sum_sav.write("{},".format(str(ruleid)))
    f_sum_sav.write("\n")

    f_sus_sav.write("\n# normal_count = {}\n".format(normal_count) )
    f_sus_sav.write("# match_count = {}\n".format(match_count) )
    f_sus_sav.write("# total_packet = {}".format(total_count) )

    f_ab_sav.write("\n#abnormal_count = {}\n".format(abnormal_count) )
    f_ab_sav.write("# total_packet = {}".format(total_count) )

    f_sus_sav.close()
    f_ab_sav.close()
    print("AS_check finished.\n==============")

            