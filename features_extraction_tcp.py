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

ruleset = dict()
for rule in rule.parse_file("./data/normal_data/modbus_AS_fullfilesupport.txt"):
    print("[%d] %s ; %s ; %s" % (rule.sid, rule.content, rule.offset, rule.depth))
    if ruleset.get(rule.sid) is None:
        ruleset[rule.sid] = list()

    ruleset[rule.sid].append(dict({'content': rule.content, 'offset': rule.offset,'depth': rule.depth}))

# o = eval("['00', '00', '00', '00', '00', '06', '0a', '08', '00', '04', '00', '00']")
# print(type(o[0]), o)

pcap = ppcap.Reader(filename="./data/normal_data/4SICS_modbus_input.pcap")
saveDir = "./output/AS_projection/modbus_projection_byteseq"
f = open(saveDir, 'w', encoding='utf-8')
normal_count = 0
match_count = 0
total_count = 0


for ts, buf in pcap:
    total_count = total_count +1
    ts_datetime = datetime.fromtimestamp(ts/1000000000).strftime('%Y-%m-%dT%H:%M:%SZ')
    eth = ethernet.Ethernet(buf)

    if eth[tcp.TCP] is not None:
        feature_bytes = eth[tcp.TCP].body_bytes
        #("%d: %s:%s -> %s:%s (body: %s)" % (ts, eth[ip.IP].src_s, eth[udp.UDP].sport, eth[ip.IP].dst_s, eth[udp.UDP].dport, eth[udp.UDP].body_bytes))
        
        out = bytes.hex(feature_bytes)
        
        print("Now checking next payload...")
        print("Origin byte sequence:\n %s" % out)
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
                print("\t upper=%s , lower=%s" % (upbound/2,lowbound/2))
                for i in range(lowbound, upbound, 2):
                    checkout = out[ i: i+ content_len]
                    print("\t\t%s <= checkout" % (checkout))
                    if checkout == refined_content:
                        
                        print("\t\tSignature match. Now generating remaining byte string.")
                        match_count = match_count +1
                        if (not match):
                            normal_count = normal_count +1

                        if out[0:i] != '':
                            rem1 = re.findall('..',out[0:i])
                            print("\t\t\t rem1 = %s" % rem1)

                            f.write(str(rem1))
                            f.write( " # {} [{}] {} matched before? {} ; ts={} ; payload={}\n".format(ts_datetime,ruleid,refined_content,match,ts,out) )
                            #f.write( " # ts={} [{}] {} matched? {}\n".format(ts_datetime,ruleid,refined_content,match) )
                        if out[i +content_len : len(out)] != '':
                            rem2 = re.findall('..',out[i +content_len : len(out)])
                            print("\t\t\t rem2 = %s" % rem2)

                            f.write(str(rem2))
                            f.write( " # R {} [{}] {} matched before? {} ; ts={} ; payload={}\n".format(ts_datetime,ruleid,refined_content,match,ts,out) )
                            #f.write( " # ts={} [{}] {} matched? {}\n".format(ts_datetime,ruleid,refined_content,match) )
                        match = True
                    print("\t\tSignature not match.")
        
        if match == False:
            print("\t\tAll not match! Now generating whole byte string.")
            out_l = re.findall('..',out)
            
            f.write(str(out_l))
            f.write( " # {} ts={}\n".format(ts_datetime,ts) )

f.write("\n# normal_count = {}\n".format(normal_count) )
f.write("# match_count = {}\n".format(match_count) )
f.write("# total_packet = {}".format(total_count) )

f.close()


# key = b'\x81\n\x00\x11\x01\x04\x00\x05\x01\x0c\x0c\x02?\xff\xff\x19K'
# out = np.array([k for k in key])
# out = np.uint8(out)
# out = np.expand_dims(out, axis=1)
# out = np.unpackbits(out, axis=1)
# print(out)