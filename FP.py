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
from PrefixSpan import PrefixSpan

PROTOCOLS = [tcp.TCP, udp.UDP]

def FP_generation(pcapFilename, FPSaveDir, freq_req, length_req=3, protocol = 0, lenLimit=12):
    print("FP_generation...")
    db = list()

    pcap = ppcap.Reader(filename=pcapFilename)
    for ts, buf in pcap:
        # print(buf)
        eth = ethernet.Ethernet(buf)
        if (eth[PROTOCOLS[protocol]] is not None) and (eth[PROTOCOLS[protocol]].body_bytes != b''):
            feature_bytes = eth[PROTOCOLS[protocol]].body_bytes
            #("%d: %s:%s -> %s:%s (body: %s)" % (ts, eth[ip.IP].src_s, eth[udp.UDP].sport, eth[ip.IP].dst_s, eth[udp.UDP].dport, eth[udp.UDP].body_bytes))

            byteseq = list(feature_bytes)[0:lenLimit]
            db.append(byteseq)

    pcap.close()

    ps = PrefixSpan(db)

    print("\tstart prefixspan...")
    seq_out = ps.topk(1000, closed=True)
    print("\t\t{} sequential pattern found.".format(len(seq_out)))
    print("\tfinish prefixspan...")
    # f_FP_seq = open("./data/normal_data/FP_rule/modbus_AS_seq", 'w', encoding='utf-8')
    # for seq in seq_out:
    #     f_FP_seq.write("{}\n".format(str(seq[1])))

    def magic(patt, matches):
        check = True
        begin = sys.maxsize #matches[0][1] - len(patt) +1
        end = -sys.maxsize -1 #matches[0][1] 
        ctn_cnt = 0
        for i in range(0, len(matches)):
            
            for k in range(0, len(patt)):
                # print('patt[k] = %s' % (patt[k]))
                # print('db = %s' % (db[matches[i][0]][matches[i][1]-len(patt)+1+k]))
                if  patt[k] == db[matches[i][0]][matches[i][1]-len(patt)+1+k]:
                    continue
                else:
                    check = False
                    break
            if check:
                ctn_cnt = ctn_cnt +1
                
                if  matches[i][1] > end:
                    end = matches[i][1]
                if  matches[i][1] - len(patt) +1 < begin:
                    begin = matches[i][1] - len(patt) +1
            else:
                check = True

        return [begin,end,ctn_cnt]

    f_FP = open(FPSaveDir, 'w', encoding='utf-8')
    sid_cnt = 1000000


    def transfer_to_rule(s):
        out_string = ' '.join(a+b for a,b in zip(s[::2], s[1::2]))
        out_string

        return '|'+out_string+'|'

    for i in ps._results:
        if len(i[1]) >= length_req:
            [begin,end,freq] = magic(i[1],i[2])

            if freq > freq_req:
                print("patter {}: frequency {}\n\tbeing: {},end: {}".format(i[1],freq,begin,end))
                sid_cnt = sid_cnt +1
                
                out = ''.join( "%0.2x" % e for e in i[1])
                # print("out = %s" % out)

                f_FP.write( "alert  tcp any any -> 192.168.88.0/24 502  (sid: {}; content:\"{}\";  offset:{}; depth:{}; )\n".format(sid_cnt, transfer_to_rule(out), begin, end-begin+1 ) )
            
    f_FP.close()
    print("FP_generation finished.\n==============")
