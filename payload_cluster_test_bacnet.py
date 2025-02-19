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
from hier_cluster import clustering, distance

PROTOCOLS = [tcp.TCP, udp.UDP]

summary = dict()
summary['abnormal_count'] = list()
summary['normal_count'] = list()
summary['total_count'] = list()
summary['abnormal_count_va'] = list()
summary['normal_count_va'] = list()
summary['total_count_va'] = list()
summary['coverage'] = list()
summary['accuracy'] = list()
summary['precision'] = list()
summary['recall'] = list()
summary['FP_rate'] = list() 
summary['clusterCnt'] = list()

def one_check(testFilename, clusterCenSaveDir, summarySaveDir, clusterBound, debug = False, protocol = 1, validation= False):

    print("Runing one_check()...[" + testFilename + "]\n")

    pcap = ppcap.Reader(filename= testFilename) 

    total_count = 0
    normal_count = 0
    abnormal_count = 0

    id_centroids = dict()
    with open(clusterCenSaveDir, 'r', encoding='utf-8') as cen_f:
        for line in cen_f:
            if (line not in ['\n', '\r\n', ' ']) and (line[0] != '#'):
                ruleid = int(line[0:7])
                centroids = eval(line[8:])
                if id_centroids.get(ruleid) is None:
                    id_centroids[ruleid] = centroids
    
    f_sum_sav = open(summarySaveDir, 'w', encoding='utf-8')

    for ts, buf in pcap:
        total_count = total_count +1
        ts_string = str(ts)
        ts_string = ts_string[0:-9] + '.' + ts_string[-9:]   

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
            data = re.findall('..',out)
            data_int = [0]* len(data)
            for j in range(0,len(data)):
                data_int[j] = int(data[j],16)

            centroids = id_centroids[ruleid]
            match = True
            for index,cen in enumerate(centroids):
                dist = distance(data_int, cen[1])
                if dist <= clusterBound:   
                    normal_count = normal_count +1
                    f_sum_sav.write("\n[Normal]: Distance to one centroid is under threshold. Distance= {}, Radius= {}\n".format(dist,cen[0])) 
                    f_sum_sav.write("  packet payload: {} , ts= {}\n".format(out, ts_string))
                    f_sum_sav.write("  centroid:[{}]--{}\n".format(index,cen[1]))
                    match = True
                    break
                else:
                    f_sum_sav.write("\n[Info]: Distance to centroid No.{} is {}, Radius= {}\n".format(index, dist, cen[0])) 
                    f_sum_sav.write("  packet payload: {} , ts= {}\n".format(out, ts_string))
                    f_sum_sav.write("  centroid:[{}]--{}\n".format(index,cen[1]))
                    match = False
            if not match:
                abnormal_count += 1
                f_sum_sav.write("\n[Abnormal]: Distance to no centroid is under threshold.")
                f_sum_sav.write("  packet payload: {} , ts= {}\n".format(out, ts_string))
    if validation == True:
        summary['abnormal_count_va'].append(abnormal_count)
        summary['normal_count_va'].append(normal_count)
        summary['total_count_va'].append(total_count)
        
    else:
        summary['abnormal_count'].append(abnormal_count)
        summary['normal_count'].append(normal_count)
        summary['total_count'].append(total_count)
        
    print("\tabnormal_count = %s" % abnormal_count)
    print("\tnormal_count = %s" % normal_count)
    print("\ttotal_count = %s" % total_count)

    print("one_check() finished. \n==============")

def one_check_cluster(trainingFilename, clusterCenSaveDir, thresh=0.2, protocol= 1, protocol_name='pro', debug = False):
    print("Runing one_check_cluster()...[" + trainingFilename + "]\n")
    pcap = ppcap.Reader(filename= trainingFilename)
    total_count = 0
    rule_seqs = dict()
    for ts, buf in pcap:
        total_count = total_count +1
        ts_string = str(ts)
        ts_string = ts_string[0:-9] + '.' + ts_string[-9:]   

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
            data = re.findall('..',out)
            id = 1000000
                
            remseq = [0]* len(data)
            for j in range(0,len(data)):
                remseq[j] = int(data[j],16)

            if rule_seqs.get(id) is None:
                rule_seqs[id] = list()
            rule_seqs[id].append(remseq)
            
    output_file = open(clusterCenSaveDir, 'w', encoding='utf-8')
    for ruleid, remseqs in rule_seqs.items():
            
        if remseqs is not None:
            print("\truning clustering... [{}]".format(ruleid))
            results = clustering(remseqs,ruleid, protocol_name, threshold=thresh)
            print("\tclustering finished.")

            output_file.write("{}: {} \n# Centroids number = {}\n".format(ruleid,results, len(results)))
        
        else:
            output_file.write("{}: None \n# No remaining part.\n".format(ruleid))

    output_file.close()
    print("one_check_cluster() finished. \n==============")
    return len(results)

for i in range(0,201):
    print("[ Iteration " + str(i+1) + " ]\n-----------------------------------\n")
    thresh = 0.00 + 0.05*i
    clusterCnt = one_check_cluster(trainingFilename = "./data/test_data/bacnet/train/bacnet_08_train.pcap", 
        clusterCenSaveDir= "./output/AS_check/bacnet/another_test/clusterCen", 
        thresh=0.2, 
        protocol_name= 'bacnet_ano',
        protocol= 1)

    one_check(testFilename= "./data/test_data/bacnet/bacnet_test_spec.pcap", # "./data/normal_data/4SICS-Modbus-Spec.pcap", #"./data/normal_data/4SICS-Modbus-Spec.pcap",
        clusterCenSaveDir = "./output/AS_check/bacnet/another_test/clusterCen", 
        summarySaveDir= "./output/AS_check/bacnet/another_test/summary_test",
        clusterBound =thresh,
        protocol = 1,
        debug = False)

    one_check(testFilename= "./data/test_data/bacnet/test/bacnet_02_test.pcap", 
        clusterCenSaveDir = "./output/AS_check/bacnet/another_test/clusterCen", 
        summarySaveDir= "./output/AS_check/bacnet/another_test/summary_validation",
        clusterBound =thresh,
        protocol = 1,
        debug = False,
        validation= True)
    
    summary['coverage'].append(summary['normal_count_va'][i]/summary['total_count_va'][i])
    summary['accuracy'].append( (summary['normal_count_va'][i]+summary['abnormal_count'][i]) / (summary['total_count_va'][i]+summary['total_count'][i]) )
    summary['recall'].append( (summary['abnormal_count'][i]) / (summary['total_count'][i]) )
    summary['FP_rate'].append(summary['abnormal_count_va'][i]/summary['total_count_va'][i])
    summary['clusterCnt'].append(clusterCnt)
    if (summary['abnormal_count'][i] == 0) and (summary['abnormal_count_va'][i] == 0):
        summary['precision'].append(0)
        
    else:
        summary['precision'].append( (summary['abnormal_count'][i]) / (summary['abnormal_count'][i]+ summary['abnormal_count_va'][i]) )

with open("./output/AS_check/bacnet/another_test/bacnet_summary", 'w', encoding='utf-8') as f:
    f.write(str(summary))
            