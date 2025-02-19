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
from AS_check_tcp import AS_check
from check import total_check
from second_model import second_phase

protocol_name = 'bacnet'
protocol_code = 1

for p in range(1,2):  
    if p == 0:
        repeat = 1          
        length_req = 2      # length_req # 5  [2-11]
        freq_req = 5        
        lenLimit = 15       
        thresh = 0.2        
        iteration = 10
        ExperimentParam = "FPLL" # Frequent Pattern Least Support
    elif p == 1:
        repeat = 1
        length_req = 5
        freq_req = 5        # freq_req # 5  [3-41]
        lenLimit = 15   
        thresh = 0.2
        iteration = 20
        ExperimentParam = "FPLS" # Frequent Pattern Least Support
    elif p == 2:
        repeat = 1
        length_req = 5
        freq_req = 5
        lenLimit = 15
        thresh = 0.1        # thresh # 0.2  [0.1-0.55]
        iteration = 10
        ExperimentParam = "CBT"  # Cluster Boundary Threshold
    elif p == 3:
        repeat = 1          # repeat # 1 [1-5]
        length_req = 5
        freq_req = repeat*2
        lenLimit = 15
        thresh = 0.2
        iteration = 3
        ExperimentParam = "TDDT" # Training Data Duplication Time

    date_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    date_str_file = datetime.now().strftime('%m%d')
    sourceFilename = "./data/normal_data/BACnet_Host_Training_filter1.pcap"
    testFilename = "./data/test_data/bacnet/bacnet_test_spec.pcap"

    # ExperimentParam = "SLoP" # Shortened length of payload
    ExperimentOutFile = "./output/" + date_str_file + "_bacnet_experiments_param_" + ExperimentParam
    f = open(ExperimentOutFile, 'w', encoding='utf-8')
    f.write("Experiment Datetime: {}\n".format(date_str)) 
    f.write("Normal Traffic File = {}  # The PCAP file used to train normal model. It is assumed completely normal. \n".format(sourceFilename)) 
    f.write("Test Traffic File = {}  # The PCAP file used for test. It is assumed completely abnormal. \n".format(testFilename))
    f.write("*====================================*\n")
    f.close()

    for i in range(0,iteration):
        iter = str(i)
        print("[ Iteration " + iter + " ]\n-----------------------------------\n")

        abnormal_count = 0
        normal_count = 0
        total_count = 0

        abnormal_count_va = 0
        normal_count_va = 0
        total_count_va = 0
        
        saveFilename = "./data/test_data/bacnet/random_test/bacnet_customize"+ iter+ ".pcap"
        FPSaveDir = "./data/normal_data/FP_rule/bacnet/bacnet_FP" + iter

        pcapFilename = saveFilename
        abnormalSaveDir = "./output/AS_check/bacnet/random_test/bacnet_FP_check_ab_sig" + iter
        susSaveDir = "./output/AS_check/bacnet/random_test/bacnet_FP_check_sus_seq" + iter
        summarySaveDir = "./output/AS_check/bacnet/random_test/bacnet_FP_check_sum" + iter
        clusterCenSaveDir = "./output/AS_check/bacnet/random_test/bacnet_FP_cluster" + iter
        
        packet_generation(sourceFilename, saveFilename, maxi= 500, duration= 500, sampleRate= 1, repeat = repeat)
        FP_generation(pcapFilename, FPSaveDir, length_req=length_req, freq_req= freq_req, protocol=protocol_code, lenLimit=lenLimit)
        AS_check(pcapFilename, abnormalSaveDir, susSaveDir, summarySaveDir, FPSaveDir, protocol=1)
        second_phase(susSaveDir, clusterCenSaveDir, thresh=thresh, protocol_name= 'bacnet')

        finalSummarySaveDir = "./output/AS_check/bacnet/validation/bacnet_final_check_sum" + iter
        pcapFilename = saveFilename
        [abnormal_va, normal_va, total_va] = total_check(pcapFilename,finalSummarySaveDir,FPSaveDir,clusterCenSaveDir,clusterBound=thresh, protocol=1, debug=False)
        abnormal_count_va = abnormal_count_va + abnormal_va
        normal_count_va = normal_count_va + normal_va
        total_count_va = total_count_va + total_va

        finalSummarySaveDir = "./output/AS_check/bacnet/test/bacnet_final_check_sum" + iter
        pcapFilename = testFilename
        [abnormal, normal, total] = total_check(pcapFilename,finalSummarySaveDir,FPSaveDir,clusterCenSaveDir,clusterBound=thresh, protocol=1, debug=False)
        abnormal_count = abnormal_count + abnormal
        normal_count = normal_count + normal
        total_count = total_count + total

        print("[ All Iteration Ends ]\n-----------------------------------")
        print("\tabnormal_count_va = %s" % abnormal_count_va)
        print("\tnormal_count_va = %s" % normal_count_va)
        print("\ttotal_count_va = %s" % total_count_va)
        print("\n\tAverage abnormal rate of validation = %s" % (abnormal_count_va/total_count_va)) 
        print("\n-----------------------------------")
        print("\tabnormal_count = %s" % abnormal_count)
        print("\tnormal_count = %s" % normal_count)
        print("\ttotal_count = %s" % total_count)
        print("\n\tAverage abnormal rate of test= %s" % (abnormal_count/total_count)) 

        with open(ExperimentOutFile, 'a', encoding='utf-8') as f:
            
            f.write("[ Iteration " + iter + " ]\n")
            f.write("Experiment parameter:\n")
            f.write("  Training Data Duplication Time = {}  # In oder to mimic the bahavior of ICS, maybe we should give training data regularity. \n".format(repeat))
            f.write("  Frequent Pattern Least Length = {}  # The least length required for FP. \n".format(length_req)) 
            f.write("  Frequent Pattern Least Support = {}  # The least support required for FP. \n".format(freq_req))  
            f.write("  Shortened length of payload = {}  # The shortened length of payload for efficient Frequent Pattern. \n".format(lenLimit))
            f.write("  Cluster Boundary Threshold = {}  # An unknown point with distance higher that CBT would be regarded as outlier. \n".format(thresh)) 

            f.write("-------------------------------\n")
            f.write("Normal Traffic File Validation Result:\n")
            f.write("\tAbnormal Count = {}\n".format(abnormal_count_va) )
            f.write("\tNormal Count = {}\n".format(normal_count_va) )
            f.write("\tTotal Number of Packet = {}\n".format(total_count_va) )
            f.write("\t\tAbnormal Rate = {}\n".format(abnormal_count_va/total_count_va) )

            f.write("-------------------------------\n")
            f.write("Abnormal Traffic File Test Result:\n")
            f.write("\tAbnormal Count = {}\n".format(abnormal_count) )
            f.write("\tNormal Count = {}\n".format(normal_count) )
            f.write("\tTotal Number of Packet = {}\n".format(total_count) )
            f.write("\t\tAbnormal Rate = {}\n".format(abnormal_count/total_count) )

            f.write("-------------------------------\n")
            f.write("Confusion Matrix: (Assume that \"Abnormal\" is Positive)\n")
            f.write("\t*{:^12}+{:^12}+{:^12}*\n".format("----------" , "----------", "----------" ))
            f.write("\t|{:^12}|{:^12}|{:^12}|\n".format("GT \\ PR" ,"Abnormal", "Normal" )) 
            f.write("\t+{:^12}|{:^12}|{:^12}+\n".format("----------" , "----------", "----------"))
            f.write("\t|{:^12}|{:^12}|{:^12}|\n".format("Abnormal" , str(abnormal_count)+'(TP)' ,  str(normal_count)+'(FN)' ))
            f.write("\t+{:^12}|{:^12}|{:^12}+\n".format("----------" , "----------", "----------"))
            f.write("\t|{:^12}|{:^12}|{:^12}|\n".format("Normal" , str(abnormal_count_va)+'(FP)', str(normal_count_va)+'(TN)' ))
            f.write("\t*{:^12}+{:^12}+{:^12}*\n".format("----------" , "----------", "----------" ))

            f.write("\t{:<40}  # TP/TP+FN\n".format("True Positive Rate = " + str(abnormal_count/total_count) ) )
            f.write("\t{:<40}  # FP/FP+TN\n".format("False Positive Rate = " + str(abnormal_count_va/total_count_va) ) )
            f.write("\t{:<40}  # TN/FP+TN\n".format("True Negative Rate = " + str(normal_count_va/total_count_va) ) )
            f.write("\t{:<40}  # FN/TP+FN\n".format("False Negative Rate = " + str(normal_count/total_count) ) )
            f.write("\t{:<40}  # TP/TP+FP\n".format("Precision = " + str(abnormal_count /(abnormal_count + abnormal_count_va)) ) )
            f.write("\t{:<40}  # TP+TN/TP+TN+FP+FN\n".format("Accuracy = " + str((abnormal_count + normal_count_va) /(total_count_va + total_count)) ) )

            f.write("====================================\n")
            
        if p == 0:         
            length_req += 1      # length_req # 5  [2-11]

        elif p == 1:
            freq_req += 4        # freq_req # 5  [3-41]

        elif p == 2:
            thresh += 0.05        # thresh # 0.2  [0.1-0.55]

        elif p == 3:
            repeat += 2          # repeat # 1 [1-5]
            freq_req = repeat*2
    
