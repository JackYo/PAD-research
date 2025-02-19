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
import matplotlib.pyplot as plt

protocol_code = 1

if protocol_code == 0:
    protocol_name = 'modbus' 
elif protocol_code == 1:
    protocol_name = 'bacnet' 


# repeat = 1          
# length_req = 5     
# freq_req = 5        
# lenLimit = 15       
# thresh = 0.2 

for p in [1]:  
    summary = dict()
    summary['abnormal_count'] = list()
    summary['normal_count'] = list()
    summary['total_count'] = list()
    summary['abnormal_count_va'] = list()
    summary['normal_count_va'] = list()
    summary['total_count_va'] = list()
    summary['precision'] = list()
    summary['accuracy'] = list()
    summary['coverage'] = list()
    summary['recall'] = list()
    summary['FP_rate'] = list()
    summary['ph1_ab'] = list()
    summary['ph2_ab'] = list()
    summary['ph1_ab_va'] = list()
    summary['ph2_ab_va'] = list()
    summary['av_precision'] = list()
    summary['av_accuracy'] = list()
    summary['av_recall'] = list()
    summary['av_coverage'] = list()
    summary['av_FP_rate'] = list()

    if p == 0:
        repeat = 1          
        length_req = 2      # length_req # 5  [2-11]
        freq_req = 5        
        lenLimit = 15       
        thresh = 0.2        
        iteration = 10
        ExperimentParam = "FPLL" # Frequent Pattern Least Length
        summary['X'] = [ (2 + j) for j in range(0,10)]  # str(np.arange(2,12,1))
        summary['X_label'] = 'Frequent Pattern Least Length'
    elif p == 1:
        repeat = 1
        length_req = 2 
        freq_req = 2        # freq_req # 5  [3-41]
        lenLimit = 15   
        thresh = 0.2
        iteration = 6
        iteration2= 6
        ExperimentParam = "FPLS" # Frequent Pattern Minimum Support
        ExperimentParam2 = "FPLL"
        summary['X'] = [ (2 + 2*j) for j in range(0,iteration)]  # str(np.arange(3,43,2))
        summary['X_label'] = 'Minimum Support'
    elif p == 2:
        repeat = 1
        length_req = 5
        freq_req = 5
        lenLimit = 15
        thresh = 0.1        # thresh # 0.2  [0.1-0.55]
        iteration = 10
        ExperimentParam = "CBT"  # Cluster Boundary Threshold
        summary['X'] = [ (0.1 + 0.05*j) for j in range(0,10)]  # str(np.arange(0.1, 0.6, 0.05))
        summary['X_label'] = 'Cluster Boundary Threshold'
    # elif p == 3:
    #     repeat = 1          # repeat # 1 [1-5]
    #     length_req = 5
    #     freq_req = repeat*2
    #     lenLimit = 15
    #     thresh = 0.2
    #     iteration = 3
    #     ExperimentParam = "TDDT" # Training Data Duplication Time
    #     summary['X'] = np.arange(1, 6, 1)
    #     summary['X_label'] = 'Training Data Duplication Time'
    

    date_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    date_str_file = datetime.now().strftime('%m%d')
    if protocol_code == 0:
        sourceFilename = "./data/4SICS_modbus_filter2.pcap"
        testFilename = "./data/test_data/modbus/modbus_test_data_spec.pcap"
    elif protocol_code == 1:
        sourceFilename = "./data/BACnet_Host_Training_filter1.pcap"
        testFilename = "./data/test_data/bacnet/bacnet_test_spec.pcap"

    # ExperimentParam = "SLoP" # Shortened length of payload
    ExperimentOutFile = "./output/" + date_str_file + "_" + protocol_name + "_summary_param_" + ExperimentParam + "vs" + ExperimentParam2
    SummaryOutFile = "./output/summary/" + date_str_file + "_" + protocol_name + "_summary_param_" + ExperimentParam + "vs" + ExperimentParam2
    filename = ExperimentParam + 'vs' + ExperimentParam2
    f = open(ExperimentOutFile, 'w', encoding='utf-8')
    f.write("Experiment Datetime: {}\n".format(date_str)) 
    f.write("Normal Traffic File = {}  # The PCAP file used to train normal model. It is assumed completely normal. \n".format(sourceFilename)) 
    f.write("Test Traffic File = {}  # The PCAP file used for test. It is assumed completely abnormal. \n".format(testFilename))
    f.write("*====================================*\n")
    f.close()

    f_sum = open(SummaryOutFile, 'w', encoding='utf-8')
    f_sum.close()

    av_precision = 0
    av_accuracy = 0
    av_recall = 0
    av_coverage = 0
    av_FP_rate = 0
         # length_req # 5  [2-11]
    
    for k in range(0,iteration2):        
 
        freq_req = 2
        for i in range(0,iteration):
            iter = str(i+1)
            print("[ Iteration " + str(k+1) + "-" + iter + " ]\n-----------------------------------\n")
            
            abnormal_count = 0
            normal_count = 0
            total_count = 0

            abnormal_count_va = 0
            normal_count_va = 0
            total_count_va = 0

            saveFilename2 = "./data/test_data/" + protocol_name + "/test/" + protocol_name + "_02_test.pcap"
            saveFilename = "./data/test_data/" + protocol_name + "/train/" + protocol_name + "_08_train.pcap"
            FPSaveDir = "./data/normal_data/FP_rule/" + protocol_name + "/" + protocol_name + "_FP_" + filename + iter

            abnormalSaveDir = "./output/AS_check/" + protocol_name + "/random_test/" + protocol_name + "_FP_check_ab_sig" + iter
            susSaveDir = "./output/AS_check/" + protocol_name + "/random_test/" + protocol_name + "_FP_check_sus_seq" + iter
            summarySaveDir = "./output/AS_check/" + protocol_name + "/random_test/" + protocol_name + "_FP_check_sum" + iter
            clusterCenSaveDir = "./output/AS_check/" + protocol_name + "/random_test/" + protocol_name + "_FP_cluster_" + filename + iter

            # packet_generation(sourceFilename, saveFilename, maxi= 374, duration= 374, sampleRate= 1, repeat = repeat)
            FP_generation(saveFilename, FPSaveDir, length_req=length_req, freq_req=freq_req, protocol=protocol_code, lenLimit=lenLimit)
            AS_check(saveFilename, abnormalSaveDir, susSaveDir, summarySaveDir, FPSaveDir, protocol=protocol_code)
            second_phase(susSaveDir, clusterCenSaveDir, thresh=thresh, protocol_name= protocol_name)

            finalSummarySaveDir = "./output/AS_check/" + protocol_name + "/validation/" + protocol_name + "_final_check_sum" + iter
            [abnormal_va, normal_va, total_va, ph1_ab_va, ph2_ab_va] = total_check(saveFilename2,finalSummarySaveDir,FPSaveDir,clusterCenSaveDir,clusterBound=thresh, protocol=protocol_code, debug=False)
            abnormal_count_va = abnormal_count_va + abnormal_va
            normal_count_va = normal_count_va + normal_va
            total_count_va = total_count_va + total_va

            finalSummarySaveDir = "./output/AS_check/" + protocol_name + "/test/" + protocol_name + "_final_check_sum" + iter
            [abnormal, normal, total, ph1_ab, ph2_ab] = total_check(testFilename,finalSummarySaveDir,FPSaveDir,clusterCenSaveDir,clusterBound=thresh, protocol=protocol_code, debug=False)
            abnormal_count = abnormal_count + abnormal
            normal_count = normal_count + normal
            total_count = total_count + total

            precision = abnormal_count/ (abnormal_count+abnormal_count_va)
            accuracy = (abnormal_count + normal_count_va) /(total_count_va + total_count)
            recall = abnormal_count/total_count
            coverage = normal_count_va / total_count_va
            FP_rate = abnormal_count_va / total_count_va
            av_precision += precision
            av_accuracy += accuracy
            av_recall += recall
            av_coverage += coverage
            av_FP_rate += FP_rate

            summary['abnormal_count'].append(abnormal_count)
            summary['normal_count'].append(normal_count)
            summary['total_count'].append(total_count)
            summary['abnormal_count_va'].append(abnormal_count_va)
            summary['normal_count_va'].append(normal_count_va)
            summary['total_count_va'].append(total_count_va)
            summary['recall'].append(recall)
            summary['precision'].append(precision)
            summary['accuracy'].append(accuracy)
            summary['coverage'].append(coverage)
            summary['FP_rate'].append(FP_rate)
            summary['ph1_ab'].append(ph1_ab)
            summary['ph2_ab'].append(ph2_ab)
            summary['ph1_ab_va'].append(ph1_ab_va)
            summary['ph2_ab_va'].append(ph2_ab_va)

            print("[ Iteration " + iter + " Ends ]\n-----------------------------------")
            print("\tabnormal_count_va = %s" % abnormal_count_va)
            print("\tnormal_count_va = %s" % normal_count_va)
            print("\ttotal_count_va = %s" % total_count_va)
            print("\n\tAverage abnormal rate of validation = %s" % (abnormal_count_va/total_count_va)) 
            print("\n-----------------------------------")
            print("\tabnormal_count = %s" % abnormal_count)
            print("\tnormal_count = %s" % normal_count)
            print("\ttotal_count = %s" % total_count)
            print("\n\tAverage abnormal rate of test= %s" % (abnormal_count/total_count)) 

            f = open(ExperimentOutFile, 'a', encoding='utf-8')
                
            f.write("[ Iteration " + iter + " ]\n")
            f.write("Experiment parameter:\n")
            f.write("  Training Data Duplication Time = {}  # In oder to mimic the bahavior of ICS, maybe we should give training data regularity. \n".format(repeat))
            f.write("  Frequent Pattern Least Length = {}  # The least length required for FP. \n".format(length_req)) 
            f.write("  Frequent Pattern Least Support = {}  # The least support required for FP. \n".format(freq_req))  
            f.write("  Shortened length of payload = {}  # The shortened length of payload for efficient Frequent Pattern. \n".format(lenLimit))
            f.write("  Cluster Boundary Threshold = {}  # An unknown point with distance higher that CBT would be regarded as outlier. \n".format(thresh)) 

            f.write("-------------------------------\n")
            f.write("Normal Traffic File Validation Result:\n")
            f.write("\tAbnormal Count = {} [ {} : {} ]\n".format(abnormal_count_va, ph1_ab_va, ph2_ab_va) )
            f.write("\tNormal Count = {}\n".format(normal_count_va) )
            f.write("\tTotal Number of Packet = {}\n".format(total_count_va) )
            f.write("\t\tAbnormal Rate = {}\n".format(abnormal_count_va/total_count_va) )

            f.write("-------------------------------\n")
            f.write("Abnormal Traffic File Test Result:\n")
            f.write("\tAbnormal Count = {} [ {} : {} ]\n".format(abnormal_count, ph1_ab, ph2_ab) )
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

            f.write("\t{:<50}  # TP/TP+FN\n".format("True Positive Rate = " + str(recall) ) )
            f.write("\t{:<50}  # FP/FP+TN\n".format("False Positive Rate = " + str(abnormal_count_va/total_count_va) ) )
            f.write("\t{:<50}  # TN/FP+TN\n".format("True Negative Rate = " + str(coverage) ) )
            f.write("\t{:<50}  # FN/TP+FN\n".format("False Negative Rate = " + str(normal_count/total_count) ) )
            f.write("\t{:<50}  # TP/TP+FP\n".format("Precision = " + str(precision) ) )
            f.write("\t{:<50}  # TP+TN/TP+TN+FP+FN\n".format("Accuracy = " + str(accuracy) ) )
            f.write("\n")
            f.write("\t{:<50}  # Correctly_classified_normal_packets / Total_normal_packets\n".format("Coverage = " + str(coverage) ) )
            f.write("\t{:<50}  # Correctly_classified_test_packets / Total_test_packets\n".format("Accuracy = " + str(accuracy) ) )
            f.write("====================================\n")
            f.close()
                
            
            if p == 0:         
                length_req += 2      # length_req # 5  [2-11]

            elif p == 1:
                freq_req += 2        # freq_req # 5  [3-41]

            elif p == 2:
                thresh += 0.05        # thresh # 0.2  [0.1-0.55]

            elif p == 3:
                repeat += 2          # repeat # 1 [1-5]
                freq_req = repeat*2

        av_precision = av_precision / iteration
        av_accuracy = av_accuracy / iteration
        av_recall = av_recall / iteration
        av_coverage = av_coverage / iteration
        av_FP_rate = av_FP_rate / iteration
        summary['av_precision'].append(av_precision)
        summary['av_accuracy'].append(av_accuracy)
        summary['av_recall'].append(av_recall)
        summary['av_coverage'].append(av_coverage)
        summary['av_FP_rate'].append(av_FP_rate)
        f = open(ExperimentOutFile, 'a', encoding='utf-8')
        f.write("\t{:<30}  \n".format("Average precision = " + str(av_precision) ) )
        f.write("\t{:<30}  \n".format("Average Accuracy = " + str(av_accuracy) ) )
        f.write("====================================\n")
        f.close()
        if p == 1:         
            length_req += 1

    f_sum = open(SummaryOutFile, 'a', encoding='utf-8')
    f_sum.write(str(summary))
    f_sum.close()



    
