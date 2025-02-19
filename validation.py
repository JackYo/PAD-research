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

FPSaveDir = "./data/normal_data/FP_rule/modbus_AS_test.txt"

# abnormalSaveDir = "./output/AS_check/modbus/random_test/modbus_AS_check_ab_sig_validation"
# susSaveDir = "./output/AS_check/modbus/random_test/modbus_AS_check_sus_seq_validation"
# summarySaveDir = "./output/AS_check/modbus/random_test/modbus_AS_check_sum_validation"
# pcapFilename = "./data/test_data/modbus/random_test/4SICS_modbus_test0.pcap"
# AS_check(pcapFilename, abnormalSaveDir, susSaveDir, summarySaveDir, FPSaveDir, debug=False)

# abnormalSaveDir = "./output/AS_check/modbus/random_test/modbus_AS_check_ab_sig_test"
# susSaveDir = "./output/AS_check/modbus/random_test/modbus_AS_check_sus_seq_test"
# summarySaveDir = "./output/AS_check/modbus/random_test/modbus_AS_check_sum_test"
# pcapFilename = "./data/test_data/modbus/modbus_test_data_spec.pcap"
# AS_check(pcapFilename, abnormalSaveDir, susSaveDir, summarySaveDir, FPSaveDir)

FPSaveDir = "./data/normal_data/FP_rule/modbus_AS_test.txt"
summarySaveDir = "./output/AS_check/modbus/test/modbus_final_check_sum"
pcapFilename = "./data/test_data/modbus/modbus_test_data_spec.pcap"
total_check(pcapFilename,summarySaveDir,FPSaveDir,clusterBound=10)

