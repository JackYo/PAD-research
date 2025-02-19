
FIS_f = open("./output/AS_check/modbus/random_test/FIS/modbus_AS_check_FIS", 'r', encoding='utf-8')

for line in FIS_f:
    if (line in ['\n', '\r\n', ' ']) or (line[0] == '#'):    
        continue
    sid = eval(line[0:7])
    fis = eval(line[8:])
    print(sid)
    print(fis)
    


