from apyori import apriori,dump_as_json
from apyori import RelationRecord
from apyori import load_transactions

print("Now training second model...")
rule_seqs = dict()
setlist_f = open("./output/AS_check/modbus/random_test/FIS/modbus_AS_check_setlist", 'w', encoding='utf-8')
with open("./output/AS_check/modbus/random_test/modbus_AS_check_sus_seq", 'r', encoding='utf-8') as f:
    for i in f:
        if (i in ['\n', '\r\n', ' ']) or (i[0] == '#'):
            
            break
        noItem = True
        data = eval(i)
        id = data['rule_ID']
            
        
        itemset = set()
        if data['Lseq'] is not None: 
            for item in data['Lseq']:
                itemset.add(item) 
                noItem = False
        if data['Rseq'] is not None: 
            for item in data['Rseq']:
                itemset.add(item) 
                noItem = False
        if not noItem:
            if rule_seqs.get(id) is None:
                rule_seqs[id] = list()
            rule_seqs[id].append(list(itemset)[0:10])

for ruleid, setli in rule_seqs.items():
    setlist_f.write("{}: {}\n".format(ruleid, setli))

setlist_f.close()

output_file = open("./output/AS_check/modbus/random_test/FIS/modbus_AS_check_FIS", 'w', encoding='utf-8')
for ruleid, setli in rule_seqs.items():
    
    transactions = setli
    my_min_support = 0.2
    my_min_confidence = 1

    print("\truning apriori... [{}]".format(ruleid))
    results = list(apriori(transactions, min_support=my_min_support, min_confidence=my_min_confidence))  
    print("\tapriori finished.")

    for i in results:   
        output_file.write("{}: ".format(ruleid))
        dump_as_json(i,output_file)

output_file.close()
print("second model finished.")