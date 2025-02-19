from hier_cluster import clustering

def second_phase(susSaveDir, clusterCenSaveDir, thresh=1, protocol_name='pro'):
    print("Now training second model...")
    rule_seqs = dict()

    with open(susSaveDir, 'r', encoding='utf-8') as f:
        for i in f:
            if (i in ['\n', '\r\n', ' ']) or (i[0] == '#'):   
                break
            data = eval(i)
            id = data['rule_ID']
                
            if data['Rseq'] is not None: 
                remseq = [0]* len(data['Rseq'])
                for j in range(0,len(data['Rseq'])):
                    remseq[j] = int(data['Rseq'][j],16)

                if rule_seqs.get(id) is None:
                    rule_seqs[id] = list()
                rule_seqs[id].append(remseq)
            else:
                rule_seqs[id] = None
            
    # remseq_f = open(remSusSaveDir, 'w', encoding='utf-8')
    # for ruleid, remseq in rule_seqs.items():
    #     remseq_f.write("{}: {}\n".format(ruleid, remseq))

    # remseq_f.close()
    clusterCnt = 0
    output_file = open(clusterCenSaveDir, 'w', encoding='utf-8')
    for ruleid, remseqs in rule_seqs.items():
               
        if remseqs is not None:
            print("\truning clustering... [{}]".format(ruleid))
            results = clustering(remseqs,ruleid, protocol_name,threshold=thresh)
            print("\tclustering finished.")
        
            # output_file.write("# [{}]\n".format(ruleid))
            # for clu in results:
            #     output_file.write("{}\n".format(clu))
            output_file.write("{}: {} \n# Centroids number = {}\n".format(ruleid,results, len(results)))
            clusterCnt += len(results)
        
        else:
            output_file.write("{}: None \n# No remaining part.\n".format(ruleid))

    output_file.close()
    print("second model finished. \n==============")
    return clusterCnt