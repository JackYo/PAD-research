import numpy as np
import matplotlib.pyplot as plt

for t in [3]:
    if t == 0:
        title = 'Modbus Normal Packets Classification'
    elif t == 1:
        title = 'Modbus Abnormal Packets Classification'
    elif t == 2:
        title = 'Modbus Testing Performance'
    elif t == 3:
        title = 'Bacnet Testing Performance'
    elif t == 4:
        title = 'Modbus Direct Clustering Performance'
        f_sum_ano = open("./output/AS_check/modbus/another_test/modbus_summary", 'r', encoding='utf-8')
        summary_ano = eval(f_sum_ano.readlines()[0])
        f_sum_ano.close()
    elif t == 5:
        title = 'Bacnet Direct Clustering Performance'
        f_sum_ano = open("./output/AS_check/bacnet/another_test/bacnet_summary", 'r', encoding='utf-8')
        summary_ano = eval(f_sum_ano.readlines()[0])
        f_sum_ano.close()

    for p in [2]:  
        if p == 0:
            ExperimentParam = "FPLL" # Frequent Pattern Least Length

        elif p == 1:
            ExperimentParam = "FPLS" # Frequent Pattern Least Support

        elif p == 2:
            ExperimentParam = "CBT"  # Cluster Boundary Threshold

        SummaryOutFile = "./output/summary/0605_bacnet_summary_param_" + ExperimentParam
        f_sum = open(SummaryOutFile, 'r', encoding='utf-8')
        summary = eval(f_sum.readlines()[0])
        f_sum.close()

        X = summary['X']

        plt.figure(p)                # the first figure
        plt.title(title)
        plt.xlabel(summary['X_label'])
        
        # plt.plot(311)             # the first subplot in the first figure
        if t == 0:
            plt.axhline(y=374, linewidth=4, color='k')
            plt.plot(X, summary['abnormal_count_va'], linewidth=1.5, marker='o', color='r', label='total')
            plt.plot(X, summary['ph1_ab_va'], linewidth=1, marker='s', color='b', label='phase 1')
            # plt.plot(312)             # the second subplot in the first figure
            plt.plot(X, summary['ph2_ab_va'], linewidth=1, marker='^', color='g', label='phase 2')
            # plt.plot(313)             # the second subplot in the first figure
            

            plt.ylabel('Abnormal (False Classification)')

        elif t == 1:
            plt.axhline(y=157, linewidth=4, color='k')
            plt.plot(X, summary['abnormal_count'], linewidth=1.5, marker='o', color='r', label='total')
            plt.plot(X, summary['ph1_ab'], linewidth=1, marker='s', color='b', label='phase 1')
            # plt.plot(312)             # the second subplot in the first figure
            plt.plot(X, summary['ph2_ab'], linewidth=1, marker='^', color='g', label='phase 2')
            # plt.plot(313)             # the second subplot in the first figure
            

            plt.ylabel('Abnormal (Correct Classification)')

        elif t == 2:
            # axes = plt.gca()
            # axes.set_ylim([0,1])
            plt.subplot(211)
            plt.axhline(y=0, linewidth=1, color='k')
            plt.axhline(y=1, linewidth=1, color='k')   
            plt.plot(X, summary['accuracy'], linewidth=2, marker='o', color='b', label='accuracy')
            plt.plot(X, summary['FP_rate'], linewidth=2, marker='s', color='r', label='false alarm')
            plt.plot(X, summary['precision'], linewidth=2, marker='^', color='g', label='precision')
            plt.plot(X, summary['recall'], linewidth=2, marker='>', color='c', label='recall')

            plt.ylabel('ratio')
            plt.legend()

            plt.subplot(212)
            axes = plt.gca()
            axes.set_ylim([0,400])
            max_clu_cnt = max(summary['clusterCnt'])
            min_clu_cnt = min(summary['clusterCnt'])
            # plt.axhline(y=min_clu_cnt, linewidth=1, color='k')
            # plt.axhline(y=max_clu_cnt, linewidth=1, color='k')
            axes.text(0.05, 350, u'max:' + str(max_clu_cnt))
            axes.text(0.05, 300, u'min:' + str(min_clu_cnt))
            # axes.annotate(str(max_clu_cnt), xy=(0.05, max_clu_cnt), xytext=(0.1, 10), arrowprops=dict(facecolor='black', shrink=0.05))
            # axes.annotate(str(max_clu_cnt), xy=(0.05, max_clu_cnt), xytext=(0.1, 10), arrowprops=dict(facecolor='black', shrink=0.05))
            # plt.yticks([0, max(summary_ano['clusterCnt'])])
            plt.plot(X, summary['clusterCnt'], linewidth=2, marker='1', color='m', label='cluster amount')
            plt.ylabel('quantity')
            plt.xlabel('Cluster Boundary Threshold')

        elif t == 3:
            axes = plt.gca()
            axes.set_ylim([0,1])
            plt.subplot(211)

            plt.plot(X, summary['accuracy'], linewidth=2, marker='o', color='b', label='accuracy')
            plt.plot(X, summary['FP_rate'], linewidth=2, marker='s', color='r', label='false alarm')
            plt.plot(X, summary['precision'], linewidth=2, marker='^', color='g', label='precision')
            plt.plot(X, summary['recall'], linewidth=2, marker='>', color='c', label='recall')

            plt.ylabel('ratio')
            plt.legend()

            plt.subplot(212)
            axes = plt.gca()
            axes.set_ylim([0,300])
            # plt.axhline(y=min(summary_ano['clusterCnt']), linewidth=1, color='k')
            # plt.axhline(y=max(summary_ano['clusterCnt']), linewidth=1, color='k')
            # plt.yticks([0, max(summary_ano['clusterCnt'])])
            plt.plot(X, summary['clusterCnt'], linewidth=2, marker='1', color='m', label='cluster amount')
            plt.ylabel('quantity')
            plt.xlabel('Cluster Boundary Threshold')

        elif t == 4:
            axes = plt.gca()
            axes.set_ylim([0,1])
            
            X = [(0.05 + 0.05*k) for k in range(0,10)]
            plt.subplot(211)
            plt.axhline(y=0, linewidth=1, color='k')
            plt.axhline(y=1, linewidth=1, color='k')            
            plt.plot(X, summary_ano['accuracy'], linewidth=2, marker='o', color='b', label='accuracy')
            plt.plot(X, summary_ano['FP_rate'], linewidth=2, marker='s', color='r', label='false alarm')
            plt.plot(X, summary_ano['precision'], linewidth=2, marker='^', color='g', label='precision')
            plt.plot(X, summary_ano['recall'], linewidth=2, marker='>', color='c', label='recall')
            plt.ylabel('ratio')
            plt.legend()

            plt.subplot(212)
            axes = plt.gca()
            axes.set_ylim([0,300])
            # plt.axhline(y=min(summary_ano['clusterCnt']), linewidth=1, color='k')
            # plt.axhline(y=max(summary_ano['clusterCnt']), linewidth=1, color='k')
            # plt.yticks([0, max(summary_ano['clusterCnt'])])
            plt.plot(X, summary_ano['clusterCnt'], linewidth=2, marker='1', color='m', label='cluster amount')
            plt.ylabel('quantity')
            plt.xlabel('Cluster Boundary Threshold')
        
        elif t == 5:
            axes = plt.gca()
            axes.set_ylim([0,1])
            
            X = [(0.05 + 0.05*k) for k in range(0,10)]
            plt.subplot(211)
            plt.axhline(y=0, linewidth=1, color='k')
            plt.axhline(y=1, linewidth=1, color='k')  
            plt.plot(X, summary_ano['accuracy'], linewidth=2, marker='o', color='b', label='accuracy')
            plt.plot(X, summary_ano['FP_rate'], linewidth=2, marker='s', color='r', label='FP rate')
            plt.plot(X, summary_ano['precision'], linewidth=2, marker='^', color='g', label='precision')
            plt.plot(X, summary_ano['recall'], linewidth=2, marker='>', color='c', label='TP rate')
            plt.ylabel('ratio')
            plt.legend()

            plt.subplot(212)
            axes = plt.gca()
            axes.set_ylim([0,300])
            plt.plot(X, summary_ano['clusterCnt'], linewidth=2, marker='1', color='m', label='cluster amount')

            plt.ylabel('quantity')
            plt.xlabel('Cluster Boundary Threshold')
        # y1 = [0.967984934086629 , 0.9303201506591338 , 0.911487758945386 , 0.911487758945386 , 0.911487758945386 , 0.911487758945386 , 0.911487758945386 , 0.8813559322033898 , 0.8286252354048964 , 0.615819209039548]
        # red dashes, blue squares and green triangles
        # plt.plot(t, t, 'r--', t, t**2, 'bs', t, t**3, 'g^')
        # plt.plot(x1, y1, linewidth=1, linestyle='bs--', x1, y2, linewidth=1, linestyle='g^--', x1, y3, linewidth=1, linestyle='ro-')
        # plt.axis([0, 6, 0, 20])
        
        

        plt.legend()

        plt.show()
    


# summary['abnormal_count'] = list()
# summary['normal_count'] = list()
# summary['total_count'] = list()
# summary['abnormal_count_va'] = list()
# summary['normal_count_va'] = list()
# summary['total_count_va'] = list()
# summary['coverage'] = list()
# summary['accuracy'] = list()
# summary['av_coverage_count'] = 0.0
# summary['av_accuracy_count'] = 0.0
# summary['av_coverage'] = av_coverage
# summary['av_accuracy'] = av_accuracy
# summary['ph1_ab'] = list()
# summary['ph2_ab'] = list()
# summary['ph1_ab_va'] = list()
# summary['ph2_ab_va'] = list()