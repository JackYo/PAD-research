import numpy as np
import math
import sys

np.set_printoptions(threshold=np.inf)

def bitLenCount(int_type):
    # length = 0
    count = 0
    while (int_type):
        count += (int_type & 1)
        # length += 1
        int_type >>= 1
    return count

# def distance(point,centroid):
#     cummulator = 0
#     byte_diff_cnt =0
#     for i in range(0, len(point)):
#         if int(point[i]) != int(centroid[i]):
#             byte_diff_cnt += 1
#             temp = int(point[i])^int(centroid[i])
#             bit_diff_cnt = bitLenCount(temp)
#             cummulator = cummulator + bit_diff_cnt/8
#     cummulator = cummulator*byte_diff_cnt

#     # distance = math.sqrt(cummulator)
#     return cummulator

def distance(point,centroid):
    
    if len(centroid) != len(point):
        return 1

    byte_diff_cnt =0 
    for i in range(0, len(point)):
        if point[i] != centroid[i]:
            byte_diff_cnt += 1
    return byte_diff_cnt/len(point)

def new_centroid(points):
    min_dist = sys.maxsize
    min_point_index = 0
    points_cnt = len(points)
    radius_array = np.zeros((points_cnt, ), dtype=float)
    dist_array = np.zeros((points_cnt, points_cnt), dtype=float)

    for i in range(0, points_cnt):
        for j in range(i+1, points_cnt):
            dist_array[i][j] = distance(points[i], points[j])

    for i in range(0, points_cnt):
        temp_dist = 0
        temp_radius = 0
        for j in range(0, points_cnt):
            if i > j:
                temp_dist += dist_array[j][i]
                if temp_radius < dist_array[j][i]:
                    temp_radius = dist_array[j][i]
            else:
                temp_dist += dist_array[i][j]
                if temp_radius < dist_array[i][j]:
                    temp_radius = dist_array[i][j]
        radius_array[i] = temp_radius
        if temp_dist < min_dist:
            min_dist = temp_dist
            min_point_index = i

    # av_dist = min_dist/(points_cnt-1)
    return (radius_array[min_point_index], points[min_point_index])

def average(points):
    cen = [0]*len(points[0])
    for i in range(0, len(points[0])):
        cen[i] = 0
        for j in range(0, len(points)):
            cen[i] = cen[i] + points[j][i]

        cen[i] = cen[i]/len(points)

    return cen

def clustering(data, ruleid, pro_name, threshold):
    size = len(data)
    # temp_cen = data[0]
    clusters = list()
    clu_centroids = list()
    connectivity_m = np.zeros((size,size), dtype=bool)
    distance_m = np.zeros((size,size), dtype=float)
    
    # connectivity_m initialization
    for i in range(0,size):
        connectivity_m[i][i] = 1
    
    # distance_m initialization
    # closest = 1
    # min_i = 0
    # min_j = 0
    for i in range(0,size):
        for j in range(i+1,size):
            dist = distance(data[i],data[j])
    #         if dist < closest:
    #             closest = dist
    #             min_i = i
    #             min_j = j
            distance_m[i][j] = dist
            distance_m[j][i] = dist
    
    # # first iteration
    # connectivity_m[min_i][min_j] = 1
    # connectivity_m[min_j][min_i] = 1
    # for j in range(0,size):
    #     maxi_dist = distance_m[j][min_i]
    #     if maxi_dist < distance_m[j][min_j]:
    #         distance_m[j][min_i] = distance_m[j][min_j]
    #         distance_m[min_i][j] = distance_m[j][min_j]
    #     else:
    #         distance_m[j][min_j] = maxi_dist
    #         distance_m[min_j][j] = maxi_dist

    # start remaining iteration
    # count = 0
    for iteration in range(0,size-1):
        closest = 1.1
        min_i = 0
        min_j = 0
        
        # find the shortest distance
        for i in range(0,size):
            for j in range(i+1,size):
                if connectivity_m[i][j] != True:
                    # count += 1
                    dist = distance_m[i][j]
                    if dist < closest:
                        closest = dist
                        min_i = i
                        min_j = j
        if closest <= threshold:   
            # print("[{},{}] closest={}\n".format(min_i, min_j, closest) )
            # update distance_m and connectivity
            # clu_set = set()
            # maxi_dist = 0
            for k in range(0,size):
                if (connectivity_m[min_i][k] == 1):
                    for t in range(0,size):
                        if (connectivity_m[min_j][t] == 1):
                            # if connectivity_m[k][t] == 0:
                                # count += 1
                            connectivity_m[k][t] = 1
                            connectivity_m[t][k] = 1
            for k in range(0,size):
                if (connectivity_m[min_i][k] == 0):
                    if distance_m[min_i][k] < distance_m[min_j][k]:
                        for e in range(0,size):
                            if (connectivity_m[min_i][e] == 1):
                                distance_m[e][k] = distance_m[min_j][k]
                                distance_m[k][e] = distance_m[min_j][k]
                    # elif distance_m[min_i][k] > distance_m[min_j][k]:
                    else:
                        for e in range(0,size):
                            if (connectivity_m[min_j][e] == 1):
                                distance_m[e][k] = distance_m[min_i][k]
                                distance_m[k][e] = distance_m[min_i][k]
        # else:
            # break
        # print("count {}".format(count))                 # largest: 69751
        # print("closest {}".format(closest))             # largest: 1
        
            
        
        # # maxi_dist = 0
        # for k in range(0,size):
        #     if (connectivity_m[min_i][k] == 1):
        #         connectivity_m[min_j][k] = 1
        #         connectivity_m[k][min_j] = 1
        #         # clu_set.add(k)
        #     else:
        #         if distance_m[min_i][k] < distance_m[min_j][k]:
        #             for e in range(0,size):
        #                 if (connectivity_m[min_i][e] == 1):
        #                     distance_m[e][k] = distance_m[min_j][k]
        #                     distance_m[k][e] = distance_m[min_j][k]
        #         elif distance_m[min_i][k] > distance_m[min_j][k]:
        #             distance_m[min_j][k] = distance_m[min_i][k]
        #             distance_m[k][min_j] = distance_m[min_i][k]

            
    # clu_centroids = list()
    # clu_centroids.append(temp_cen)
    # cen_index = 0
    # for d in data:
    #     closest = sys.maxsize

    #     for index, c in enumerate(clu_centroids):
    #         dis = distance(d, c)
    #         if dis < closest:
    #             closest = dis
    #             cen_index = index        
        
    #     if closest <= threshold:
    #         clusters[cen_index].append(d)
    #         min_point_index = new_centroid(clusters[cen_index])
    #         clu_centroids[cen_index] = clusters[cen_index][min_point_index]
    #     else:
    #         clu_centroids.append(d)
    #         clusters.append([d])
    
    next_set = set([ i for i in range(0,size)])
    clu_index = 0
    # connectivity_a = connectivity_m
    while bool(next_set):
        
        clusters.append(list())
        cut_set = set()
        i = next(iter(next_set))
        for j in next_set:
            if (connectivity_m[i][j] == 1):
                clusters[clu_index].append(data[j])
                cut_set.add(j)
        for i in cut_set:
            next_set.remove(i)
        clu_index += 1

    for points in clusters:
        cen = new_centroid(points)
        clu_centroids.append(cen)

    # file_name = "./output/debug/" + pro_name + "_connectivity_debug_" + str(ruleid)
    # with open(file_name, 'w', encoding='utf-8') as f:
    #     f.write("RuleID [{}]:\n".format(ruleid))
    #     f.write(" {}\n".format(connectivity_m))

    # file_name = "./output/debug/" + pro_name + "_distance_debug_" + str(ruleid)
    # with open(file_name, 'w', encoding='utf-8') as f:
    #     f.write("RuleID [{}]:\n".format(ruleid))
    #     f.write(" {}\n".format(distance_m))
        

    file_name = "./output/debug/" + pro_name + "_cluster_debug_" + str(ruleid)
    with open(file_name, 'w', encoding='utf-8') as f:
        f.write("RuleID [{}]:\n".format(ruleid))
        for index, clus in enumerate(clusters):
            f.write(" Cluster [{}]:\n".format(index))
            for point in clus:
                f.write("  {}\n".format(point))
    # print(clusters)
    # print(clu_centroids)
    return clu_centroids