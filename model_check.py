#! /usr/bin/env python

import tensorflow as tf
import numpy as np
import os
import time
import datetime

# Parameters
# ==================================================
data_file = "./output/AS_check/modbus_AS_check_normal_subseq"

# Data Preparation
# ==================================================

# # Load data
print("Loading data...")

sequence_length = 260

def hexi_string_get(data_file):
    test_data = list(open(data_file, "r", encoding='utf-8').readlines())
    test_data = [eval(s) for s in test_data]

    return test_data

# Load test data
x_hexi_string = hexi_string_get(data_file)

# for sequence in x_hexi_string:
#     if len(sequence) > sequence_length:
#         sequence_length = len(sequence)

x = np.full( (len(x_hexi_string) ,sequence_length), 0)

# print("x_hexi_string = {}".format(x_hexi_string))
for i in range(0, len(x_hexi_string)):
    for j in range(0, len(x_hexi_string[i])):
        x[i][j] = int(x_hexi_string[i][j], 16)

x_test = np.uint8(x)

def hexi_string_transfer(binary_strings):
    output = np.expand_dims(binary_strings, axis=2)
    output = np.unpackbits(output, axis=2)
    
    return output
x_test = hexi_string_transfer(x_test)
# print("x = {}".format(x))

with tf.Session() as sess:
    new_saver = tf.train.import_meta_graph('./runs/1525518508/checkpoints/model-1000.meta')   
    new_saver.restore(sess, tf.train.latest_checkpoint('./runs/1525518508/checkpoints'))
    graph = tf.get_default_graph()
    input_x = graph.get_tensor_by_name("input_x:0")
    dropout_keep_prob = graph.get_tensor_by_name("dropout_keep_prob:0")
    #f = open('./operations', 'w', encoding='utf-8')
    #f.write(str(graph.get_operations()))
    #predictions = graph.get_tensor_by_name("predictions:0")
    predictions = graph.get_tensor_by_name("output/predictions:0")
    feed_dict = { 
        input_x: x_test ,
        dropout_keep_prob: 0.5
    }
    out = sess.run([predictions], feed_dict)
    print("predictions {}".format(out ))
    
