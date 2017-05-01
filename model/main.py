import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import tensorflow as tf

dataframe = pd.read_csv('kddcup.10')

# Data Selection
dataframe = dataframe[0:494021]

predict_x = dataframe.loc[397000:397100,['src_bytes',
                          'dst_bytes',
                          'count',
                          'srv_count',
                          'dst_host_srv_count',
                          'dst_host_same_src_port_rate',
                          'dst_host_srv_diff_host_rate',
                          'dst_host_serror_rate',
                          'dst_host_srv_serror_rate',
                          'dst_host_rerror_rate',
                          'dst_host_srv_rerror_rate']].as_matrix()

inputX =  dataframe.loc[:,['src_bytes',
                          'dst_bytes',
                          'count',
                          'srv_count',
                          'dst_host_srv_count',
                          'dst_host_same_src_port_rate',
                          'dst_host_srv_diff_host_rate',
                          'dst_host_serror_rate',
                          'dst_host_srv_serror_rate',
                          'dst_host_rerror_rate',
                          'dst_host_srv_rerror_rate']].as_matrix()

attacks = ['back',
			'buffer_overflow',
			'ftp_write',
			'guess_passwd',
			'imap',
			'ipsweep',
			'land',
			'loadmodule',
			'multihop',
			'neptune',
			'nmap',
			'normal',
			'perl',
			'phf',
			'pod',
			'portsweep',
			'rootkit',
			'satan',
			'smurf'
		]
attack_ids = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18]
attack_dict = dict(zip(attacks, attack_ids))

dataframe['label']=dataframe['label'].map(lambda x : str(x)[:-1])
dataframe['label'] = dataframe['label'].map(attack_dict)

# Integer labels
tempInputY = dataframe['label']

# Input of labels, encoded as one hot input
inputY = []

for inY in tempInputY:
	lst = []
	for y_id in range(0, len(attacks)):
		if inY == y_id:
			lst.append(1)
		else:
			lst.append(0)
	inputY.append(lst)
# Convert one hot list to one hot array of labels
inputY = np.array(inputY)

# Hyperparameters Setup

parameters = {
'learning_rate': 0.0001,
'training_epochs': 70,
'display_steps': 1,
'n_features': inputX[0].size,
'n_classes': inputY[0].size
}

# =======================================================
# CREATE COMPUTATION MODEL
# =======================================================


x = tf.placeholder(tf.float32, [None, parameters['n_features']])

# Initialize weights
W = tf.Variable(tf.zeros([parameters['n_features'], parameters['n_classes']]))

# Initialize biases
b = tf.Variable(tf.zeros([parameters['n_classes']]))

# Aply softmax activation function
y = tf.nn.softmax(tf.matmul(x, W) + b)

y_ = tf.placeholder(tf.float32, [None, parameters['n_classes']])



def train_and_save_model(inputX, inputY, parameters):
	# cost = tf.reduce_mean(-tf.reduce_sum(y_ * tf.log(y), reduction_indices=[1]))
	cost = tf.reduce_sum(tf.pow(y_ - y, 2)) / (2 * parameters['n_classes'])

	train_step = tf.train.AdamOptimizer(parameters['learning_rate']).minimize(cost)
	# Initiate tf saver
	saver = tf.train.Saver()
	# Model Path
	model_path = "./tmp/model.ckpt"

	# Starting Session
	sess = tf.InteractiveSession()
	tf.global_variables_initializer().run()

	for i in range(parameters['training_epochs']):
	    sess.run(train_step, feed_dict={x:inputX, y_:inputY})
	    cc = sess.run(cost, feed_dict={x:inputX, y_:inputY})
	    if i % parameters['display_steps'] == 0:
		    correct_prediction = tf.equal(tf.argmax(y,1), tf.argmax(y_,1))
		    accuracy = tf.reduce_mean(tf.cast(correct_prediction, tf.float32))
		    print("Training Step: ", "%04d" % (i), 'cost=', "{:.9f}".format(cc), "Accuracy: ", sess.run(accuracy, feed_dict={x: inputX, y_: inputY}))

	print("Optimization Finished!")
	# training_cost = sess.run(cost, feed_dict={x:inputX, y_:inputY})
	# print("Training cost= ", training_cost, " W=", sess.run(W), " b=", sess.run(b))

	save_path = saver.save(sess, model_path)
	print("Model saved in file: %s" % save_path)
	return save_path


def predict_class(input_x, save_path):
	sess = tf.InteractiveSession()
	saver = tf.train.Saver()

	saver.restore(sess, save_path)
	print("Model restored from file: %s" % save_path)
	
	feed_dict = {x: input_x}
	classification = list(sess.run(y, feed_dict))
	# print(classification)
	for c in classification:
		c = list(c)
		print(attacks[c.index(max(c))])

def main():
	# save_path = train_and_save_model(inputX, inputY, parameters)
	predict_class(predict_x, './tmp/model.ckpt')

main()