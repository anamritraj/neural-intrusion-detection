import pandas as pd
import numpy as np

import matplotlib
matplotlib.use("TkAgg")

import matplotlib.pyplot as plt
import tensorflow as tf

# For Live graphs
import matplotlib.animation as animation
from matplotlib import style


dataframe = pd.read_csv('kddcup.10')

# Data Selection
dataframe = dataframe[0:494021]


inputX =  dataframe.loc[:,[
						  'protocol_type',
						  'duration',
						  'src_bytes',
						  'dst_bytes',
						  'wrong_fragment',
						  'hot',
						  'num_compromised',
						  'root_shell',
						  'su_attempted',
						  'num_root',
						  'num_file_creations',
						  'num_shells',
						  'num_access_files',
						  'num_outbound_cmds',
						  'service',
						  'land',
						  'count',
						  'srv_count',
						  'urgent',
						  'same_srv_rate',
						  'diff_srv_rate',
						  'srv_diff_host_rate']].as_matrix()


# Converts a given service name to a data point numerical value which is consistent throughout the model.
def convert_service_to_data_point(s_name):
	
	services = ['http', 'smtp', 'finger', 'domain_u', 'auth', 'telnet', 'ftp', 'eco_i', 'ntp_u', 'ecr_i', 'other', 'private', 'pop_3', 'ftp_data', 'rje', 'time', 'mtp', 'link', 'remote_job', 'gopher', 'ssh', 'name', 'whois', 'domain', 'login', 'imap4', 'daytime', 'ctf', 'nntp', 'shell', 'IRC', 'nnsp', 'http_443', 'exec', 'printer', 'efs', 'courier', 'uucp', 'klogin', 'kshell', 'echo', 'discard', 'systat', 'supdup', 'iso_tsap', 'hostnames', 'csnet_ns', 'pop_2', 'sunrpc', 'uucp_path', 'netbios_ns', 'netbios_ssn', 'netbios_dgm', 'sql_net', 'vmnet', 'bgp', 'Z39_50', 'ldap', 'netstat', 'urh_i', 'X11', 'urp_i', 'pm_dump', 'tftp_u', 'tim_i', 'red_i']

	if s_name in services:
		# Assumed port number for 'other'
		return services.index(s_name)
	else:
		return services.index('other')


# Convert a protocol to data point 
def convert_protocol_to_data_point(proto):
	if proto == 'tcp':
		return 6
	elif proto == 'udp':
		return 17
	elif proto == 'icmp':
		return 1


def preprocess_input(input_x):
	for x in input_x:
		#  Convert service names for each packet into data points
		x[1] = convert_service_to_data_point(x[1])
		# Convert protocol for each packet into data points
		x[0] = convert_protocol_to_data_point(x[0])
	return input_x
		

# ============================
# Data Preprocessing - inputX
# ============================
for x in inputX:
	#  Convert service names for each packet into data points
	x[1] = convert_service_to_data_point(x[1])
	# Convert protocol for each packet into data points
	x[0] = convert_protocol_to_data_point(x[0])


# ============================
# Data Preprocessing - InputY
# ============================

attacks = [
	'back',
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

# ======================
# Hyperparameters Setup
# ======================

parameters = {
	'learning_rate': 0.0001,
	'training_epochs': 250,
	'display_steps': 1,
	'n_features': inputX[0].size,
	'n_classes': inputY[0].size
}

# ========================
# CREATE COMPUTATION MODEL
# ========================


x = tf.placeholder(tf.float32, [None, parameters['n_features']])

# Initialize weights
W = tf.Variable(tf.zeros([parameters['n_features'], parameters['n_classes']]))

# Initialize biases
b = tf.Variable(tf.zeros([parameters['n_classes']]))

# Aply softmax activation function
y = tf.nn.softmax(tf.matmul(x, W) + b)

y_ = tf.placeholder(tf.float32, [None, parameters['n_classes']])

xpoints = []
ypoints = []

def train_and_save_model(inputX, inputY, parameters):
	# cost = tf.reduce_mean(-tf.reduce_sum(y_ * tf.log(y), reduction_indices=[1]))
	cost = tf.reduce_sum(tf.pow(y_ - y, 2)) / (2 * parameters['n_classes'])

	train_step = tf.train.AdamOptimizer(parameters['learning_rate']).minimize(cost)
	# Initiate tf saver
	saver = tf.train.Saver()
	# Model Path
	model_path = "./tmp_model_2/model.ckpt"

	# Starting Session
	sess = tf.InteractiveSession()
	tf.global_variables_initializer().run()

	for i in range(parameters['training_epochs']):
		sess.run(train_step, feed_dict={x:inputX, y_:inputY})
		cc = sess.run(cost, feed_dict={x:inputX, y_:inputY})
		if i % parameters['display_steps'] == 0:
			correct_prediction = tf.equal(tf.argmax(y,1), tf.argmax(y_,1))
			accuracy = tf.reduce_mean(tf.cast(correct_prediction, tf.float32))
			accuracy_percentage = sess.run(accuracy, feed_dict={x: inputX, y_: inputY})
			print("Training Step: ", "%04d" % (i), 'cost=', "{:.9f}".format(cc), "Accuracy: ",accuracy_percentage )
			xpoints.append(i)
			ypoints.append(accuracy_percentage * 100)




	print("Optimization Finished!")
	print(xpoints, ypoints)
	plt.plot(xpoints, ypoints)

	plt.xlabel('Epochs')
	plt.ylabel('Accuracy Percentage')
	plt.title("Model Accuracy vs No of Epochs")
	plt.legend()
	plt.show()
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
	save_path = train_and_save_model(inputX, inputY, parameters)
	print(predict_x)

	predict_x = dataframe.loc[397000:397100,[
						  'protocol_type',
						  'duration',
						  'src_bytes',
						  'dst_bytes',
						  'wrong_fragment',
						  'hot',
						  'num_compromised',
						  'root_shell',
						  'su_attempted',
						  'num_root',
						  'num_file_creations',
						  'num_shells',
						  'num_access_files',
						  'num_outbound_cmds',
						  'service',
						  'land',
						  'count',
						  'srv_count',
						  'urgent',
						  'same_srv_rate',
						  'diff_srv_rate',
						  'srv_diff_host_rate']].as_matrix()
	predict_x = preprocess_input(predict_x)
	predict_class(predict_x, './tmp_model_2/model.ckpt')

if __name__ == '__main__':
	main()