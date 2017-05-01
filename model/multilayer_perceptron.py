import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import tensorflow as tf

dataframe = pd.read_csv('kddcup.10')

# Data Selection
dataframe = dataframe[0:494021]

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


# Parameters
learning_rate = 0.0003
training_epochs = 1500000
batch_size = 10000
display_step = 1

# Network Parameters
n_hidden_1 = 11# 1st layer number of features
n_hidden_2 = 11 # 2nd layer number of features
# n_hidden_3 = 11 # 2nd layer number of features
n_input = 11 # MNIST data input (img shape: 28*28)
n_classes = 19 

# tf Graph input
x = tf.placeholder("float", [None, n_input])
y = tf.placeholder("float", [None, n_classes])

def multilayer_perceptron(x, weights, biases):
	# Hidden layer with RELU activation
	layer_1 = tf.add(tf.matmul(x, weights['h1']), biases['b1'])
	layer_1 = tf.nn.relu(layer_1)
	# Hidden layer with RELU activation
	layer_2 = tf.add(tf.matmul(layer_1, weights['h2']), biases['b2'])
	layer_2 = tf.nn.relu(layer_2)
	
	# layer_3 = tf.add(tf.matmul(layer_2, weights['h3']), biases['b3'])
	# layer_3 = tf.nn.relu(layer_3)
	
	# Output layer with linear activation
	out_layer = tf.matmul(layer_2, weights['out']) + biases['out']
	return out_layer

# Store layers weight & bias
weights = {
	'h1': tf.Variable(tf.random_normal([n_input, n_hidden_1])),
	'h2': tf.Variable(tf.random_normal([n_hidden_1, n_hidden_2])),
	# 'h3': tf.Variable(tf.random_normal([n_hidden_2, n_hidden_3])),
	'out': tf.Variable(tf.random_normal([n_hidden_2, n_classes]))
}
biases = {
	'b1': tf.Variable(tf.random_normal([n_hidden_1])),
	'b2': tf.Variable(tf.random_normal([n_hidden_2])),
	# 'b3': tf.Variable(tf.random_normal([n_hidden_3])),
	'out': tf.Variable(tf.random_normal([n_classes]))
}

# Construct model
pred = multilayer_perceptron(x, weights, biases)

# Define loss and optimizer
cost = tf.reduce_mean(tf.nn.softmax_cross_entropy_with_logits(logits=pred, labels=y))
optimizer = tf.train.AdamOptimizer(learning_rate=learning_rate).minimize(cost)

# Initializing the variables
init = tf.global_variables_initializer()


# Get Next batch of input
def get_next_batch(start, batch_size):
	return inputX[start:batch_size], inputY[start:batch_size]

# Launch the graph
with tf.Session() as sess:
	sess.run(init)

	# Training cycle
	for epoch in range(training_epochs):
		avg_cost = 0
		# total_batches = int(inputX[:-10000].size/batch_size)
		# Loop over all batches
		# for i in range(0, total_batches):
		#     batch_x, batch_y = get_next_batch(i * batch_size, batch_size)
			
			# Run optimization op (backprop) and cost op (to get loss value)
		_, c = sess.run([optimizer, cost], feed_dict={x: inputX[0:480000],
													  y: inputY[0:480000]})
		# Compute average loss
		avg_cost = (c)
		# print("Avregae Cost ", avg_cost)
			# exit(0)
		# Display logs per epoch step
		if epoch % display_step == 0:

			# Test model
			correct_prediction = tf.equal(tf.argmax(pred, 1), tf.argmax(y, 1))
			# Calculate accuracy
			accuracy = tf.reduce_mean(tf.cast(correct_prediction, "float"))
			print ("Epoch:", '%04d' % (epoch+1), "cost=", "{:.9f}".format(avg_cost), " Accuracy: ", accuracy.eval({x: inputX[:-10000], y: inputY[:-10000]}))
	print ("Optimization Finished!")
