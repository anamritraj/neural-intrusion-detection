# Neural Network Intrusion Detection

## Synopsis

Intrusion detection systems are an important part of a computer network. The proposed model aims to solve the problem of classifying packets based on the network traffic captured using a softmax regression model trained on Tensorflow.

## Installation

### Install [Tensorflow](https://www.tensorflow.org/install/install_linux#InstallingAnaconda)
	
`conda create -n tensorflow python=3.6`
`source activate tensorflow`
`pip install --ignore-installed --upgrade https://storage.googleapis.com/tensorflow/linux/cpu/tensorflow-1.1.0-cp36-cp36m-linux_x86_64.whl`
		

### Clone this repository

**Assuming you have `git` already installed.**

`git clone http://github.com/anamritraj/neural-network-intrusion-detection.git`

### Dependencies

- pandas
- matplotlib
- scapy
