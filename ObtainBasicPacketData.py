import pandas as pd
import numpy as np
import pyshark
import sys
from sklearn import metrics
from sklearn import tree
from pandas.api.types import is_string_dtype, is_numeric_dtype
import os
from pathlib import Path
#Automatically creates the PacketFiles directory if not already created
def createPacketFileLocation():
	Path(os.path.dirname(os.path.realpath(__file__)) + "\PacketFiles").mkdir(parents=True, exist_ok=True)

#Fix missing removes null values and creates a new column in the pandas dataframe, containg a boolean flag, telling us that the value was null
def fix_missing(df, col, name):
	if is_numeric_dtype(col):
		if pd.isnull(col).sum():
			df[name + '_na'] = pd.isnull(col)
		df[name] = col.fillna(col.median())

#Use the category codes instead of the strings. Used for formatting for machine learning algorithms.
def numericalize(df, col, name, max_n_cat):
	if not is_numeric_dtype(col) and (max_n_cat is None or col.nunique() > max_n_cat):
		df[name] = col.cat.codes + 1


#Ensure all strings are now categories
def train_cats(df_raw):
	df = df_raw
	for n, c in df.items():
		if is_string_dtype(c): df[n] = c.astype('category')



# This function cleans the data.
# The isTest parameter determines if the dataframe will return a field with the dependent variable
def proc_df(df, y_fld, isTest, skip_flds=None, do_scale=False, preproc_fn=None, max_n_cat=None, subset=None):
	if not skip_flds: skip_flds = []
	df = df.copy()
	# Keep a copy with correct prediction results
	if isTest: withY = df.copy()
	if preproc_fn: preproc_fn(df)
	y = df[y_fld].values
	df.drop(skip_flds + [y_fld], axis=1, inplace=True)
	# Fix missing/incorrect data and use category codes.
	for n, c in df.items(): fix_missing(df, c, n)
	for n, c in df.items(): numericalize(df, c, n, max_n_cat)
	res = [pd.get_dummies(df, dummy_na=True), y]
	if not do_scale: return res
	if isTest: return res, withY
	return res

def ObtainData(filename):
	# Obtain the data: Timestamp,SourceIP,SourcePort,DestinationIP,DestinationPort,Protocol
	cap = pyshark.FileCapture(filename)
	counter = 1
	packetFileData = []
	for packet in cap:
		packetData = []
		# Length of packet in bytes
		packetData.append(packet.sniff_time)
		counter += 1
		if 'ARP' in packet:
			packetData.append(None)
			packetData.append(1)
			packetData.append(None)
			packetData.append(1)
			packetData.append(None)
			packetData.append(1)
			packetData.append(None)
			packetData.append(1)
			packetData.append(None)
			packetData.append(1)
			pass
		# IPV6
		if 'IPV6' in packet:
			packetData.append(packet.ipv6.src)
			packetData.append(0)
			packetData.append(packet.ipv6.dst)
			packetData.append(0)
			packetData.append(packet.ipv6.nxt)
			packetData.append(0)
			# Since ports are the layer 4 address, all protocols will have TCP or UDP so...
			if 'TCP' in packet:
				packetData.append(packet.tcp.srcport)
				packetData.append(0)
				packetData.append(packet.tcp.dstport)
				packetData.append(0)
			
			if 'UDP' in packet:
				packetData.append(packet.udp.srcport)
				packetData.append(0)
				packetData.append(packet.udp.dstport)
				packetData.append(0)
			if hasattr(packet, 'icmpv6'):
				# ICMP has no port numbers.
				# We already have its addresses
				
				packetData.append(None)
				packetData.append(1)
				packetData.append(None)
				packetData.append(1)
			if 'IGMP' in packet:
				packetData.append(packet[packet.transport_layer].srcport)
				packetData.append(0)
				packetData.append(packet[packet.transport_layer].dstport)
				packetData.append(1)
		# IPV4
		if 'IP' in packet:
			packetData.append(packet.ip.src)
			packetData.append(0)
			packetData.append(packet.ip.dst)
			packetData.append(0)
			packetData.append(packet.ip.proto)
			packetData.append(0)
			# Since ports are the layer 4 address, all protocols will have TCP or UDP so...
			if 'TCP' in packet:
				packetData.append(packet.tcp.srcport)
				packetData.append(0)
				packetData.append(packet.tcp.dstport)
				packetData.append(0)
			if 'UDP' in packet:
				packetData.append(packet.udp.srcport)
				packetData.append(0)
				packetData.append(packet.udp.dstport)
				packetData.append(0)
			# Things that do not have an ip source address
			if 'ICMP' in packet:
				# ICMP has no port numbers.
				# We already have its addresses
				packetData.append(None)
				packetData.append(1)
				packetData.append(None)
				packetData.append(1)
			if 'IGMP' in packet:
				packetData.append(None)
				packetData.append(1)
				packetData.append(None)
				packetData.append(1)
		packetData.append(int(packet.length))
	df = pd.DataFrame(packetFileData,
					  columns=['Timestamp', 'SourceIP', 'SourceIP_na', 'DestinationIP', 'DestinationIP_na', 'Protocol',
							   'Protocol_na', 'SourcePort', 'SourcePort_na',
							   'DestinationPort', 'DestinationPort_na', 'Size'])
	return df


def CalculateMeanPacketsPerSecond(df):
	# Calculate Packets per Second (PerSec)
	lastRow = (df.tail(1))
	endTime = lastRow['Timestamp']
	firstRow = (df.head(1))
	firstTime = firstRow['Timestamp']
	# Need the total number of seconds passed.
	
	# This try except exists because sometimes we get empty numpy arrays.
	try:
		sniffTime = (endTime.values[0] - firstTime.values[0])
	except:
		sniffTime = 0
	# Count the number of packets with same Source,Destination addresses and same Source,Destination ports and protocol
	cols = ['SourceIP', 'SourcePort', 'DestinationIP', 'DestinationPort', 'Protocol']
	df['PerSec'] = df.groupby(cols)['SourceIP'].transform('count')
	# Remove NaN values caused by ARP in perSec column
	df['PerSec'].fillna(0, inplace=True)
	# Calculate Per Second
	df['PerSec'] = df['PerSec'].div(pd.Timedelta(sniffTime).total_seconds())
	return df

#Will ensure that only valid files are used.
def validateFiles():
	# Loop through Chosen Directory.
	os.path.dirname(os.path.realpath(__file__)) + "\PacketFiles"
	fileNames = [f for f in os.listdir(os.path.dirname(os.path.realpath(__file__)) + "\PacketFiles") if
				 os.path.isfile(os.path.join(os.path.dirname(os.path.realpath(__file__)) + "\PacketFiles", f))]
	print("Files Detected: " + str(fileNames))
	# Ensure files are packet files
	validFiles = fileNames
	#Add Packet Capture File Types here
	validFiles = [f for f in fileNames if ".pcapng" in f or ".pcap" in f]
	print("Files Used: " + str(validFiles))
	return validFiles

