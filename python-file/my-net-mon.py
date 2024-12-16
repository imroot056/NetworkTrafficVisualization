#!/usr/bin/python3
'''
The Network Traffic Visualization Program which is Written in Python3 can be a used to Visualize the 
Incomming and Outgoing Network Traffice in any particular device using attractive Kibana dashboard
'''


'''This is the change made'''

'''This is second change'''


#The module Scapy is used for Network Programming in the project
from scapy.all import *
#Time is used to mantain time of log files
import time
# Datetime is used to extract the current date from the operating system. 
import datetime
#The module Os is used to interact with operating system
import os
#The module getmac is used to get the Mac Address of the device
from getmac import get_mac_address as gma
#The module webbrowser is used to open webbrowser
import webbrowser
#The module Json is used to creat Json dumps of incomming and outgoing packets 
import json
#The module argparse is used for argument parsing functionality
import argparse
# Signal is used for interacting with keyboard hot keys
import signal

# Argument parsing for different functions of the program
def parse_args():
	#Very short Description of the program
	parser=argparse.ArgumentParser(description='A Packet Sniffer written python 3.8 Which sniffs the Incomming and Outgoing Network Traffic')
	#Argument -t to sniff Incoming/Outgoing TCP packets only
	parser.add_argument('-t',"--TCP",help='Capture TCP Packets Only',action='store_true')
	#Argument -u to sniff Incoming/Outgoing UDP packets only
	parser.add_argument('-u','--UDP', help='Capture only UDP packets',action='store_true')
	#Argument -i to sniff Incoming/Outgoing ICMP packets only
	parser.add_argument('-i','--ICMP',help='Capture only ICMP packets',action='store_true')
	#Argument -a to sniff Incoming/Outgoing ARP packets only
	parser.add_argument('-a','--ARP',help='Capture only ARP packets',action='store_true')
	#Argument -w to sniff all the Incoming/Outgoing packets
	parser.add_argument('-w','--Whole',help='Sniff all Packets',action='store_true')
	#Argument -w to Visualize the Sniffed packets and Parse the logs
	parser.add_argument('-v','--Visualize',help='Visualize the Network Logs in Kibana dashboard',action='store_true')

	return parser.parse_args()
	# returns the parse_args argument to the function and console output
	# Network packet sniffing using functional programming
	# @pkt is the argument for extracting packet from low socket interface and scapy functions

'''
This us used to create a colourful colour indexing for output
'''
G = '\u001b[32;1m'  # Green Colour Index (For TCP)
Y = '\u001b[33;1m'  # Yellow Colour Index (For UDP)
B = '\u001b[34;1m'  # Blue Colour Index (For ICMP)
P = '\u001b[35;1m'   # Purple Colour Index (For ARP)
W = '\u001b[0m' #White Colour Index
R = '\u001b[31;1m'  # Red Colour Index (Others)



#Storing Mac Address in te Variable My_MAC
My_MAC=gma()

#Directory of Log files
log_files_dir='/opt/logfiles'


def pkthndler(pkt):

	#Exception handling in order to reduce error in the program
	# try		# Extractig time from datetime module to maintain consistency while maintaining packet logs
		time=datetime.datetime.now()

		# Getting additional TCP argument as -t from the user in the program for sniffing
		if args.TCP or args.Whole:
			
			#For packets having TCP layer
			if pkt.haslayer(TCP):
				#Changing the directory to store the log files 
				os.chdir(log_files_dir)
				# Opening a file for TCP logs and with appending rights
				TCP_LOG=open("TCP.log","a")
				
				# Classifying the network packets as Incoming based on Mac Address where a Incoming packet's destination Address Has my Mac Address
				if My_MAC == str(pkt.dst): # IncommingTCP
					#Changing Colour to Green for incoming/Outgoing TCP Packets
					print("%s"%G)
					#Printing 117 '.'
					print('.'*117)
					#Printing The time when packet entered the interface
					print("TCP Incomming"+"  "+str("[")+str(time)+str("]"))
					#Printing Other diffrent packet details
					print("TCP-IN:{}".format(len(pkt[TCP]))+" Bytes"+"    "+"SRC-MAC:" +str(pkt.src)+"    "+ "DST-MAC:"+str(pkt.dst)+
					"    "+ "SRC-PORT:"+str(pkt.sport)+"    "+"DST-PORT:"+str(pkt.dport))
					#Using try to make the program compatible for IPv6 adresses as well
					try:			
						#Printing Source and Destination IP of packet 
						print("IP-Version:"+str(pkt[IP].version)+"    "+"SRC-IP: "+str(pkt[IP].src)+ "    "+"DST-IP:  "+str(pkt[IP].dst))
					#If packet with IPv6 address comes this block of code is executed				
					except:
						#Printing Source and Destination IP of packet 			
						print("IP-Version:"+str(pkt[IPv6].version)+"    "+"SRC-IP: "+str(pkt[IPv6].src)+ "    "+"DST-IP:  "+str(pkt[IPv6].dst))
					
					#Printing 117 '.'				
					print('.'*117)
					# Opening a file for TCP Incoming logs and with appending rights
					TCP_IN_log=open("TCP_IN.log","a")
					# Creating a object for TCP incoming Packet for dumping
					TCP_IN={}
					#Classified packet as TCP-INCOMMING
					TCP_IN['Packet_Type']="TCP-INCOMING"
					#Getting Source Mac of the packet
					TCP_IN['Source_Mac']=pkt.src
					#Getting Destination Mac of the packet
					TCP_IN['Destination_Mac']=pkt.dst
					#Getting time for the logs consistency
					TCP_IN['Time']=str(time)
					#Getting source port number of the packet
					TCP_IN['Source_Port']=pkt.sport
					#Getting Destination port number of the packet
					TCP_IN['Destination_Port']=pkt.dport
					#Getting the size of the packet
					TCP_IN['Packet_Size']=len(pkt)
					#Using try to make the program compatible for IPv6 adresses as well
					try:
						#Getting Source IP of the packet
						TCP_IN['Source_IP']=pkt[IP].src
						#Getting Destination IP of the packet
						TCP_IN['Destination_IP']=pkt[IP].dst
					#If packet with IPv6 address comes this block of code is executed				
					except:
						#Getting Source IPv6 of the packet
						TCP_IN['Source_IP']=pkt[IPv6].src
						#Getting Destination IPv6 of the packet
						TCP_IN['Destination_IP']=pkt[IPv6].dst
					#Dumping the TCP logs into The TCP Incomming File
					TCP_IN_log.write('\n'+json.dumps(TCP_IN))
					#Dumping the TCP logs into TCP log file
					TCP_LOG.write('\n'+json.dumps(TCP_IN))			
					
					# Creating a text file for the connection ip address				
					connection_log_for_tcp=open('connection.txt','a')
					# extracting the connected ip address into the connection log
					write_tcp='\n'+str(pkt[IP].src)
					# appending the connected ip address in the connetion logs text file
					connection_log_for_tcp.write(write_tcp)
					
					#Further Classification of TCP packet into HTTP packet examining the source port i.e 80
					if pkt.sport==80:#HTTP_IN
						# Opening a file for HTTP Incoming logs and with appending rights
						HTTP_log=open("HTTP.log","a")
						#Creating a json object of HTTP incoming packet
						HTTP_IN={}
						#Classified packet as HTTP Incoming packet
						HTTP_IN['Packet_Type']="HTTP-INCOMING"
						#Getting Source Mac of the packet
						HTTP_IN['Source_Mac']=pkt.src
						#Getting Destinatiom Mac of the packet 
						HTTP_IN['Destination_Mac']=pkt.dst
						#Getting Time for logs consistence
						HTTP_IN['Time']=str(time)
						#Getting the source port of the packet
						HTTP_IN['Source_Port']=pkt.sport
						#Getting the Destination port of the packet 
						HTTP_IN['Destination_Port']=pkt.dport
						#Getting the size of the packet 
						HTTP_IN['Packet_Size']=len(pkt)
						#Using try to make the program compatible for IPv6 adresses as well
						try:
							#Getting Source IP address of the packet
							HTTP_IN['Source_IP']=pkt[IP].src
							#Getting the destination IP address of the packet
							HTTP_IN['Destination_IP']=pkt[IP].dst
						#If packet with IPv6 address comes this block of code is exexuted.
						except:
							#Getting the source IPv6 address of the packet
							HTTP_IN['Source_IP']=pkt[IPv6].src
							#Getting the Destination IPv6 address of the packet
							HTTP_IN['Destination_IP']=pkt[IPv6].dst
						#Dumping the whole json data into a HTTP log file
						HTTP_log.write('\n'+json.dumps(HTTP_IN))
					
				
					#Further Classification of TCP packet into HTTPS packet examining the source port i.e. 443
					if pkt.sport==443:#HTTPS_IN
						# Opening a file for HTTPS Incoming logs and with appending rights
						HTTPS_log=open("HTTPS.log","a")
						#Creating a json object for HTTPS incoming packet
						HTTPS_IN={}
						#Classified packet as HTTPS incomning packet
						HTTPS_IN['Packet_Type']="HTTPS-INCOMING"
						#Getting the Source Mac address of the packet
						HTTPS_IN['Source_Mac']=pkt.src
						#Getting the Destination of the packet
						HTTPS_IN['Destination_Mac']=pkt.dst
						#Geting the time for logs consistency
						HTTPS_IN['Time']=str(time)
						#Getting the Source port of the packet
						HTTPS_IN['Source_Port']=pkt.sport
						#Getting the Destination port of the packet
						HTTPS_IN['Destination_Port']=pkt.dport
						#getting the size of the packet
						HTTPS_IN['Packet_Size']=len(pkt)
						#Using try to make program compatible for IPv6 address as well
						try:
							#Getting the source IP of the packet
							HTTPS_IN['Source_IP']=pkt[IP].src
							#Getting the Destination IP of the packet
							HTTPS_IN['Destination_IP']=pkt[IP].dst
						#If the packet contains IPv6 Address this block of code will be executed
						except:
							#Getting the source IPv6 address of the apcket
							HTTPS_IN['Source_IP']=pkt[IPv6].src
							#Getting the destination IPv6 address of the packet
							HTTPS_IN['Destination_IP']=pkt[IPv6].dst

						#Dumping the whole json data in the HTTPS log file
						HTTPS_log.write('\n'+json.dumps(HTTPS_IN))

					#Further Classification of TCP packet into FTP packet examining the source port i.e. 443
					if pkt.sport==21:
						#Opening the file for FTP logs with appending rights
						FTP_log=open("FTP.log","a")
						#Creating an object for FTP incoming packets for dumping 
						FTP_IN={}
						#Classified packet as FTP incoming packet
						FTP_IN['Packet_Type']="FTP-INCOMING"
						#Getting the source Mac address of the packet
						FTP_IN['Source_Mac']=pkt.src
						#Getting the Destination Mac Address of the packet
						FTP_IN['Destination_Mac']=pkt.dst
						#Getting the time for logs consistency
						FTP_IN['Time']=str(time)
						#Getiing the source port of the packet
						FTP_IN['Source_Port']=pkt.sport
						#Getting the destination port of the pcket
						FTP_IN['Destination_Port']=pkt.dport
						#Getting the size of the apcket
						FTP_IN['Packet_Size']=len(pkt)
						#Using try to make program compatible with IPv6 addresses as well
						try:
							#Getting Source IP address of the packet
							FTP_IN['Source_IP']=pkt[IP].src
							#Getting the Destination IP address of the packet
							FTP_IN['Destination_IP']=pkt[IP].dst
						#If the packet contains IPv6 address this block of code gets executed	
						except:
							#Getting source IPv6 address of the packet
							FTP_IN['Source_IP']=pkt[IPv6].src
							#Getting the destination IPv6 address of the apcket
							FTP_IN['Destination_IP']=pkt[IPv6].dst
						#Dumping the whole json data into a FTP log file
						FTP_log.write('\n'+json.dumps(FTP_IN))	

					#Further Classification of TCP packet into Telnet packet examining the source port i.e. 23
					if pkt.sport==23:
						#Opening the file for TELNET with appending rights
						TELNET_log=open("TELNET.log","a")
						#Ceating an object for TELNET incoming packets
						TELNET_IN={}
						#Classified packet as Telnet Incoming packets
						TELNET_IN['Packet_Type']="TCP_TELNET-INCOMING"
						#Getting the source Mac address of the packet
						TELNET_IN['Source_Mac']=pkt.src
						#Getting the destination Mac address of the packet
						TELNET_IN['Destination_Mac']=pkt.dst
						#Getting the time of the packet for logs consistency
						TELNET_IN['Time']=str(time)
						#Getting the source port of the packet
						TELNET_IN['Source_Port']=pkt.sport
						#Getting the destination port of the packet
						TELNET_IN['Destination_Port']=pkt.dport
						#Getting the size of the apcket
						TELNET_IN['Packet_Size']=len(pkt)

						#Using try to make program compatible with IPv6 addresses as well
						try:
							#Getting Source IP address of the packet
							TELNET_IN['Source_IP']=pkt[IP].src
							#Getting the Destination IP address of the packet
							TELNET_IN['Destination_IP']=pkt[IP].dst
						#If the packet contains IPv6 address this block of code gets executed	
						except:
							#Getting source IPv6 address of the packet
							TELNET_IN['Source_IP']=pkt[IPv6].src
							#Getting the destination IPv6 address of the apcket
							TELNET_IN['Destination_IP']=pkt[IPv6].dst
						#Dumping the whole json data into a TELNET log file
						TELNET_log.write('\n'+json.dumps(TELNET_IN  ))
					
					#Further Classification of TCP packet into SSH packet examining the source port i.e. 23
					if pkt.sport==22:#SSH_in
						#Opening the file for SSH with appending rights
						SSH_log=open("SSH.log","a")
						#Ceating an object for SSH incoming packets
						SSH_IN={}
						#Classified packet as SSH Incoming packets
						SSH_IN['Packet_Type']="SSH-INCOMING"
						#Getting the source Mac address of the packet
						SSH_IN['Source_Mac']=pkt.src
						#Getting the destination Mac address of the packet
						SSH_IN['Destination_Mac']=pkt.dst
						#Getting the time of the packet for logs consistency
						SSH_IN['Time']=str(time)
						#Getting the source port of the packet
						SSH_IN['Source_Port']=pkt.sport
						#Getting the destination port of the packet
						SSH_IN['Destination_Port']=pkt.dport
						#Getting the size of the packet
						SSH_IN['Packet_Size']=len(pkt)
						#Using try to make program compatible with IPv6 addresses as well
						try:
							#Getting Source IP address of the packet
							SSH_IN['Source_IP']=pkt[IP].src
							#Getting the Destination IP address of the packet
							SSH_IN['Destination_IP']=pkt[IP].dst
						#If the packet contains IPv6 address this block of code gets executed	
						except:
							#Getting source IPv6 address of the packet
							SSH_IN['Source_IP']=pkt[IPv6].src
							#Getting the destination IPv6 address of the packet
							SSH_IN['Destination_IP']=pkt[IPv6].dst
						#Dumping the whole json data into a SSH log file
						SSH_log.write('\n'+json.dumps(SSH_IN))
					
					#Looking if the packet contains DNS or not
					if DNS in pkt: # IncommingDNS_TCP 
						#Opening the file for DNS with appending rights
						DNS_log=open("DNS.log","a")
						#Ceating an object for DNS incoming packets
						TCP_DNS_IN={}
						#Classified packet as DNS Incoming packets
						TCP_DNS_IN['PACKET_TYPE']="DNS-TCP-INCOMING"
						#Getting the source Mac address of the packet
						TCP_DNS_IN['Source Mac']=pkt.src
						#Getting the destination Mac address of the packet
						TCP_DNS_IN['Destination Mac']=pkt.dst
						#Getting the source port of the packet
						TCP_DNS_IN['Source Port']=pkt.sport
						#Getting the destination port of the packet
						TCP_DNS_IN['Destination Port']=pkt.dport
						#Getting the summary of the packet
						TCP_DNS_IN['Summary']=pkt.summary()
						#Using try to make program compatible with IPv6 addresses as well
						try:
							#Getting Source IP address of the packet
							TCP_DNS_IN['Source_IP']=pkt[IP].src
							#Getting the Destination IP address of the packet
							TCP_DNS_IN['Destination_IP']=pkt[IP].dst
						#If the packet contains IPv6 address this block of code gets executed	
						except:
							#Getting source IPv6 address of the packet
							TCP_DNS_IN['Source_IP']=pkt[IPv6].src
							#Getting the destination IPv6 address of the packet
							TCP_DNS_IN['Destination_IP']=pkt[IPv6].dst
						
						#Dumping the whole json data into a DNS log file
						DNS_log.write('\n'+json.dumps(TCP_DNS_IN  ))

				# Classifying the network packets as Outgoing based on Mac Address where a Outgoing packet's source Mac Address has my Mac Address
				if My_MAC == pkt.src: # OutgoingTCP
					#Changing Colour to Green for incoming/Outgoing TCP Packets
					print("%s"%G)
					#Printing 117 '.'
					print('.'*117)
					#Printing The time when packet went out the interface
					print("TCP Outgoing"+"  "+str("[")+str(time)+str("]"))		
					#Printing Other diffrent packet details
					print("TCP-OUT:{}".format(len(pkt[TCP]))+" Bytes"+"    "+"SRC-MAC:" +str(pkt.src)+"    "+ "DST-MAC:"+str(pkt.dst)+
					"    "+"SRC-PORT:"+str(pkt.sport)+"    "+"DST-PORT:"+str(pkt.dport))
					#Using try to make the program compatible for IPv6 adresses as well
					try:
						#Printing Source and Destination IP of packet 
						print("IP-Version:"+str(pkt[IP].version)+"    "+"SRC-IP: "+str(pkt[IP].src)+ "    "+"DST-IP:  "+str(pkt[IP].dst))
					#If packet with IPv6 address comes this block of code is executed				
					except:
						#Printing Source and Destination IP of packet 			
						print("IP-Version:"+str(pkt[IPv6].version)+"    "+"SRC-IP: "+str(pkt[IPv6].src)+ "    "+"DST-IP:  "+str(pkt[IPv6].dst))

					#Printing 117 '.'				
					print('.'*117)
					# Opening a file for TCP Outgoing logs and with appending rights
					TCP_OUT_log=open("TCP_OUT.log","a")
					# Creating a object for TCP incoming Packet for dumping
					TCP_OUT={}
					#Classified packet as TCP-OUTGOING
					TCP_OUT['Packet_Type']="TCP-OUTGOING"
					#Getting Source Mac of the packet
					TCP_OUT['Source_Mac']=pkt.src
					#Getting Destination Mac of the packet
					TCP_OUT['Destination_Mac']=pkt.dst
					#Getting time for the logs consistency
					TCP_OUT['Time']=str(time)
					#Getting source port number of the packet
					TCP_OUT['Source_Port']=pkt.sport
					#Getting Destination port number of the packet
					TCP_OUT['Destination_Port']=pkt.dport
					#Getting the size of the packet
					TCP_OUT['Packet_Size']=len(pkt)
					#Using try to make the program compatible for IPv6 adresses as well
					try:
						#Getting Source IP of the packet
						TCP_OUT['Source_IP']=pkt[IP].src
						#Getting Destination IP of the packet
						TCP_OUT['Destination_IP']=pkt[IP].dst
					#If packet with IPv6 address comes this block of code is executed				
					except:
						#Getting Source IPv6 of the packet
						TCP_OUT['Source_IP']=pkt[IPv6].src
						#Getting Destination IPv6 of the packet
						TCP_OUT['Destination_IP']=pkt[IPv6].dst
					#Dumping the TCP logs into The TCP Outgoing File
					TCP_OUT_log.write('\n'+json.dumps(TCP_OUT))
					#Dumping the TCP logs into TCP log file
					TCP_LOG.write('\n'+json.dumps(TCP_OUT))

					#Further Classification of TCP packet into HTTP packet examining the destination port i.e 80
					if pkt.dport==80: #HTTP Outgoing
						# Opening a file for HTTP Outgoing logs and with appending rights
						HTTP_log=open("HTTP.log","a")
						#Creating a json object of HTTP incoming packet
						HTTP_OUT={}
						#Classified packet as HTTP Outgoing packet
						HTTP_OUT['Packet_Type']="HTTP-OUTGOING"
						#Getting Source Mac of the packet
						HTTP_OUT['Source_Mac']=pkt.src
						#Getting Destinatiom Mac of the packet 
						HTTP_OUT['Destination_Mac']=pkt.dst
						#Getting Time for logs consistence
						HTTP_OUT['Time']=str(time)
						#Getting the source port of the packet
						HTTP_OUT['Source_Port']=pkt.sport
						#Getting the Destination port of the packet 
						HTTP_OUT['Destination_Port']=pkt.dport
						#Getting the size of the packet 
						HTTP_OUT['Packet_Size']=len(pkt)
						#Using try to make the program compatible for IPv6 adresses as well
						try:
							#Getting Source IP address of the packet
							HTTP_OUT['Source_IP']=pkt[IP].src
							#Getting the destination IP address of the packet
							HTTP_OUT['Destination_IP']=pkt[IP].dst
						#If packet with IPv6 address comes this block of code is exexuted.
						except:
							#Getting the source IPv6 address of the packet
							HTTP_IN['Source_IP']=pkt[IPv6].src
							#Getting the Destination IPv6 address of the packet
							HTTP_IN['Destination_IP']=pkt[IPv6].dst
						#Dumping the whole json data into a HTTP log file
						HTTP_log.write('\n'+json.dumps(HTTP_OUT))

					#Further Classification of TCP packet into HTTPS packet examining the destination port i.e. 443
					if pkt.dport==443: #HTTPS Outgoing 
						# Opening a file for HTTPS Incoming logs and with appending rights
						HTTPS_log=open("HTTPS.log","a")
						#Creating a json object for HTTPS outgoing packet
						HTTPS_OUT={}
						#Classified packet as HTTPS outgoing packet
						HTTPS_OUT['Packet_Type']="HTTPS-OUTGOING"
						#Getting the Source Mac address of the packet
						HTTPS_OUT['Source_Mac']=pkt.src
						#Getting the destination Mac address of the packet
						HTTPS_OUT['Destination_Mac']=pkt.dst
						#Geting the time for logs consistency
						HTTPS_OUT['Time']=str(time)
						#Getting the Source port of the packet
						HTTPS_OUT['Source_Port']=pkt.sport
						#Getting the Destination port of the packet
						HTTPS_OUT['Destination_Port']=pkt.dport
						#getting the size of the packet
						HTTPS_OUT['Packet_Size']=len(pkt)
						#Using try to make program compatible for IPv6 address as well
						try:
							#Getting the source IP of the packet
							HTTPS_OUT['Source_IP']=pkt[IP].src
							#Getting the Destination IP of the packet
							HTTPS_OUT['Destination_IP']=pkt[IP].dst
						#If the packet contains IPv6 Address this block of code will be executed
						except:
							#Getting the source IPv6 address of the apcket
							HTTPS_IN['Source_IP']=pkt[IPv6].src
							#Getting the destination IPv6 address of the packet
							HTTPS_IN['Destination_IP']=pkt[IPv6].dst
						#Dumping the whole json data in the HTTPS log file
						HTTPS_log.write('\n'+json.dumps(HTTPS_OUT  ))
					#Further Classification of TCP packet into FTP packet examining the destination port i.e. 443
					if pkt.dport==21: #FTP Outgoing
						#Opening the file for FTP logs with appending rights
						FTP_log=open("FTP.log","a")
						#Creating an object for FTP outgoing packets for dumping 
						FTP_OUT={}
						#Classified packet as FTP outgoing packet
						FTP_OUT['Packet_Type']="FTP-OUTGOING"
						#Getting the source Mac address of the packet
						FTP_OUT['Source_Mac']=pkt.src
						#Getting the Destination Mac Address of the packet
						FTP_OUT['Destination_Mac']=pkt.dst
						#Getting the time for logs consistency
						FTP_OUT['Time']=str(time)
						#Getiing the source port of the packet
						FTP_OUT['Source_Port']=pkt.sport
						#Getting the destination port of the pcket
						FTP_OUT['Destination_Port']=pkt.dport
						#Getting the size of the apcket
						FTP_OUT['Packet_Size']=len(pkt)
						#Using try to make program compatible with IPv6 addresses as well
						try:
							#Getting Source IP address of the packet
							FTP_OUT['Source_IP']=pkt[IP].src
							#Getting the Destination IP address of the packet
							FTP_OUT['Destination_IP']=pkt[IP].dst
						#If the packet contains IPv6 address this block of code gets executed	
						except:
							#Getting source IPv6 address of the packet
							FTP_OUT['Source_IP']=pkt[IPv6].src
							#Getting the destination IPv6 address of the apcket
							FTP_OUT['Destination_IP']=pkt[IPv6].dst
						#Dumping the whole json data into a FTP log file
						FTP_log.write('\n'+json.dumps(FTP_OUT  ))	

					#Further Classification of TCP packet into Telnet packet examining the source port i.e. 23
					if pkt.dport==23:
						#Opening the file for TELNET with appending rights
						TELNET_log=open("TELNET.log","a")
						#Ceating an object for TELNET outgoing packets
						TELNET_OUT={}
						#Classified packet as Telnet outgoing packets
						TELNET_OUT['Packet_Type']="TCP_TELNET-OUTGOING"
						#Getting the source Mac address of the packet
						TELNET_OUT['Source_Mac']=pkt.src
						#Getting the destination Mac address of the packet
						TELNET_OUT['Destination_Mac']=pkt.dst
						#Getting the time of the packet for logs consistency
						TELNET_OUT['Time']=str(time)
						#Getting the source port of the packet
						TELNET_OUT['Source_Port']=pkt.sport
						#Getting the destination port of the packet
						TELNET_OUT['Destination_Port']=pkt.dport
						#Getting the size of the apcket
						TELNET_OUT['Packet_Size']=len(pkt)

						#Using try to make program compatible with IPv6 addresses as well
						try:
							#Getting Source IP address of the packet
							TELNET_OUT['Source_IP']=pkt[IP].src
							#Getting the Destination IP address of the packet
							TELNET_OUT['Destination_IP']=pkt[IP].dst
						#If the packet contains IPv6 address this block of code gets executed	
						except:
							#Getting source IPv6 address of the packet
							TELNET_OUT['Source_IP']=pkt[IPv6].src
							#Getting the destination IPv6 address of the apcket
							TELNET_OUT['Destination_IP']=pkt[IPv6].dst
						#Dumping the whole json data into a TELNET log file
						TELNET_log.write('\n'+json.dumps(TELNET_OUT))	
					
					#Further Classification of TCP packet into SSH packet examining the destination port i.e. 23
					if pkt.dport==22: #SSH Outgoing
						#Opening the file for SSH with appending rights
						SSH_log=open("SSH.log","a")
						#Ceating an object for SSH outgoing packets
						SSH_OUT={}
						#Classified packet as SSH outgoing packets
						SSH_OUT['Packet_Type']="SSH-OUTGOING"
						#Getting the source Mac address of the packet
						SSH_OUT['Source_Mac']=pkt.src
						#Getting the destination Mac address of the packet
						SSH_OUT['Destination_Mac']=pkt.dst
						#Getting the time of the packet for logs consistency
						SSH_OUT['Time']=str(time)
						#Getting the source port of the packet
						SSH_OUT['Source_Port']=pkt.sport
						#Getting the destination port of the packet
						SSH_OUT['Destination_Port']=pkt.dport
						#Getting the size of the packet
						SSH_OUT['Packet_Size']=len(pkt)
						#Using try to make program compatible with IPv6 addresses as well
						try:
							#Getting Source IP address of the packet
							SSH_OUT['Source_IP']=pkt[IP].src
							#Getting the Destination IP address of the packet
							SSH_OUT['Destination_IP']=pkt[IP].dst
						#If the packet contains IPv6 address this block of code gets executed	
						except:
							#Getting source IPv6 address of the packet
							SSH_OUT['Source_IP']=pkt[IPv6].src
							#Getting the destination IPv6 address of the packet
							SSH_OUT['Destination_IP']=pkt[IPv6].dst
						#Dumping the whole json data into a SSH log file
						SSH_log.write('\n'+json.dumps(SSH_OUT))	
					
					#Looking if the packet contains DNS or not
					if DNS in pkt: # OutgoingDNS__TCP 
						#Opening the file for DNS with appending rights
						DNS_log=open("DNS.log","a")
						#Ceating an object for DNS outgoing packets
						DNS_OUT={}
						#Classified packet as DNS outgoing packets
						DNS_OUT['PACKET_TYPE']="DNS-TCP-OUTGOING"
						#Getting the source Mac address of the packet
						DNS_OUT['Source Mac']=pkt.src
						#Getting the destination Mac address of the packet
						DNS_OUT['Destination Mac']=pkt.dst
						#Getting the source port of the packet
						DNS_OUT['Source Port']=pkt.sport
						#Getting the destination port of the packet
						DNS_OUT['Destination Port']=pkt.dport
						#Getting the summary of the packet
						DNS_OUT['Summary']=pkt.summary()
						#Using try to make program compatible with IPv6 addresses as well
						try:
							#Getting Source IP address of the packet
							DNS_OUT['Source_IP']=pkt[IP].src
							#Getting the Destination IP address of the packet
							DNS_OUT['Destination_IP']=pkt[IP].dst
						#If the packet contains IPv6 address this block of code gets executed	
						except:
							#Getting source IPv6 address of the packet
							DNS_OUT['Source_IP']=pkt[IPv6].src
							#Getting the destination IPv6 address of the packet
							DNS_OUT['Destination_IP']=pkt[IPv6].dst
						#Dumping the whole json data into a DNS log file
						DNS_log.write('\n'+json.dumps(DNS_OUT  ))
		
		# Getting additional UDP argument as -u from the user in the program for sniffing
		if args.UDP or args.Whole:
            
			#For packets having UDP laye
			if pkt.haslayer(UDP):
				#Changing the directory to store the log files 
				os.chdir(log_files_dir)	
				#Opening a file for TCP logs and with appending rights
				UDP_LOG=open("UDP.log","a")

				# Classifying the network packets as Incoming based on Mac Address where a Incoming packet's destination Address Has my Mac Address
				if My_MAC == pkt.dst: # IncommingUDP
					#Changing Colour to Yellow for incoming/Outgoing UDP Packets
					print("%s"%Y)
					#Printing 117 '.'
					print('.'*117)
					#Printing The time when packet entered the interface
					print("UDP Incomming"+"  "+str("[")+str(time)+str("]"))
					#Printing Other diffrent packet details
					print("UDP-IN:{}".format(len(pkt[UDP]))+" Bytes"+"	 SRC-MAC:"+str(pkt.src)+"    "+"DST-MAC:"+str(pkt.dst)+
					"    "+ "SRC-PORT:"+str(pkt.sport)+"    "+"DST-PORT:"+str(pkt.dport))		
					#Using try to make the program compatible for IPv6 adresses as well
					try:
						#Printing Source and Destination IP of packet 
						print("SRC-IP: "+str(pkt[IP].src)+ "    "+"DST-IP:  "+str(pkt[IP].dst))		
					#If packet with IPv6 address comes this block of code is executed				
					except:	
						#Printing Source and Destination IP of packet 			
						print("SRC-IP: "+str(pkt[IPv6].src)+ "    "+"DST-IP:  "+str(pkt[IPv6].dst))		
					
					#Printing 117 '.'				
					print('.'*117)
					# Opening a file for UDP Incoming logs and with appending rights
					UDP_IN_log=open("UDP_IN.log","a")
					#Creating a object for UDP incoming Packet for dumping
					UDP_IN={}
					#Classified packet as UDP-INCOMMING
					UDP_IN['Packet_Type']="UDP-INCOMING"
					#Getting Source Mac of the packet
					UDP_IN['Source_Mac']=pkt.src
					#Getting Destination Mac of the packet
					UDP_IN['Destination_Mac']=pkt.dst
					#Getting time for the logs consistency
					UDP_IN['Time']=str(time)
					#Getting source port number of the packet
					UDP_IN['Source_Port']=pkt.sport
					#Getting Destination port number of the packet
					UDP_IN['Destination_Port']=pkt.dport
					#Getting the size of the packet
					UDP_IN['Packet_Size']=len(pkt)
					#Using try to make the program compatible for IPv6 adresses as well
					try:
						#Getting Source IP of the packet
						UDP_IN['Source_IP']=pkt[IP].src
						#Getting Destination IP of the packet
						UDP_IN['Destination_IP']=pkt[IP].dst
					#If packet with IPv6 address comes this block of code is executed				
					except:
						#Getting Source IPv6 of the packet
						UDP_IN['Source_IP']=pkt[IPv6].src
						#Getting Destination IPv6 of the packet
						UDP_IN['Destination_IP']=pkt[IPv6].dst
					#Dumping the UDP logs into The UDP Incomming File
					UDP_IN_log.write('\n'+json.dumps(UDP_IN))
					#Dumping the TCP logs into UDP log file
					UDP_LOG.write('\n'+json.dumps(UDP_IN))
					
					#Further Classification of UDP packet into Telnet packet examining the source port i.e. 23
					if pkt.sport==23:#Telnet Incoming
						# Opening a file for TELNET incomming logs and with appending rights
						TELNET_log=open("TELNET.log","a")
						#Ceating an object for TELNET outgoing packets
						TELNET_IN={}
						#Classified packet as Telnet outgoing packets
						TELNET_IN['Packet_Type']="UDP_TELNET-INCOMING"
						#Getting the source Mac address of the packet
						TELNET_IN['Source_Mac']=pkt.src
						#Getting the destination Mac address of the packet
						TELNET_IN['Destination_Mac']=pkt.dst
						#Getting the time of the packet for logs consistency
						TELNET_IN['Time']=str(time)
						#Getting the source port of the packet
						TELNET_IN['Source_Port']=pkt.sport
						#Getting the destination port of the packet
						TELNET_IN['Destination_Port']=pkt.dport
						#Getting the size of the apcket
						TELNET_IN['Packet_Size']=len(pkt)

						#Using try to make program compatible with IPv6 addresses as well
						try:
							#Getting Source IP address of the packet
							TELNET_IN['Source_IP']=pkt[IP].src
							#Getting the Destination IP address of the packet
							TELNET_IN['Destination_IP']=pkt[IP].dst
						#If the packet contains IPv6 address this block of code gets executed	
						except:
							#Getting source IPv6 address of the packet
							TELNET_IN['Source_IP']=pkt[IPv6].src
							#Getting the destination IPv6 address of the apcket
							TELNET_IN['Destination_IP']=pkt[IPv6].dst
						#Dumping the whole json data into a TELNET log file
						TELNET_log.write('\n'+json.dumps(TELNET_IN  ))
					#Looking if the packet contains DNS or not
					if DNS in pkt: # IncommingDNS__UDP 
						#Opening the file for DNS with appending rights
						DNS_log=open("DNS.log","a")
						#Ceating an object for DNS incoming packets
						DNS_IN={}
						#Classified packet as DNS Incoming packets
						DNS_IN['PACKET_TYPE']="DNS-UDP-INCOMING"
						#Getting the source Mac address of the packet
						DNS_IN['Source Mac']=pkt.src
						#Getting the destination Mac address of the packet
						DNS_IN['Destination Mac']=pkt.dst
						#Getting the source port of the packet
						DNS_IN['Source Port']=pkt.sport
						#Getting the destination port of the packet
						DNS_IN['Destination Port']=pkt.dport
						#Getting the summary of the packet
						DNS_IN['Summary']=pkt.summary()
						#Using try to make program compatible with IPv6 addresses as well
						try:
							#Getting Source IP address of the packet
							DNS_IN['Source_IP']=pkt[IP].src
							#Getting the Destination IP address of the packet
							DNS_IN['Destination_IP']=pkt[IP].dst
						#If the packet contains IPv6 address this block of code gets executed	
						except:
							#Getting source IPv6 address of the packet
							DNS_IN['Source_IP']=pkt[IPv6].src
							#Getting the destination IPv6 address of the packet
							DNS_IN['Destination_IP']=pkt[IPv6].dst
						#Dumping the whole json data into a DNS log file
						DNS_log.write('\n'+json.dumps(DNS_IN  ))

					#Further Classification of UDP packet into DHCP packet examining the source port i.e. 23
					if pkt.sport==67 or pkt.sport==68: # IncommingDHCP__UDP
						#Opening the log file for DHCP with appending rights
						DHCP_log=open("DHCP.log","a")
						#Creating object for DHCP Incoming logs
						DHCP_IN={}
						#Classified packet as DHCP Incoming packet
						DHCP_IN['PACKET_TYPE']="DHCP-UDP-INCOMING"
						#Getting the source Mac address of the packet
						DHCP_IN['Source Mac']=pkt.src
						#Getting the destination Mac address of the packet
						DHCP_IN['Destination Mac']=pkt.dst
						#Getting the source port of the packet for logs consistency
						DHCP_IN['Source Port']=pkt.sport
						#Getting the destination port of the packet
						DHCP_IN['Destination Port']=pkt.dport
						#Getting the summary of the packet
						DHCP_IN['Summary']=pkt.summary()
						#Using try to make program compatible with IPv6 addresses as well
						try:
							#Getting Source IP address of the packet
							DHCP_IN['Source_IP']=pkt[IP].src
							#Getting the Destination IP address of the packet
							DHCP_IN['Destination_IP']=pkt[IP].dst
						#If the packet contains IPv6 address this block of code gets executed	
						except:
							#Getting source IPv6 address of the packet
							DHCP_IN['Source_IP']=pkt[IPv6].src
							#Getting destination IPv6 address of the packet
							DHCP_IN['Destination_IP']=pkt[IPv6].dst
						#Dumping the whole json data into a DHCP log file
						DHCP_log.write('\n'+json.dumps(DHCP_IN  ))
				
				#Classifying the network packets as Outgoing based on Mac Address where a Outgoing packet's source Mac Address Has my Mac Address
				if My_MAC == pkt.src: # OutgoingUDP
					#Changing Colour to Yellow for incoming/Outgoing UDP Packets
					print("%s"%Y)
					#Printinf 117 '.'
					print('.'*117)
					#Printing The time when packet went out the interface
					print("UDP Outgoing "+"  "+str("[")+str(time)+str("]"))
					#Printing Other diffrent packet details
					print("UDP-OUT:{}".format(len(pkt[UDP]))+" Bytes"+"	 SRC-MAC:"+str(pkt.src)+"    "+"DST-MAC:"+str(pkt.dst)+"    "+ 
					"    "+"SRC-PORT:"+str(pkt.sport)+"    "+"DST-PORT:"+str(pkt.dport))			
					#Using try to make the program compatible for IPv6 adresses as well
					try:
						#Printing Source and Destination IP of packet 
						print("SRC-IP: "+str(pkt[IP].src)+ "    "+"DST-IP:  "+str(pkt[IP].dst))			
					#If packet with IPv6 address comes this block of code is executed				
					except:
						#Printing Source and Destination IP of packet 			
						print("SRC-IP: "+str(pkt[IPv6].src)+ "    "+"DST-IP:  "+str(pkt[IPv6].dst))	
					#Printing 117 '.'				
					print('.'*117)
					# Opening a file for UDP Outgoing logs and with appending rights
					UDP_OUT_log=open("UDP_OUT.log","a")
					#Creating a object for UDP incoming Packet for dumping
					UDP_OUT={}
					#Classified packet as UDP-INCOMMING
					UDP_OUT['Packet_Type']="UDP-OUTGOING"
					#Getting Source Mac of the packet
					UDP_OUT['Source_Mac']=pkt.src
					#Getting Destination Mac of the packet
					UDP_OUT['Destination_Mac']=pkt.dst
					#Getting time for the logs consistency
					UDP_OUT['Time']=str(time)
					#Getting source port number of the packet
					UDP_OUT['Source_Port']=pkt.sport
					#Getting Destination port number of the packet
					UDP_OUT['Destination_Port']=pkt.dport
					#Getting the size of the packet
					UDP_OUT['Packet_Size']=len(pkt)
					#Using try to make the program compatible for IPv6 adresses as well
					try:
						#Getting Source IP of the packet
						UDP_OUT['Source_IP']=pkt[IP].src
						#Getting Destination IP of the packet
						UDP_OUT['Destination_IP']=pkt[IP].dst
					#If packet with IPv6 address comes this block of code is executed				
					except:
						#Getting Source IPv6 of the packet
						UDP_OUT['Source_IP']=pkt[IPv6].src
						#Getting Destination IPv6 of the packet
						UDP_OUT['Destination_IP']=pkt[IPv6].dst
					#Dumping the UDP logs into The UDP Incomming File
					UDP_OUT_log.write('\n'+json.dumps(UDP_OUT  ))
					#Dumping the TCP logs into UDP log file
					UDP_LOG.write('\n'+json.dumps(UDP_OUT  ))

					#Further Classification of UDP packet into Telnet packet examining the source port i.e. 23
					if  pkt.dport==23: #TELNET Outgoing
						#Opening the file for TELNET with appending rights
						TELNET_log=open("TELNET.log","a")
						#Ceating an object for TELNET outgoing packets
						TELNET_OUT={}
						#Classified packet as Telnet outgoing packets
						TELNET_OUT['Packet_Type']="UDP_TELNET-OUTGOING"
						#Getting the source Mac address of the packet
						TELNET_OUT['Source_Mac']=pkt.src
						#Getting the destination Mac address of the packet
						TELNET_OUT['Destination_Mac']=pkt.dst
						#Getting the time of the packet for logs consistency
						TELNET_OUT['Time']=str(time)
						#Getting the source port of the packet
						TELNET_OUT['Source_Port']=pkt.sport
						#Getting the destination port of the packet
						TELNET_OUT['Destination_Port']=pkt.dport
						#Getting the size of the apcket
						TELNET_OUT['Packet_Size']=len(pkt)
						#Using try to make program compatible with IPv6 addresses as well
						try:
							#Getting Source IP address of the packet
							TELNET_OUT['Source_IP']=pkt[IP].src
							#Getting the destination IPv6 address of the apcket
							TELNET_OUT['Destination_IP']=pkt[IP].dst
						#If the packet contains IPv6 address this block of code gets executed	
						except:
							#Getting source IPv6 address of the packet
							TELNET_OUT['Source_IP']=pkt[IPv6].src
							#Getting the destination IPv6 address of the apcket
							TELNET_OUT['Destination_IP']=pkt[IPv6].dst
						#Dumping the whole json data into a TELNET log file
						TELNET_log.write('\n'+json.dumps(TELNET_OUT  ))

					#Looking if the packet contains DNS or not
					if DNS in pkt: # OutgoingDNS__UDP
						#Opening the file for DNS with appending rights
						DNS_log=open("DNS.log","a")
						#Ceating an object for DNS outgoing packets
						DNS_OUT={}
						#Classified packet as DNS outgoing packets
						DNS_OUT['PACKET_TYPE']="DNS-UDP-OUTGOING"
						#Getting the source Mac address of the packet
						DNS_OUT['Source Mac']=pkt.src
						#Getting the destination Mac address of the packet
						DNS_OUT['Destination Mac']=pkt.dst
						#Getting the source port of the packet
						DNS_OUT['Source Port']=pkt.sport
						#Getting the destination port of the packet
						DNS_OUT['Destination Port']=pkt.dport
						#Getting the summary of the packet
						DNS_OUT['Summary']=pkt.summary()
						#Using try to make program compatible with IPv6 addresses as well
						try:
							#Getting Source IP address of the packet
							DNS_OUT['Source_IP']=pkt[IP].src
							#Getting the Destination IP address of the packet
							DNS_OUT['Destination_IP']=pkt[IP].dst
						#If the packet contains IPv6 address this block of code gets executed	
						except:
							#Getting source IPv6 address of the packet
							DNS_OUT['Source_IP']=pkt[IPv6].src
							#Getting the destination IPv6 address of the packet
							DNS_OUT['Destination_IP']=pkt[IPv6].dst
						#Dumping the whole json data into a DNS log file
						DNS_log.write('\n'+json.dumps(DNS_OUT  ))

					#Further Classification of UDP packet into DHCP packet examining the destination port i.e. 23
					if pkt.dport==67 or pkt.dport==68: # OutgoingDHCP__UDP 
						#Opening the log file for DHCP with appending rights
						DHCP_log=open("DHCP.log","a")
						#Creating object for DHCP outgoing logs
						DHCP_OUT={}
						#Classified packet as DHCP outgoing packet
						DHCP_OUT['PACKET_TYPE']="DHCP-UDP-OUTGOING"
						#Getting the source Mac address of the packet
						DHCP_OUT['Source Mac']=pkt.src
						#Getting the destination Mac address of the packet
						DHCP_OUT['Destination Mac']=pkt.dst
						#Getting the source port of the packet for logs consistency
						DHCP_OUT['Source Port']=pkt.sport
						#Getting the destination port of the packet
						DHCP_OUT['Destination Port']=pkt.dport
						#Getting the summary of the packet
						DHCP_OUT['Summary']=pkt.summary()
						#Using try to make program compatible with IPv6 addresses as well
						try:
							#Getting Source IP address of the packet
							DHCP_OUT['Source_IP']=pkt[IP].src
							#Getting the Destination IP address of the packet
							DHCP_OUT['Destination_IP']=pkt[IP].dst
						#If the packet contains IPv6 address this block of code gets executed	
						except:
							#Getting source IPv6 address of the packet
							DHCP_OUT['Source_IP']=pkt[IPv6].src
							#Getting destination IPv6 address of the packet
							DHCP_OUT['Destination_IP']=pkt[IPv6].dst
						#Dumping the whole json data into a DHCP log file
						DHCP_log.write('\n'+json.dumps(DHCP_OUT  ))

		# Getting additional ICMP argument as -i from the user in the program for sniffing
		if args.ICMP or args.Whole:

			#For packets having ICMP layer
			if pkt.haslayer(ICMP):
				#Changing the directory to store log files
				os.chdir(log_files_dir)
				#Opening ICMP log file to store logs with append rights
				ICMP_LOG=open("ICMP.log","a")

				# Classifying the network packets as Incoming based on Mac Address where the packet's Destination MAC Address Has my Mac Address				
				if My_MAC == pkt.dst: # IncommingICMP
					#Changing the colour of next line to Blue
					print("%s"%B)
					#Printing 117 '.' 
					print('.'*117)
					#Printing the time of incomming packet for logs consistency
					print("ICMP Incomming"+"  "+str("[")+str(time)+str("]"))
					#Printing some additional information of the packet
					print("ICMP-IN:{}".format(len(pkt[ICMP]))+" Bytes"+"    "+"SRC-MAC:"+str(pkt.src)+"    "+"DST-MAC:"+str(pkt.dst))				
					#Using try to make program comaptible with packet containing IPv6 Addresses
					try:
						#Printing Source and Destination IP address of the Incomming packet			
						print("IP-Version:"+str(pkt[IP].version)+"    "+"SRC-IP: "+str(pkt[IP].src)+ "    "+"DST-IP:  "+str(pkt[IP].dst))			
					#If the packet contains IPv6 Address this block of code gets executed
					except:
						#Printing Source and Destination IPv6 address of the Incomming packet			
						print("IP-Version:"+str(pkt[IPv6].version)+"    "+"SRC-IP: "+str(pkt[IPv6].src)+ "    "+"DST-IP:  "+str(pkt[IPv6].dst))			
					#Printing 117 '.'
					print('.'*117)
					#Opening the log file to store json data with appent rights
					ICMP_IN_log=open("ICMP_IN.log","a")
					#Creating a json object to store json data
					ICMP_IN={}
					#Classified packet as ICMP incoming packet
					ICMP_IN['Packet_Type']="ICMP-INCOMING"
					#Getting source MAC address of the packet
					ICMP_IN['Source_Mac']=pkt.src
					#Getting Destination MAC address of the apcket
					ICMP_IN['Destination_Mac']=pkt.dst
					#Getting time of the packet for logs consistency
					ICMP_IN['Time']=str(time)
					#Getting the sixe of the packet
					ICMP_IN['Packet_Size']=len(pkt)
					#Using try to make program comaptible with packet containing IPv6 Addresses
					try:
						#Getting Source IP address of the packet
						ICMP_IN['Source_IP']=pkt[IP].src
						#getting the Destination IP address of the packet
						ICMP_IN['Destination_IP']=pkt[IP].dst
					#If the packet contains IPv6 Address this block of code gets executed
					except:
						#Getting Source IPv6 address of the packet
						ICMP_IN['Source_IP']=pkt[IPv6].src
						#Getting Destination IPv6 address of the packet 
						ICMP_IN['Destination_IP']=pkt[IPv6].dst
					#Writing the data to the ICMP Incomming log file
					ICMP_IN_log.write('\n'+json.dumps(ICMP_IN))
					#Writting the data to the ICMP log file
					ICMP_LOG.write('\n'+json.dumps(ICMP_IN))

				# Classifying the network packets as Outgoing based on Mac Address where the packet's Source MAC Address Has my Mac Address				
				if My_MAC == pkt.src: # OutgoingICMP
					print("%s"%B) 
					print('.'*117)
					print("ICMP Outgoing"+"  "+str("[")+str(time)+str("]"))
					print("ICMP-OUT:{}".format(len(pkt[ICMP]))+" Bytes"+"    "+"SRC-MAC:"+str(pkt.src)+"    "+"DST-MAC:"+str(pkt.dst))
					#Using try to make program comaptible with packet containing IPv6 Addresses
					try:
						#Printing the Source and Destination IP address of the packet
						print("SRC-IP: "+str(pkt[IP].src)+ "    "+"DST-IP:  "+str(pkt[IP].dst))
					#If the packet contains IPv6 Address this block of code gets executed
					except:
						#Printing the Source and Destination IPv6 address of the packet
						print("SRC-IP: "+str(pkt[IPv6].src)+ "    "+"DST-IP:  "+str(pkt[IPv6].dst))
					#Printing 117 '.'
					print('.'*117)
					#ICMP Outgoing JSON dumps
					ICMP_OUT_log=open("ICMP_OUT.log","a")
					#Creating the json object to store data
					ICMP_OUT={}
					#Classified as ICMP Outgoing packet
					ICMP_OUT['Packet_Type']="ICMP-OUTGOING"
					#Getting the Source MAC address of the packet
					ICMP_OUT['Source_Mac']=pkt.src
					#Getting the Destination MAC address of the packet
					ICMP_OUT['Destination_Mac']=pkt.dst
					#Getting the time of the Outgoing packet for logs consistency
					ICMP_OUT['Time']=str(time)
					#Getting the size of the packet
					ICMP_OUT['Packet_Size']=len(pkt)
					#Using try to make program comaptible with packet containing IPv6 Addresses
					try:
						#Getting Source IP address of the packet
						ICMP_OUT['Source_IP']=pkt[IP].src
						#Getting the Destination IP address of the packet
						ICMP_OUT['Destination_IP']=pkt[IP].dst
					#If the packet contains IPv6 Address this block of code gets executed
					except:
						#Getting Source IPv6 address of the packet
						ICMP_OUT['Source_IP']=pkt[IPv6].src
						#Getting the Destination IPv6 address of the packet
						ICMP_OUT['Destination_IP']=pkt[IPv6].dst
					
					#Writing the data to the ICMP Outgoing log file
					ICMP_OUT_log.write('\n'+json.dumps(ICMP_OUT))				
					#Writing the data to the ICMP  log file
					ICMP_LOG.write('\n'+json.dumps(ICMP_OUT))
		
		# Getting additional ARP argument as -a from the user in the program for sniffing
		if args.ARP or args.Whole:

			#For packets having ARP Layer
			if pkt.haslayer(ARP):
				#Changing the directory to store the log files 
				os.chdir(log_files_dir)
				#Opening ARP log file to store json dumps with append rights
				ARP_LOG=open("ARP.log","a")

				# Classifying the network packets as Incoming based on Mac Address where the packet's Destination MAC Address Has my Mac Address				
				if My_MAC == pkt.dst: # IncommingARP 
					#Changing the colour of Next Line to Purple
					print("%s"%P)
					#Printing 117 '.'		
					print('.'*117)
					#Printing the timing of Incoming ARP packet
					print("ARP Incomming"+"  "+str("[")+str(time)+str("]"))
					#Prints different information of the Incoming ARP packets
					print("ARP-IN:{}".format(len(pkt[ARP]))+" Bytes"+"SRC-MAC:"+str(pkt.src)+"    "+"DST-MAC:"+str(pkt.dst))
					#Prints different information of the Incoming ARP packets
					print("REQ-CODE:"+str(pkt[ARP].op)+"    "+"ARP-SRC: "+str(pkt[ARP].psrc)+ "    "+"ARP-DST:  "+str(pkt[ARP].pdst))
					#Printing 117 '.'					
					print('.'*117)
					#Opening ARP Incoming log file to store json dumps with append rights
					ARP_IN_LOG=open("ARP_IN.log","a")
					#Creating json object for ARP Incoming packets
					ARP_IN={}
					#Getting time to mantain logs consistency
					ARP_IN['Time']=str(time)
					#Getting the Destination MAC Address of the packet
					ARP_IN['Destination Mac']=pkt.dst
					#Getting the source MAC Address of the packet
					ARP_IN['Source Mac']=pkt.src
					#Getting the source IP Address of the packet
					ARP_IN['Packet Source']=pkt[ARP].psrc
					#Getting the Destination IP Address of the packet
					ARP_IN['Packet Destination ']=pkt[ARP].pdst
					#Getting the size of the packet
					ARP_IN['Packet Size']=len(pkt)
					#Classified packet as ARP Incoming packet
					ARP_IN['PACKET_TYPE']='ARP INCOMING'
					#Getting the request code of the packet
					ARP_IN['Request Code']=pkt[ARP].op
					#Dumping all the json data in ARP log file
					ARP_LOG.write('\n'+json.dumps(ARP_IN))
					#Dumping the json data in the ARP Outgoing log filr
					ARP_IN_LOG.write('\n'+json.dumps(ARP_IN))	

				# Classifying the network packets as Outgoing based on Mac Address where the packet's Source MAC Address Has my Mac Address				
				if My_MAC == pkt.src: # OutgoingARP
					#Changes the Colour of Next Line to Purple
					print("%s"%P)		
					#Printing 117 '.'
					print('.'*117)
					#Prints the timing of the outgoing ARP packet
					print("ARP Outgoing"+"  "+str("[")+str(time)+str("]"))
					#Prints different information of the Outgoing ARP packets
					print("ARP-OUT:{}".format(len(pkt[ARP]))+" Bytes"+"    "+"SRC-MAC:"+str(pkt.src)+"    "+"DST-MAC:"+str(pkt.dst))
					#Prints Some information about the Outgoing ARP packet
					print("REQ-CODE:"+str(pkt[ARP].op)+"    "+"ARP-SRC: "+str(pkt[ARP].psrc)+ "    "+"ARP-DST:  "+str(pkt[ARP].pdst))
					#Printing 117 '.'
					print('.'*117)
					#Opening Arp outgoing log file with appending rights
					ARP_OUT_LOG=open("ARP_OUT.log","a")
					#Creating json object for ARP outgoing packets
					ARP_OUT={}
					#Getting time to mantain logs consistency
					ARP_OUT['Time']=str(time)
					#Getting the Destination MAC Address of the packet
					ARP_OUT['Destination Mac']=pkt.dst
					#Getting the source MAC Address of the packet
					ARP_OUT['Source Mac']=pkt.src
					#Getting the source IP Address of the packet
					ARP_OUT['Packet Source']=pkt[ARP].psrc
					#Getting the Destination IP Address of the packet
					ARP_OUT['Packet Destination ']=pkt[ARP].pdst
					#Getting the size of the packet
					ARP_OUT['Packet Size']=len(pkt)
					#Classified packet as ARP outgoing packet
					ARP_OUT['PACKET_TYPE']='ARP OUTGOING'
					#Getting the request code of the packet
					ARP_OUT['Request Code']=pkt[ARP].op
					#Dumping all the json data in ARP log file
					ARP_LOG.write('\n'+json.dumps(ARP_OUT))
					#Dumping the json data in the ARP Outgoing log filr
					ARP_OUT_LOG.write('\n'+json.dumps(ARP_OUT))


		#If User queries for the visualization of the program
		'''if args.Visualize:
			#Print an empty line
			print("")
			#Print the Visualization detail
			print("Visualizing the Network Traffic in Localhost at http://localhost:5601/")
			#Changing colour of another line to Yellow
			print("%s"%Y)
			#Displays Opening Kibana using figlet
			os.system('figlet Opening Kibana')
			#Changing colour of another line to Yellow
			print("%s"%W)
			#Print an empty line 
			print("")
			#Webbrowser is used to start the webbrowser and open the kibana dashboard
			webbrowser.get('firefox').open('http://localhost:5601/goto/128e9ad212d17d7131a02ec7bbbcf620')
			#Command to parse the logs and send it to elasticsearch database
			os.system('/usr/share/logstash/bin/logstash -f /etc/logstash/conf.d/json_read.conf')
			#Exiting the program after Completion of the previous command
			exit()'''

	# Exception handling to reduce error						
	# except Exception as error:   
	# increase error one increment for each error thrown
		# error=1

# Getting keyboard signal from the user
def keyboardInterruptHandler(signal, frame):
	# Terminates the program after the signal from user is sent
	print("")
	print("")
	#Printing The detection of Keyboard Interrupt and exiting the program
	print(" %s Keyboard Interrupt  has been Detected. Program is Terminating ..."%R)
	print("")
	os.system('figlet ThankYou')
	exit(0)
	exit(0)
# gets the signal for the ctrl + c for terminating the program
signal.signal(signal.SIGINT, keyboardInterruptHandler)

		
#The Main Function in Python to call variable
if __name__ == '__main__':
	args = parse_args()

#Using sniff function to sniff the Incoming/Outgoing packets in the interface
sniff(prn = pkthndler)
