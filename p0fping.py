#!/usr/bin/python

import argparse
from random import randint 
from scapy.all import *
import time
import socket

pofbase = {"name":['formats']}

def init():
	
	parser = argparse.ArgumentParser()
	parser.add_argument('-p','--ports',help='Ports to Scan (eg... 21-23,25)',dest='ports',required=True)
	parser.add_argument('-t','--target',help='IP of target',dest='target',required=True)
	parser.add_argument('-f','--fingerprint',help='p0f Finger Print',dest='fp',required=False)
	parser.add_argument('-n','--number',help='p0f Finger Print number (Which of the fingerprints associated with the -f/--fingerprint) (eg... 1)',type=int,dest='val',required=False)
	args = vars(parser.parse_args())
	
	user_ports = args['ports'].split(",")									#convert user input to list for scapy
	new_ports = []
	for port in user_ports:
		if (not type(port) is int) and (port.isdigit()):
			new_ports.append(int(port))
		elif (port.find("-") >=0):
			port=port.split("-")
			for a in range(int(port[0]),int(port[1])+1):
				new_ports.append(a)
	if not args['val'] == None:
		args['val'] -= 1
	return (args['target'],new_ports,args['fp'],args['val'])		

def importData():
	data_portion = 0
	data_done = 0
	label = ""
	
	for line in open('/usr/share/p0f/p0f.fp','r').readlines():
		if line.rstrip() == "[tcp:request]":
			data_portion = 1
			continue
		elif line.rstrip() == "[http:request]":
			data_done = 1
			break
		if ( not (line[0] == ";" or line[0] == "\n") ) and ( data_portion == 1 and data_done == 0 ):
			linesplit = line.rstrip().split('=')
			if len(linesplit) >= 2:
				if linesplit[0].rstrip() == "label":
					label = linesplit[1].replace(" ","")					
					continue
				elif linesplit[0].rstrip() == "sig":
					if not label in pofbase.keys():
						pofbase[label] = [linesplit[1].lstrip()]
					else:
						pofbase[label].append(linesplit[1].lstrip())

def send_packet(label,value,ports,target):
	print "-"*20
	print "\nSending packets with the following data"
	print "\tFP Label:",label
	print "\tp0f FP:",pofbase[label][value]
	print "\tTarget(s):",target
	print "\tPort(s):",ports
	print "-"*20+"\n"
	mtu=1500
	options = []
	data = pofbase[label][int(value)].split(":")
	ip = IP(dst=target,ttl=int(data[1].replace('-','')))
	tcp = TCP(flags="S",seq=randint(1,65000))
	
	#sig = ver:ittl:olen:mss:wsize,scale:olayout:quirks:pclass 
	if not data[3] == "*":
		mss = int(data[3])
	else:
		mss = 536

	if not data[4] == "*":
		winders = data[4].split(',')
		if "*" in winders[0]:
				chunk = winders[0].split("*")
				if chunk[0] == "mss":
					wsize = mss*int(chunk[1])
				elif chunk[0] == "mtu":
					wsize = mtu*int(chunk[1])
		else:
			wsize = int(winders[0])
		if winders[1] == "*":
			wscale = 1
		else:
			wscale = int(winders[1])
	tcp.window = wsize
	for option in data[5].split(","):
		if option == "mss":
			options.append(('MSS',int(mss)))
		elif option == "nop":
			options.append(('NOP',None))
		elif option == "ws":
			options.append(('WScale',int(wscale)))
		elif option == "ts":
			ts = [randint(1,1280000),0]
			if "ts1-" in data[6].split(','):
				ts[0] = 0
			if "ts2+" in data[6].split(','):
				ts[1] = randint(1,1280000)
			options.append(('Timestamp',(ts[0],ts[1])))
		elif option == "sok":
			options.append(('SAckOK', ''))
		elif option.contains("eol"):
			options.append(('EOL',''))
			if len(option.split("+")) >= 2:
				padding = " "*int(option.split("+")[1])
	
	for quirks in data[6].split(","):
		if quirks == "df":
			ip.flags += 2
		elif quirks == "id+":
			ip.id = 1
		elif quirks == "id-":
			ip.id = 0
		elif quirks == "0+":
			ip.flags += 1
		elif quirks == "seq-":
			tcp.seq = 0
		elif quirks == "ack+":
			tcp.ack == 1
			tcp.flags %= 16
		elif quirks == "ack-":
			tcp.ack == 0
			tcp.flags += 16
		elif quirks == "uptr+":
			tcp.urgptr = 1
			tcp.flags %= 32
		elif quirks == "urgf+":
			tcp.flags += 32
		elif quirks == "pushf+":
			tcp.flags += 8
			
	tcp.options = (options)
			
	tcp.sport = randint(1024,65000)		
	tcp.dport = ports
	pkt = ip/tcp
	ans,unans = sr(pkt,timeout=5,verbose=0)						#send packet(s)
	responses = {}
	if len(ans) == 0:												#no responses :(
		print "\tNo Response Possibly Filtered"
	else:
		ra_ports = [] #20											parse output results
		for s,r in ans:
			#print r.sprintf("\t%IP.src% %TCP.sport%\t Responded %TCP.flags%")
			if r[TCP].flags == 20: 	
				if r[IP].src in responses.keys():
					responses[r[IP].src][1] += str(r[TCP].sport)+","
				else:
					responses[r[IP].src] = ["",str(r[TCP].sport)+","]
			else:
				if r[IP].src in responses.keys():
					responses[r[IP].src][0] += ","+str(r[TCP].sport)
				else:
					responses[r[IP].src] = [str(r[TCP].sport)+",",""]
		ips = sorted(responses.keys(), key=lambda x:tuple(map(int, x.split('.'))))
		for ip in ips:
			sa = responses[ip][0].split(',')
			sa.sort()
			sa = " ".join(sa)
			ra = responses[ip][1].split(',')
			ra.sort()
			ra = " ".join(ra)
			print "%s\n\tSynAck Recvd:\t%s\n\tRstAck Recvd:\t%s" % (ip,sa,ra)

def getfp(fp,val):
	if fp == None:
		fp = ":"
	found = []
	for line in pofbase.keys():
		if fp in line:
			found.append(line)
	count = 1
	found.sort()
	if not len(found) == 1:
		for line in found:
			print "%d\t%s" % (count,line)
			count += 1
		print "-"*30
		userInput = raw_input("Which Fingerprint? (1)") or "1"
		while not int(userInput) in range(1,len(found)+1):
			print "\n%d selected, but not an option" % (int(userInput))
			userInput = raw_input("Which Fingerprint? ")
		fp = found[int(userInput)-1]
	
	if not val == None:
		return (fp,val)
	elif len(pofbase[fp]) == 1:
		val = 0
	else:
		count = 1
		for val in pofbase[fp]:
			print "%d\t%s" % (count,val)
			count += 1
		print "-"*30
		userInput= raw_input("Which Fingerprint Version? (1) ") or "1"
		while not int(userInput) in range(1,len(pofbase[fp])+1):
			print "\n%d selected, but not an option" % (int(userInput))
			userInput = raw_input("Which Fingerprint Version? ")
		val = int(userInput)-1
	return (fp,val)
	
def main():
	print "\033c"
	myargs = init()
	importData()
	fp,val = getfp(myargs[2],myargs[3])
	send_packet(fp,val,myargs[1],myargs[0])
	return 0

if __name__ == '__main__':
	main()
