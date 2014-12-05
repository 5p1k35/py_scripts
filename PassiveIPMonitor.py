#!/usr/bin/python

from scapy.all import *
import sys
import time
import os

ipv4 = {}   # ipv4[integer_ip] = (count,last_seen,mac,other)
ipv6 = {}

def print_data():
	os.system('clear')
	print "%-18s%5s" % ("IP","Time")
	tmp_list = ipv4.keys()
	tmp_list.sort()
	for key in tmp_list:
		print "%-18s%5ss" % (i2q(key),(int(time.time()) - ipv4[key][1]))
		print "\t%s" % str(ipv4[key][2])
		print "\t%s" % ipv4[key][4]
	tmp_list = ipv6.keys()
	tmp_list.sort()
	for key in tmp_list:
		print "%-18s%5ss" % (key,(int(time.time()) - ipv6[key][1]))
		print "\t%s" % str(ipv6[key][2])


def i2q(num):
	ip = [0,0,0,0]
	ip[0] = int(num) / 256 ** 3
	num %= 256 ** 3
	ip[1] = int(num) / 256 ** 2
	num %= 256 ** 2
	ip[2] = int(num) / 256 
	ip[3] = num % 256
	return str(ip[0])+"."+str(ip[1])+"."+str(ip[2])+"."+str(ip[3])
	
def q2i(num):
	num = num.split(".")
	return int(num[0]) * (256 **3) + int(num[1]) * (256 **2) + int(num[2]) * (256) + int(num[3])

def hardwork(pkt):
	if IP in pkt:
		if q2i(pkt[IP].src) in ipv4:
			if ipv4[q2i(pkt[IP].src)][1] <= int(time.time()):
				ipv4[q2i(pkt[IP].src)][0] += 1
				ipv4[q2i(pkt[IP].src)][1] = int(time.time())
				if not str(pkt[Ether].src) in ipv4[q2i(pkt[IP].src)][2]:
					ipv4[q2i(pkt[IP].src)][2].append(str(pkt[Ether].src))
				else:
					ipv4[q2i(pkt[IP].src)][2][0] = (str(pkt[Ether].src))
				if TCP in pkt and (int(pkt[TCP].flags) == 18):
					if pkt[TCP].sport in ipv4[q2i(pkt[IP].src)][4].keys():
						ipv4[q2i(pkt[IP].src)][4][pkt[TCP].sport] += 1
					else:
						ipv4[q2i(pkt[IP].src)][4][pkt[TCP].sport] = 1
		else:
#			ipv4[integer_IP] = [count,last_time_seen,[list of mac addresses],"not used yet",{dictionary of tcp ports with associated count}, {dictionary of udp ports}]
			ipv4[q2i(pkt[IP].src)] = [1,int(time.time()),[str(pkt[Ether].src)],"",{},{}]
#			print "added",pkt[IP].src
	elif IPv6 in pkt:
		if pkt[IPv6].src in ipv6:
			if ipv6[pkt[IPv6].src][1] <= int(time.time()):
				ipv6[pkt[IPv6].src][0] += 1
				ipv6[pkt[IPv6].src][1] = int(time.time())
				if not str(pkt[Ether].src) in ipv6[pkt[IPv6].src][2]:
					ipv6[pkt[IPv6].src][2].append(str(pkt[Ether].src))
				else:
					ipv6[pkt[IPv6].src][2][0] = str(pkt[Ether].src)
		else:
			ipv6[pkt[IPv6].src] = [1,int(time.time()),[str(pkt[Ether].src)],""]
	if len(sys.argv) == 1:
		print_data()
	
	
def main():
	print len(sys.argv)
	if len(sys.argv) > 1:
		print "Going to use",sys.argv[1]
		sniff(offline=sys.argv[1],prn=hardwork,store=0)
		print_data()
	else:
		print "Sniffing the wire"
		sniff(prn=hardwork,store=0)

if __name__ == '__main__':
	main()
