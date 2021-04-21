
#!/usr/bin/python

from scapy.all import *
import sys
import os

# tos = 1: filename ; tos = 0: payload ; tos = 2: EOF
last_tos = 0

filename = ""
payload = b""

def process_packet(packet):
	global last_tos
	global filename
	global payload

	transfered_bytes = 0
	if type(filename) != str:
		filename = filename.decode()
	print("1: '{}'".format(filename))
	print("2: '{}'".format(os.path.splitext(os.path.basename(filename).rstrip())[0]))
	print("3: '{}'".format(str(packet[IP].src)))

	print("zob{}_az{}_er{}_ty{}".format(os.path.splitext(os.path.basename(filename).rstrip())[0] , str(packet[IP].src) , datetime.now().strftime('%Y%m%d%H%M%S') , os.path.splitext(os.path.basename(filename).rstrip())[1]))
	print("TOS : '{}'".format(packet.tos))
	if last_tos == 0 and packet.ttl > 100:
		filename = packet[ICMP].load[-len(packet[ICMP].load):].decode()

	elif last_tos > 100 and packet.ttl > 100:
		filename += packet[ICMP].load[-len(packet[ICMP].load):].decode()
	elif last_tos > 100 and packet.ttl > 60:
		filename = os.path.splitext(os.path.basename(filename).rstrip())[0] + "_" + str(packet[IP].src) + "_" + datetime.now().strftime('%Y%m%d%H%M%S') + os.path.splitext(os.path.basename(filename).rstrip())[1]
		print("Receiving file {}".format(filename))
		payload = packet[ICMP].load[-len(packet[ICMP].load):]
		transfered_bytes += len(payload)
		print("{} bytes transfered".format(transfered_bytes)),
	elif last_tos > 60 and packet.ttl > 60:
		print("6: '{}'".format(payload))
		print("7: '{}'".format(packet[ICMP].load))

		payload += packet[ICMP].load[-len(packet[ICMP].load):]
		transfered_bytes += len(payload)
		print("\r{} bytes transfered".format(transfered_bytes)),

	sys.stdout.flush()

	last_tos = packet.ttl

	if packet.ttl <= 60:
		print("\r\nWriting payload to file ({})...".format(filename)),
		print("5: '{}'".format(filename))
		with open(filename, "wb") as fh:
		#fh = open(filename,"w+")
			fh.write(payload)
	
		print("done!")
		print("4: '{}'".format(payload))
		last_tos = 0


if len(sys.argv) == 1:
        print("Sniffing on all interfaces.")
else:
        if sys.argv[1] == "-h":
                print("Usage: {0} [<iface>]. Example: {0} eth0".format(sys.argv[0]))
                exit()
        else:
                print("Sniffing interface: {}.".format(sys.argv[1]))

sniff(filter="inbound and icmp[icmptype] == 8", prn=process_packet)
