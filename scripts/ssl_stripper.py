import os
import logging as log
import re
from scapy.all import IP, DNSRR, DNS, UDP, DNSQR, TCP
from scapy.layers.http import *
from netfilterqueue import NetfilterQueue


class SslStrip:
	def __init__(self, hostDict, queueNum):
		self.hostDict = hostDict
		self.queueNum = queueNum
		self.queue = NetfilterQueue()

	def __call__(self):
		log.info("Stripping....")
		os.system(
			f'iptables -I INPUT -j NFQUEUE --queue-num {self.queueNum}')
		self.queue.bind(self.queueNum, self.callBack)
		try:
			self.queue.run()
		except KeyboardInterrupt:
			os.system(
				f'iptables -D INPUT -j NFQUEUE --queue-num {self.queueNum}')
			log.info("[!] iptable rule flushed")

	def callBack(self, packet):		
		scapyPacket = IP(packet.get_payload())	
		if TCP in scapyPacket and scapyPacket[TCP].dport==80:
			print(scapyPacket.summary())
		return packet.accept()


if __name__ == '__main__':
	try:
		hostDict = {
			b"google.com.": "10.0.123.7",
			# b"facebook.com.": "10.0.123.7",
			# b"youtube.com": "10.0.123.7"
		}
		queueNum = 2
		log.basicConfig(format='%(asctime)s - %(message)s', 
						level = log.INFO)
		strip = SslStrip(hostDict, queueNum)
		strip()
	except OSError as error:
		log.error(error)