import os
import logging as log
from scapy.all import IP, DNSRR, DNS, UDP, DNSQR
from netfilterqueue import NetfilterQueue


def dns_spoof(queue_number):
    net_queue = NetfilterQueue()
    os.system(f'')