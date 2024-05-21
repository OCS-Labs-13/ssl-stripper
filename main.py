import sys
import signal
from termcolor import colored
import scripts.arp_poisoner as arp_poisoner

VERSION = "1.0"

CONFIG = {
    "arp": {
        "target": None,
        "gateway": None,
        "interval": 30  # Interval in seconds between ARP requests for ARP spoofing
    }
}


def parse_args():
    args = [[sys.argv[i], sys.argv[i + 1]] for i in range(1, len(sys.argv) - 1) if sys.argv[i].startswith("-")]

    try:
        for i, arg in enumerate(args):
            if arg[0] == "-h" or arg[0] == "--help":
                print("Usage: python main.py")
                print("Prints the TU/e logo in ASCII art.")
                sys.exit(0)
            elif arg[0] == "-v" or arg[0] == "--version":
                print("ASCII Art TU/e logo v1.0")
                sys.exit(0)
            elif arg[0] == "-t":
                CONFIG["arp"]["target"] = arg[1]
            elif arg[0] == "-aI":
                value = int(arg[1])
                if value < 1:
                    print(f"Error: Invalid value for argument '{arg[0]}': '{arg[1]}'")
                    sys.exit(1)
                CONFIG["arp"]["interval"] = value
            else:
                print(f"Error: Unknown argument '{arg[0]}': '{arg[1]}'")
                print("Use -h or --help for usage information.")
                sys.exit(1)
    except ValueError:
        print(f"Error: Invalid value for argument '{args[i][0]}': '{args[i][1]}'")
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

    dash = """
    
        
        
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

    art = '\n'.join(' '.join(pair) for pair in zip(*(s.split('\n') for s in (logo, dash, title))))

    print(colored(art, "light_red"))


def print_welcome():
    print_art()

    print(f"{colored("Automated SSL Stripper", "light_green")} by "
          f"{colored("group 13", "blue")} made for the course "
          f"{colored("2IC80 - Lab on Offensive Computer Security", "red")}.")
    print(f"Version: {VERSION}")

    print("\nUse -h or --help for usage information.\n")


def start():
    # Register signal handler
    signal.signal(signal.SIGINT, lambda sig, frame: print("Terminating program...") or sys.exit(0))

    target_ip = CONFIG["arp"]["target"]
    poisoning_interval = CONFIG["arp"]["interval"]
    gateway_ip = CONFIG["arp"]["gateway"]

    # Run ARP poisoning script with configured parameters
    arp_poisoner.start(target_ip, poisoning_interval, gateway_ip)

    # RUN ADDITIONAL SCRIPTS HERE


if __name__ == '__main__':
    parse_args()
    print_welcome()
    start()
