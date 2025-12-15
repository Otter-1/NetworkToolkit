#!/usr/bin/env python3

import signal
from pathlib import Path
import os
import subprocess
import time
import socket
from datetime import datetime as dt
from scapy.all import *


# --- GLOBAL VARIABLES FOR TOOLS ---
# Used by SYN Detector
syn_historique = {}
# Used by OS Fingerprinting
os_seen_ips = set()

stop_sniffing = False

CURRENT_DIR=os.getcwd()

# --- CONFIG ---
TOOLS_DIR = "./tools"
BASH_SCRIPT_NAME = "subnet_scanner.sh"


# --- UI UTILITIES ---
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    PINK = '\033[95m'
    GREEN = '\033[92m'
    RED = '\033[91m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
#print(print("\x1b]11;rgb:f2/f0/ef\x07"))
BANNER = f"""{Colors.RED}
░▒▓███████▓▒░░▒▓████████▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░         ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░         ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓██████▓▒░    ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓███████▓▒░  
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░         ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░         ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░  ░▒▓█▓▒░    ░▒▓█████████████▓▒░ ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
                                                                                                    
                                                                                                    
░▒▓████████▓▒░▒▓██████▓▒░ ░▒▓██████▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓████████▓▒░                
   ░▒▓█▓▒░  ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░  ░▒▓█▓▒░                    
   ░▒▓█▓▒░  ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░  ░▒▓█▓▒░                    
   ░▒▓█▓▒░  ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓███████▓▒░░▒▓█▓▒░  ░▒▓█▓▒░                    
   ░▒▓█▓▒░  ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░  ░▒▓█▓▒░                    
   ░▒▓█▓▒░  ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░  ░▒▓█▓▒░                    
   ░▒▓█▓▒░   ░▒▓██████▓▒░ ░▒▓██████▓▒░░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░  ░▒▓█▓▒░                    
                                                                                                    
                                                                                                                                                                                                    
      {Colors.HEADER}>> Network Toolkit v2.0 <<{Colors.ENDC}
"""

def print_error(msg):
    print(f"{Colors.FAIL}✖ {msg}{Colors.ENDC}")

def print_success(msg):
    print(f"{Colors.GREEN}✔ {msg}{Colors.ENDC}")

def print_info(msg):
    print(f"{Colors.BLUE}ℹ {msg}{Colors.ENDC}")

# ==========================================
# TOOL 1: PACKET SNIFFER (INTERACTIVE)
# ==========================================
def handle_ctrl_c(signum, frame):
    global stop_sniffing
    print("\n[!] User pressed CTRL+C. Exiting...")
    stop_sniffing = True
    
    raise KeyboardInterrupt


def sniffer_get_target_filter():
    cond = input(f"{Colors.BLUE}Do you want to target a specific IP (y/n)? {Colors.ENDC}").strip().lower()
    if cond == "y":
        target = input("Enter the IP: ").strip()
        return f"host {target}"
    return None

def sniffer_process_packet(pkt):
    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        src = pkt[IP].src
        dst = pkt[IP].dst
        flag = pkt[TCP].flags

        if flag == "S":
            print(f"{src} ----> {dst} : SYN")
        elif flag == "A" or flag == ".": 
            print(f"{src} ----> {dst} : ACK")
        elif flag == "F":
            print(f"{src} ----> {dst} : FIN")
        elif flag == "P":
            print(f"{src} ----> {dst} : PSH")
        elif flag == "U":
            print(f"{src} ----> {dst} : URG")
        elif flag == "R":
            print(f"{src} ----> {dst} : RST")

    elif pkt.haslayer(IP) and pkt.haslayer(UDP):
        src = pkt[IP].src
        dst = pkt[IP].dst
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
        print(f"{src}:{src_port} -----> {dst}:{dst_port}")

def sniffer_start_sniffer():
    filters = sniffer_get_target_filter()
    print_info("--------- Starting Sniffing ---------")
    print("Press CTRL+C to stop...")
    signal.signal(signal.SIGINT, handle_ctrl_c)
    start = time.time()
    while True:
        if stop_sniffing:
            break
        try:
            # We add stop_filter to ensure we can still exit cleanly
            sniff(filter=filters, prn=sniffer_process_packet, store=0)
            # 5. Sniff returned. Why?
            if stop_sniffing:
                # It returned because user pressed CTRL+C
                end = time.time()
                time_taken = end - start
                print_info("\nSniffing stopped by user.")
                print_success(f"Execution time : {time_taken:.2f} seconds")
                break # Actually exit the program
                
            else:
                
                continue

            
        except KeyboardInterrupt:
            break
        except Exception:
            # If the socket crashes, we just pass and the loop restarts sniffing
            continue
    

# ==========================================
# TOOL 2: PORT SCANNER
# ==========================================

def port_scanner_scan(target):
    import_ports = [21, 22, 23, 25, 80, 110, 443]
    openports = []
    
    print("*" * 40)
    print(f"Scanning target: {target}")
    print(str(dt.now()))
    print("*" * 40)

    try:
        for port in import_ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((target, port))
            
            if result == 0:
                print_success(f"Port open: {port}")
                openports.append(port)
            else:
                print(f"{Colors.FAIL}Closed: {port}{Colors.ENDC}")
            s.close()
    except KeyboardInterrupt:
        print("\nScan interrupted.")
    except socket.gaierror:
        print_error("Hostname could not be resolved.")
    except socket.error:
        print_error("Could not connect to server.")
    

def port_scanner_start():
    target_input = input(f"{Colors.BLUE}Enter Target IP/Host: {Colors.ENDC}").strip()
    if not target_input:
        print_error("No target provided.")
        return
    
    try:
        target_ip = socket.gethostbyname(target_input)
        port_scanner_scan(target_ip)
    except Exception as e:
        print_error(f"Error: {e}")

# ==========================================
# TOOL 3: SUBNET SCANNER (BASH WRAPPER)
# ==========================================

def subnet_scanner_run():
    # initializing working directory
    loc = Path(__file__).resolve().parent
    try:
        os.chdir(loc)
        print_info(f"Directory changed to: {os.getcwd()}")
    except FileNotFoundError:
        print_error(f"The folder {loc} does not exist.")
        return
    # 1. Check if script exists
    script_path = os.path.join(TOOLS_DIR, BASH_SCRIPT_NAME)
    if not os.path.isfile(script_path):
        print_error(f"Bash script not found at: {script_path}")
        print("Please ensure 'tools/subnet_scanner.sh' exists.")
        return

    # 2. Get Inputs
    subnet = input(f"{Colors.BLUE}Enter Subnet (e.g., 192.168.1): {Colors.ENDC}").strip()
    filename = input(f"{Colors.BLUE}Enter Output Filename (no extension): {Colors.ENDC}").strip()

    if not subnet or not filename:
        print_error("Invalid input.")
        return

    # 3. Execute Bash Script
    print_info(f"Launching {BASH_SCRIPT_NAME}...")
    try:
        # We assume the bash script takes arguments: $1=subnet, $2=filename
        subprocess.run(["bash", script_path, subnet, filename], check=True)
    except subprocess.CalledProcessError as e:
        print_error(f"Script failed with exit code {e.returncode}")
    except KeyboardInterrupt:
        print("\nInterrupted.")

# ==========================================
# TOOL 4: SYN SCAN DETECTOR
# ==========================================

def syn_detector_callback(pkt):
    global syn_historique
    seuille = 5
    temp = 3
    
    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        flags = pkt[TCP].flags
        src = pkt[IP].src
        # 0x02 is SYN flag
        if flags == 0x02:
            now = time.time()
            if src not in syn_historique:
                syn_historique[src] = []
            
            syn_historique[src].append(now)
            # Keep only timestamps within the window (temp)
            syn_historique[src] = [t for t in syn_historique[src] if now - t <= temp]
            
            if len(syn_historique[src]) >= seuille:
                print(f"{Colors.WARNING}[ALERT] {src} is possibly scanning you!{Colors.ENDC}")

def syn_detector_start():
    global syn_historique
    syn_historique = {} # Reset history on start
    
    print_info("--------- Starting SYN Scan Detection ---------")
    print("Passively listening for SYN floods. Press CTRL+C to stop.")
    
    try:
        start = time.time()
        sniff(prn=syn_detector_callback, store=0)
    except KeyboardInterrupt:
        end = time.time()
        print(f"\nExecution time : {end - start:.2f} seconds")

# ==========================================
# TOOL 5: OS FINGERPRINTING
# ==========================================

def os_fingerprint_detect_os(ttl):
    if ttl <= 64:
        return "Linux/Android"
    elif ttl <= 128:
        return "Windows"
    elif ttl <= 255:
        return "Cisco/Network Device"
    else:
        return "Unknown"

def os_fingerprint_callback(packet):
    global os_seen_ips
    
    if IP in packet:
        src = packet[IP].src
        
        if src in os_seen_ips:
            return  

        os_seen_ips.add(src)  

        ttl = packet[IP].ttl
        os_guess = os_fingerprint_detect_os(ttl)

        print(f"{Colors.GREEN}[+] {src:<15} | TTL = {ttl:<5} | OS Guess: {os_guess}{Colors.ENDC}")

def os_fingerprint_start():
    global os_seen_ips
    os_seen_ips = set() # Reset on start
    
    print_info("--------- Starting Passive OS Fingerprinting ---------")
    print("Analyzing TTL values from incoming traffic. Press CTRL+C to stop.")
    
    try:
        sniff(filter="ip", prn=os_fingerprint_callback, store=False)
    except KeyboardInterrupt:
        print("\nStopped.")

# ==========================================
# MAIN MENU LOGIC
# ==========================================

MENU_OPTIONS = {
    "1": {"label": "Packet Sniffer", "func": sniffer_start_sniffer},
    "2": {"label": "Port Scanner", "func": port_scanner_start},
    "3": {"label": "Subnet Scanner (Bash)", "func": subnet_scanner_run},
    "4": {"label": "SYN Scan Detector", "func": syn_detector_start},
    "5": {"label": "OS Fingerprinting", "func": os_fingerprint_start},
}

def main():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print(BANNER)
        
        # Check root privileges (Needed for Scapy)
        if os.geteuid() != 0:
            print(f"{Colors.WARNING}⚠ WARNING: Not running as root. Sniffing tools will fail.{Colors.ENDC}")
            print(f"{Colors.WARNING}  Try running with: sudo python3 cli.py{Colors.ENDC}\n")

        print(f"{Colors.BOLD}SELECT A TOOL:{Colors.ENDC}\n")

        for key, option in MENU_OPTIONS.items():
            print(f" {Colors.RED}[{key}]{Colors.ENDC} {option['label']}")
        
        print(f" {Colors.RED}[q]{Colors.ENDC} Quit")

        choice = input(f"\n{Colors.BOLD}> {Colors.ENDC}").strip().lower()

        if choice == 'q':
            print("""
░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓█▓▒░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░ 
░▒▓███████▓▒░ ░▒▓██████▓▒░░▒▓██████▓▒░ ░▒▓█▓▒░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░                    
░▒▓███████▓▒░   ░▒▓█▓▒░   ░▒▓████████▓▒░▒▓█▓▒░▒▓█▓▒░ 
                                                     
Thank you for using Network Toolkit v2.0!""")
            break
        elif choice in MENU_OPTIONS:
            # Execute the mapped function
            try:
                MENU_OPTIONS[choice]["func"]()
            except Exception as e:
                print_error(f"Critical Tool Error: {e}")
            
            input(f"\n{Colors.BLUE}Press Enter to return to menu...{Colors.ENDC}")
        else:
            print_error("Invalid option")
            time.sleep(1)

if __name__ == "__main__":
    main()