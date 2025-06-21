import socket
from IPy import IP

print("\n")
ip_addresses = input("[+] Enter target IP addresses: ").split(", ")
ports_range = input("[+] Enter ports range: ").split("-")
print("\n")
connected_ports = []

def check_ip(ip):
    try:
        IP(ip)
        return ip
    except ValueError:
        return socket.gethostbyname(ip)

def get_banner(s):
    return s.recv(1024)

def scan_port(ip, port):
    try:
        sock = socket.socket()
        sock.settimeout(0.25)
        sock.connect((ip, port))
        try:
            banner = get_banner(sock)
            print(f"[+] Connection successful, port {port} is open")
            print(f"[+] Banner: {str(banner.decode().strip('\n'))}\n")
        except:
            print(f"[+] Connection successful, port {port} is open")
            print("[-] Banner not received\n")
        connected_ports.append(port)
    except:
        pass

def scan_ports(ip, ports):
    for port in range(int(ports_range[0]), int(ports_range[1]) + 1):
        scan_port(ip, port)

def main():
    open_ports = []
    for ip in ip_addresses:
        print(f"[---] Scanning IP: {ip}\n")
        scan_ports(check_ip(ip), ports_range)
        open_ports.append(connected_ports.copy())
        connected_ports.clear()
        print("\n")
    print(f"[+] Open ports for all IPs relatively: {open_ports}")

if __name__ == "__main__":
    main()
