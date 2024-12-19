import time
from scapy.all import *
import docker
import sys

# Function to get Docker container IP address
def get_container_ip(container_name):
    client = docker.from_env()
    try:
        container = client.containers.get(container_name)
        ip_address = container.attrs['NetworkSettings']['IPAddress']
        if not ip_address:
            raise ValueError("IP address not found.")
        print(f"Found container '{container_name}' with IP: {ip_address}")
        return ip_address
    except docker.errors.NotFound:
        print(f"Error: Container '{container_name}' not found.")
        sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

# Get target IP dynamically
target_ip = get_container_ip("my-net-mon")

# Validate target IP
if not target_ip or target_ip == "0.0.0.0":
    print("Invalid target IP address.")
    sys.exit(1)

# Packet sending functions
def send_icmp():
    pkt = IP(dst=target_ip)/ICMP()
    send(pkt, verbose=False)
    print("Sent ICMP packet to", target_ip)

def send_udp():
    pkt = IP(dst=target_ip)/UDP(dport=53)/Raw(load="GET / HTTP/1.1\r\n")
    send(pkt, verbose=False)
    print("Sent UDP packet to", target_ip)

def send_tcp():
    pkt = IP(dst=target_ip)/TCP(dport=80, flags="S")
    send(pkt, verbose=False)
    print("Sent TCP packet to", target_ip)

def send_ftp():
    pkt = IP(dst=target_ip)/TCP(dport=21, flags="S")
    send(pkt, verbose=False)
    print("Sent FTP packet to", target_ip)

def send_ssh():
    pkt = IP(dst=target_ip)/TCP(dport=22, flags="S")
    send(pkt, verbose=False)
    print("Sent SSH packet to", target_ip)

def send_telnet():
    pkt = IP(dst=target_ip)/TCP(dport=23, flags="S")
    send(pkt, verbose=False)
    print("Sent Telnet packet to", target_ip)

def send_dns():
    pkt = IP(dst=target_ip)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com"))
    send(pkt, verbose=False)
    print("Sent DNS request packet to", target_ip)

def send_dhcp():
    pkt = Ether()/IP(src="0.0.0.0", dst="255.255.255.255")/UDP(sport=68, dport=67)/BOOTP(chaddr="00:11:22:33:44:55")/DHCP(options=[("message-type", "discover"), "end"])
    sendp(pkt, verbose=False)
    print("Sent DHCP Discover packet")

# Main function to continuously send packets
def continuous_packets():
    try:
        while True:
            send_icmp()
            send_udp()
            send_tcp()
            send_ftp()
            send_ssh()
            send_telnet()
            send_dns()
            send_dhcp()
            time.sleep(1)  # Sleep for 1 second before sending more packets
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt detected. Stopping packet sending.")

if __name__ == "__main__":
    print("Starting to send continuous packets to", target_ip)
    continuous_packets()
