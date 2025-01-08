import time
from scapy.all import *
import docker
import sys
import random

# Function to get Docker container IP address
def get_container_ip(container_name):
    client = docker.from_env()
    try:
        container = client.containers.get(container_name)
        networks = container.attrs['NetworkSettings']['Networks']
        if networks:
            for net in networks.values():
                ip_address = net['IPAddress']
                if ip_address:
                    print(f"Found container '{container_name}' with IP: {ip_address}")
                    return ip_address
        raise ValueError("IP address not found in container network settings.")
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

# Function to generate a random IP address
def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

# Packet sending functions
def send_tcp(src_ip):
    for _ in range(10):  # Send more TCP packets
        pkt = IP(dst=target_ip, src=src_ip)/TCP(dport=443, flags="S")  # Target HTTPS port
        send(pkt, verbose=False)
        print("Sent TCP packet to", target_ip, "from", pkt[IP].src)

def send_udp(src_ip):
    pkt = IP(dst=target_ip, src=src_ip)/UDP(dport=53)/Raw(load="GET / HTTP/1.1\r\n")
    send(pkt, verbose=False)
    print("Sent UDP packet to", target_ip, "from", pkt[IP].src)

def send_icmp(src_ip):
    if random.randint(1, 100) <= 5:  # Reduced ICMP frequency
        pkt = IP(dst=target_ip, src=src_ip)/ICMP()
        send(pkt, verbose=False)
        print("Sent ICMP packet to", target_ip, "from", pkt[IP].src)

def send_ftp(src_ip):
    pkt = IP(dst=target_ip, src=src_ip)/TCP(dport=21, flags="S")
    send(pkt, verbose=False)
    print("Sent FTP packet to", target_ip, "from", pkt[IP].src)

def send_ssh(src_ip):
    if random.randint(1, 100) <= 10:  # Reduced SSH frequency
        pkt = IP(dst=target_ip, src=src_ip)/TCP(dport=22, flags="S")
        send(pkt, verbose=False)
        print("Sent SSH packet to", target_ip, "from", pkt[IP].src)

def send_telnet(src_ip):
    if random.randint(1, 100) <= 5:  # Reduced Telnet frequency
        pkt = IP(dst=target_ip, src=src_ip)/TCP(dport=23, flags="S")
        send(pkt, verbose=False)
        print("Sent Telnet packet to", target_ip, "from", pkt[IP].src)

def send_arp(src_ip):
    pkt = ARP(op=1, pdst=target_ip, psrc=src_ip)  # Replace with your gateway IP
    send(pkt, verbose=False)
    print("Sent ARP packet to", target_ip, "from", pkt[ARP].psrc)

# Main function to continuously send packets
def continuous_packets():
    counter = 0
    packet_count = 0
    current_src_ip = random_ip()
    try:
        while True:
            send_tcp(current_src_ip)
            send_udp(current_src_ip)

            if counter % 50 == 0:  # Reduced frequency for FTP, SSH, and Telnet
                send_ftp(current_src_ip)
                send_ssh(current_src_ip)
                send_telnet(current_src_ip)

            if counter % 100 == 0:  # Reduced frequency for ICMP
                send_icmp(current_src_ip)

            if counter % 60 == 0:  # Every 60th iteration (1 minute)
                send_arp(current_src_ip)

            packet_count += 1

            # Change source IP after 50 packets
            if packet_count >= 50:
                current_src_ip = random_ip()
                packet_count = 0
                print("Switched to new source IP:", current_src_ip)

            counter += 1
            time.sleep(1)  # Sleep for 1 second
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt detected. Stopping packet sending.")

if __name__ == "__main__":
    print("Starting to send continuous packets to", target_ip)
    continuous_packets()
