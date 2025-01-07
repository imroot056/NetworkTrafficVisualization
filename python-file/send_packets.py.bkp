import time
from scapy.all import *
import docker
import sys

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

# Packet sending functions
def send_tcp():
    pkt = IP(dst=target_ip)/TCP(dport=80, flags="S")
    send(pkt, verbose=False)
    print("Sent TCP packet to", target_ip)

def send_udp():
    pkt = IP(dst=target_ip)/UDP(dport=53)/Raw(load="GET / HTTP/1.1\r\n")
    send(pkt, verbose=False)
    print("Sent UDP packet to", target_ip)

def send_icmp():
    pkt = IP(dst=target_ip)/ICMP()
    send(pkt, verbose=False)
    print("Sent ICMP packet to", target_ip)

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

def send_arp():
    pkt = ARP(op=1, pdst=target_ip, psrc="192.168.1.1")  # Replace with your gateway IP
    send(pkt, verbose=False)
    print("Sent ARP packet to", target_ip)

# Main function to continuously send packets
def continuous_packets():
    counter = 0
    try:
        while True:
            send_tcp()
            send_udp()

            if counter % 10 == 0:  # Every 10th iteration (10 seconds)
                send_ftp()
                send_ssh()
                send_telnet()

            if counter % 30 == 0:  # Every 30th iteration (30 seconds)
                send_icmp()

            if counter % 60 == 0:  # Every 60th iteration (1 minute)
                send_arp()

            counter += 1
            time.sleep(1)  # Sleep for 1 second
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt detected. Stopping packet sending.")

if __name__ == "__main__":
    print("Starting to send continuous packets to", target_ip)
    continuous_packets()
