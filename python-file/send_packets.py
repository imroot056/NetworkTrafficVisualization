import time
from scapy.all import *

# Target IP address
target_ip = "172.18.0.2"  # Change this to the target IP address

# Function to send ICMP (Ping) packet
def send_icmp():
    pkt = IP(dst=target_ip)/ICMP()
    send(pkt, verbose=False)
    print("Sent ICMP packet to", target_ip)

# Function to send UDP packet
def send_udp():
    pkt = IP(dst=target_ip)/UDP(dport=53)/Raw(load="GET / HTTP/1.1\r\n")
    send(pkt, verbose=False)
    print("Sent UDP packet to", target_ip)

# Function to send TCP packet
def send_tcp():
    pkt = IP(dst=target_ip)/TCP(dport=80, flags="S")
    send(pkt, verbose=False)
    print("Sent TCP packet to", target_ip)

# Function to send ARP packet
def send_arp():
    pkt = ARP(op=1, pdst=target_ip, psrc="192.168.1.1")  # Replace with your gateway IP
    send(pkt, verbose=False)
    print("Sent ARP packet to", target_ip)

# Function to send DNS request (UDP)
def send_dns():
    pkt = IP(dst=target_ip)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com"))
    send(pkt, verbose=False)
    print("Sent DNS packet to", target_ip)

# Function to simulate a simple FTP request (TCP)
def send_ftp():
    pkt = IP(dst=target_ip)/TCP(dport=21, flags="S")
    send(pkt, verbose=False)
    print("Sent FTP packet to", target_ip)

# Function to simulate a DHCP request (UDP)
def send_dhcp():
    pkt = Ether()/IP(src="0.0.0.0", dst="255.255.255.255")/UDP(sport=68, dport=67)/BOOTP(chaddr="00:11:22:33:44:55")/DHCP(options=[("message-type", "discover"), "end"])
    sendp(pkt, verbose=False)
    print("Sent DHCP Discover packet to", target_ip)

# Main function to continuously send packets
def continuous_packets():
    try:
        while True:
            send_icmp()
            send_udp()
            send_tcp()
            send_arp()
            send_dns()
            send_ftp()
            send_dhcp()
            time.sleep(1)  # Sleep for 1 second before sending more packets
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt detected. Stopping packet sending.")
        # Clean-up code (if necessary) goes here

if __name__ == "__main__":
    print("Starting to send continuous packets to", target_ip)
    continuous_packets()
