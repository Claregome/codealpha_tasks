from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from datetime import datetime


def analyze_packet(packet):
    print("\n=== Packet Captured ===")
    # Timestamp of packet
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol Number: {ip_layer.proto}")

        # Analyze transport layer based on protocol
        if TCP in packet:
            tcp_layer = packet[TCP]
            print("Protocol: TCP")
            print(f"Source Port: {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")
            print(f"Flags: {tcp_layer.flags}")
        elif UDP in packet:
            udp_layer = packet[UDP]
            print("Protocol: UDP")
            print(f"Source Port: {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")
        elif ICMP in packet:
            print("Protocol: ICMP")
            print(f"ICMP Type: {packet[ICMP].type}")
        else:
            print("Other Transport Protocol")

        # Display raw payload (if any)
        payload = bytes(packet[IP].payload)
        if payload:
            print(f"Payload (Raw): {payload[:50]}...")  # limit to 50 bytes for readability
    else:
        print("Non-IP Packet")


# Start sniffing (count = 10 packets)
print("Starting packet capture... (press Ctrl+C to stop)")
sniff(prn=analyze_packet, count=10)
