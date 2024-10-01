from scapy.all import sniff, IP, UDP, Raw

# Function to process captured packets
def packet_callback(packet):
    if packet.haslayer(UDP):  # Check for UDP layer
        ip_layer = packet[IP]
        udp_layer = packet[UDP]
        payload = packet[Raw].load.decode(errors='ignore') if packet.haslayer(Raw) else "No Payload"

        # Print packet details
        print("Packet captured:")
        print(f"---------------------------------------------")
        print(f"Source IP: {ip_layer.src}")
        print(f"Source Port: {udp_layer.sport}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Destination Port: {udp_layer.dport}")
        print(f"Payload: {payload}")
        print(f"---------------------------------------------\n")

# Start packet sniffing
def start_sniffing(interface=None):
    print("Starting UDP packet capture...\nPress Ctrl+C to stop.")
    try:
        sniff(filter="udp", prn=packet_callback, store=0, iface=interface)
    except KeyboardInterrupt:
        print("\nPacket capture stopped.")

if __name__ == "__main__":
    # Optionally specify an interface here, e.g., "eth0", "wlan0", or leave it as None for all interfaces.
    start_sniffing()  