from scapy.all import *
import threading

sniff(iface='eth0', prn=self.analyze_packet, store=0)
class PacketAnalyzer:
    def __init__(self):
        self.packet_count = 0
        self.protocols = {}

    def analyze_packet(self, packet):
        self.packet_count += 1
        # Get packet information
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            packet_length = len(packet)

            # Count protocols
            if protocol not in self.protocols:
                self.protocols[protocol] = 1
            else:
                self.protocols[protocol] += 1

            # Print packet info
            print(f"Packet #{self.packet_count}: {src_ip} -> {dst_ip} | Protocol: {protocol} | Length: {packet_length} bytes")

    def start_capture(self):
        print("Starting packet capture...")
        sniff(prn=self.analyze_packet, store=0)

if __name__ == "__main__":
    analyzer = PacketAnalyzer()
    capture_thread = threading.Thread(target=analyzer.start_capture)
    capture_thread.start()

    try:
        while True:
            pass  # Keep the main thread alive
    except KeyboardInterrupt:
        print("\nStopping packet capture...")
        print(f"Total packets captured: {analyzer.packet_count}")
        print("Protocols used:")
        for proto, count in analyzer.protocols.items():
            print(f"Protocol {proto}: {count} packets")