import scapy.all as scapy

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def process_sniffed_packet(packet):
    if packet.haslayer(scapy.IP):
        print(packet[scapy.IP].src + " -> " + packet[scapy.IP].dst)

sniff("eth0")