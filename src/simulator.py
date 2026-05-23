# src/simulator.py
import time
import os
from scapy.all import (
    RadioTap, Dot11, Dot11Deauth, Dot11Auth, Dot11Beacon,
    Dot11Elt, wrpcap
)
import random
class Wpa3AttackSimulator:
    def __init__(self, target_bssid, client_mac="ff:ff:ff:ff:ff:ff", pcap_file="data/simulated_attack.pcap"):
        self.target_bssid = target_bssid
        self.client_mac = client_mac
        self.pcap_file = pcap_file
        
        # Xóa file cũ nếu tồn tại
        if os.path.exists(self.pcap_file):
            os.remove(self.pcap_file)

def generate_random_mac():
    return "00:%02x:%02x:%02x:%02x:%02x" % (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255)
    )

    def save_packet(self, packet):
        """Ghi gói tin trực tiếp vào file PCAP"""
        wrpcap(self.pcap_file, packet, append=True)

    def simulate_deauth(self, count=100):
        print(f"[*] Tạo {count} gói Deauth vào file PCAP...")
        for _ in range(count):
            packet1 = RadioTap() / Dot11(addr1=self.client_mac, addr2=self.target_bssid, addr3=self.target_bssid) / Dot11Deauth(reason=7)
            self.save_packet(packet1)
        print(f"[+] Hoàn tất nạp gói Deauth vào {self.pcap_file}")

    def simulate_auth_flood_dos(self, count=300):
        print(f"[*] Tạo {count} gói DoS Auth Flood vào file PCAP...")
        for _ in range(count):
            fake_client = generate_random_mac()
            packet = (RadioTap() / 
                      Dot11(addr1=self.target_bssid, addr2=fake_client, addr3=self.target_bssid) / 
                      Dot11Auth(algo=0, seqnum=1, status=0))
            self.save_packet(packet)
        print(f"[+] Hoàn tất nạp gói DDoS Auth vào {self.pcap_file}")

    def simulate_downgrade_evil_twin(self, target_ssid="WPA3_Lab_Network", count=50):
        print(f"[*] Tạo gói Beacon giả mạo (Evil Twin WPA2) vào file PCAP...")
        fake_ap_bssid = "00:11:22:33:44:55"
        
        essid_el = Dot11Elt(ID="SSID", info=target_ssid)
        rates_el = Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96")
        rsn_wpa2_info = (
            b"\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x00\x00"
        )
        rsn_el = Dot11Elt(ID="RSNinfo", info=rsn_wpa2_info)
        
        packet = (RadioTap() / 
                  Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=fake_ap_bssid, addr3=fake_ap_bssid) / 
                  Dot11Beacon(cap=0x1104) / 
                  essid_el / rates_el / rsn_el)
        
        for _ in range(count):
            self.save_packet(packet)
        print(f"[+] Hoàn tất nạp gói Evil Twin vào {self.pcap_file}")