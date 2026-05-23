# src/monitor.py
import time
import requests
import os
from scapy.all import sniff, Dot11, Dot11Deauth, Dot11Auth, Dot11AssoReq
from analyzer import Wpa3Analyzer 

TARGET_BSSID = "aa:bb:cc:dd:ee:ff"
DESKTOP_TAILSCALE_IP = "100.124.99.87"
VPN_URL = f"http://{DESKTOP_TAILSCALE_IP}:8000/api/metrics"

packet_counts = {"deauth": 0, "ddos_auth": 0, "downgrade": 0}

def packet_callback(packet):
    global packet_counts
    if not packet.haslayer(Dot11): return
    
    addr1, addr2, addr3 = packet.addr1, packet.addr2, packet.addr3
    if TARGET_BSSID not in [addr1, addr2, addr3]: return

    # 1. Đếm Deauth
    if packet.haslayer(Dot11Deauth):
        packet_counts["deauth"] += 1
        
    # 2. Đếm DoS Auth (Gọi Wpa3Analyzer để loại trừ các gói SAE hợp lệ)
    elif packet.haslayer(Dot11Auth) and packet.addr1 == TARGET_BSSID:
        if not Wpa3Analyzer.is_sae_auth(packet): # Nếu không phải WPA3 Auth -> Nghi vấn DoS
            packet_counts["ddos_auth"] += 1
            
    # 3. Đếm Hạ cấp (Gọi trực tiếp detect_downgrade từ Analyzer)
    elif packet.addr1 == TARGET_BSSID and Wpa3Analyzer.detect_downgrade(packet):
        packet_counts["downgrade"] += 1

def run_monitor(pcap_file=None, live_interface="wlan0", duration=5):
    # ... (Phần code bên dưới giữ nguyên như cũ của bạn, xóa biến packet_buffer đi) ...
    global packet_counts
    print(f"\n[*] Bắt đầu thu thập dữ liệu (Nguồn: {pcap_file if pcap_file else live_interface})")
    
    if pcap_file and os.path.exists(pcap_file):
        packets = sniff(offline=pcap_file, prn=packet_callback, store=0)
        time.sleep(1)
    else:
        sniff(iface=live_interface, prn=packet_callback, timeout=duration, store=0)
    
    try:
        response = requests.post(VPN_URL, json=packet_counts, timeout=2)
        if response.status_code == 200:
            print(f"[+] VPN Updated: {packet_counts}")
    except Exception:
        print(f"[-] Lỗi kết nối VPN Desk. Packet thống kê: {packet_counts}")
        
    packet_counts = {"deauth": 0, "ddos_auth": 0, "downgrade": 0}