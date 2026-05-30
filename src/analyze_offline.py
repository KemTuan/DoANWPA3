# analyze_offline.py
from scapy.all import rdpcap
from analyzer import Wpa3Analyzer
import os

def process_lab_data(pcap_file, target_ssid="WPA3_Lab_Network"):
    print(f"\n[*] Đang nạp file dữ liệu: {pcap_file}")
    
    if not os.path.exists(pcap_file):
        print(f"[-] Lỗi: Không tìm thấy file '{pcap_file}'.")
        return

    packets = rdpcap(pcap_file)
    print(f"[*] Đã đọc thành công {len(packets)} gói tin.\n")
    
    stats = {"sae_handshakes": 0, "downgrade_attempts": 0, "pmf_beacons": 0}
    
    # 1. Quét tìm các đợt hạ cấp mạng (Evil Twin)
    alerts = Wpa3Analyzer.analyze_downgrade_evil_twin(packets, target_ssid)
    if alerts:
        print("--- KẾT QUẢ QUÉT HẠ CẤP ---")
        for alert in alerts:
            print(alert)
        print("-" * 25 + "\n")
    
    # 2. Phân tích chi tiết từng gói tin
    print("--- PHÂN TÍCH ĐẶC TÍNH WPA3 ---")
    for pkt in packets:
        # Bóc tách tiến trình bắt tay Dragonfly
        sae_log = Wpa3Analyzer.parse_sae_handshake(pkt)
        if sae_log:
            print(sae_log)
            stats["sae_handshakes"] += 1
            
        # Tìm cờ bảo vệ PMF
        if Wpa3Analyzer.check_pmf_mandatory(pkt):
            stats["pmf_beacons"] += 1
            
        # Đếm các gói bị ép về WPA2
        if Wpa3Analyzer.detect_downgrade(pkt):
            stats["downgrade_attempts"] += 1
            
    print(f"\n[+] Hoàn tất bóc tách dữ liệu mạng.")
    print(f"    - Khung quản lý PMF tìm thấy: {stats['pmf_beacons']}")
    print(f"    - Tiến trình bắt tay SAE: {stats['sae_handshakes']}")
    print(f"    - Yêu cầu kết nối WPA2 (Downgrade): {stats['downgrade_attempts']}")

if __name__ == "__main__":
    print("=" * 45)
    print("   CÔNG CỤ BÓC TÁCH MẬT MÃ WPA3 OFFLINE")
    print("=" * 45)
    
    # Giả sử bạn dùng Wireshark bắt được file 'lab_capture.pcap'
    target_pcap = input("Nhập đường dẫn file PCAP cần phân tích (VD: data/capture.pcap): ")
    target_ssid = input("Nhập SSID mạng cần giám định: ")
    
    process_lab_data(target_pcap, target_ssid)