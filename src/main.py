# src/main.py
import threading
import time
import os
from monitor import run_real_monitor
from analyzer import Wpa3Analyzer
from simulator import Wpa3AttackSimulator
from scapy.all import rdpcap
from setup_network import prepare_interface

MONITOR_INTERFACE = "wlan0"
WIFI_CHANNEL = 36 
TARGET_SSID = "WPA3_Lab_Network"

def menu_attack_simulation():
    current_target_bssid = "" 
    sim = Wpa3AttackSimulator(target_bssid=current_target_bssid, interface=MONITOR_INTERFACE)
    
    while True:
        print("\n--- MODULE KIỂM THỬ XÂM NHẬP (ATTACK SIMULATOR) ---")
        print(f"Mục tiêu hiện tại: {current_target_bssid if current_target_bssid else '[CHƯA XÁC ĐỊNH]'}")
        print("-" * 45)
        print("1. [Trinh sát] Quét các mạng Wi-Fi xung quanh")
        print("2. [Thiết lập] Nhập BSSID mục tiêu để khóa")
        print("3. [Kiểm thử] Trinh sát ồn ào (Probe Request Flood)") # <--- MỚI THÊM
        print("4. [Kiểm thử] Ngắt kết nối (Deauth Test)")
        print("5. [Kiểm thử] Ngập lụt xác thực (SAE Auth Flood)")
        print("6. [Kiểm thử] Khởi tạo AP hạ cấp (Rogue AP Setup)")
        print("7. Quay lại Menu chính")
        
        choice = input("Lựa chọn kịch bản (1-7): ")
        
        if choice == "1":
            sim.run_network_scan(timeout="15")
            
        elif choice == "2":
            new_bssid = input("Nhập địa chỉ MAC của Router WPA3 mục tiêu (VD: c0:b1...): ")
            current_target_bssid = new_bssid.strip()
            sim.set_target(current_target_bssid)
            
        elif choice == "3": # <--- LOGIC GỌI PROBE FLOOD
            target_ssid = input(f"Nhập SSID muốn trinh sát (Mặc định: {TARGET_SSID}): ") or TARGET_SSID
            count = input("Số lượng gói tin muốn bắn (Mặc định: 100): ") or "100"
            sim.run_probe_flood_test(target_ssid=target_ssid, count=count)
            
        elif choice == "4":
            sim.run_deauth_test()
            
        elif choice == "5":
            sim.run_sae_dos_test(duration_sec=10)
            
        elif choice == "6":
            target_ssid = input(f"Nhập SSID để phát giả mạo (Mặc định: {TARGET_SSID}): ") or TARGET_SSID
            sim.run_evil_twin_setup(target_ssid=target_ssid)
            
        elif choice == "7":
            break
            
        else:
            print("[-] Lựa chọn không hợp lệ.")

def menu_analyze_offline():
    print("\n--- BÓC TÁCH GÓI TIN WPA3 (OFFLINE) ---")
    pcap_path = input("Nhập đường dẫn file PCAP (VD: data/capture.pcap): ")
    
    if not os.path.exists(pcap_path):
        print("[-] Không tìm thấy file.")
        return
        
    packets = rdpcap(pcap_path)
    print(f"[*] Đang phân tích {len(packets)} gói tin...")
    
    for pkt in packets:
        if Wpa3Analyzer.check_pmf_mandatory(pkt):
            print("[+] [PMF] Đã tìm thấy cờ Protected Management Frames.")
        
        sae_log = Wpa3Analyzer.parse_sae_handshake(pkt)
        if sae_log:
            print(sae_log)
            
            
def main():
    os.makedirs("data", exist_ok=True)
    ids_thread = None # Biến giữ thread của cảm biến
    
    while True:
        print("\n" + "═" * 45)
        print("   WPA3 SECURITY DEFENSE PLATFORM")
        print("═" * 45)
        print("1. Chuyển đổi Card mạng sang Monitor Mode")
        
        # Đổi mô tả Option 2 cho phù hợp
        if ids_thread and ids_thread.is_alive():
            print("2. [Phòng thủ] Cảm biến IDS đang CHẠY NGẦM 🟢")
        else:
            print("2. [Phòng thủ] Bật Cảm biến IDS chạy ngầm 🔴")
            
        print("3. [Kiểm thử] Khởi chạy Module Tấn công (Simulator)")
        print("4. [Chứng minh] Phân tích mật mã học WPA3 Offline")
        print("5. Thoát")
        
        choice = input("Vui lòng chọn chức năng (1-5): ")
        
        if choice == "1":
            try:
                prepare_interface(MONITOR_INTERFACE, channel=WIFI_CHANNEL)
            except Exception as e:
                print(f"[-] Không thể chuyển Mode: {e}")
                
        elif choice == "2":
            if ids_thread and ids_thread.is_alive():
                print("[!] Cảm biến đã đang hoạt động rồi!")
            else:
                # KIẾN TRÚC ĐA LUỒNG: Bật cảm biến chạy ngầm
                ids_thread = threading.Thread(target=run_real_monitor, args=(MONITOR_INTERFACE,), daemon=True)
                ids_thread.start()
                time.sleep(1) # Chờ 1s cho chữ in ra đẹp
                print("[+] Cảm biến ngầm đã kích hoạt thành công.")
                
        elif choice == "3":
            if not (ids_thread and ids_thread.is_alive()):
                print("[-] LƯU Ý: Bạn chưa bật Cảm biến IDS (Option 2). Dashboard sẽ không nhận được Log!")
            menu_attack_simulation()
            
        elif choice == "4":
            menu_analyze_offline()
            
        elif choice == "5":
            print("[!] Đang đóng hệ thống...")
            break
            
        time.sleep(1)

if __name__ == "__main__":
    main()