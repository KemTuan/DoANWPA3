# main.py
import threading
import time
import os
from simulator import Wpa3AttackSimulator
from monitor import run_monitor
from analyzer import Wpa3Analyzer
from scapy.all import rdpcap

PCAP_FILE = "data/simulated_attack.pcap"
TARGET_BSSID = "aa:bb:cc:dd:ee:ff"
TARGET_SSID = "WPA3_Lab_Network"

def menu_monitor():
    from src.setup_network import prepare_interface
    # Chuyển card sang monitor trước
    prepare_interface("wlan0", channel=6)
    print("\n--- CHỨC NĂNG GIÁM SÁT & VPN ---")
    print("1. Giám sát từ file PCAP (Dùng cho máy 1 card mạng)")
    print("2. Giám sát Live từ wlan0")
    choice = input("Lựa chọn: ")
    
    if choice == "1":
        # Chạy ẩn để bạn vẫn dùng menu được
        threading.Thread(target=run_monitor, args=(PCAP_FILE, None, 5), daemon=True).start()
        print("[+] Đang chạy tiến trình đọc PCAP và gửi VPN dưới nền.")
    elif choice == "2":
        threading.Thread(target=run_monitor, args=(None, "wlan0", 10), daemon=True).start()
        print("[+] Đang ngửi Live trên wlan0 và gửi VPN dưới nền.")

def menu_attack():
    print("\n--- GIẢ LẬP TẤN CÔNG (GHI VÀO PCAP) ---")
    print("1. Tấn công Deauth")
    print("2. Tấn công DoS Auth Flood")
    print("3. Tấn công Evil Twin WPA2 (Downgrade)")
    choice = input("Lựa chọn: ")
    
    sim = Wpa3AttackSimulator(target_bssid=TARGET_BSSID, pcap_file=PCAP_FILE)
    if choice == "1": sim.simulate_deauth()
    elif choice == "2": sim.simulate_auth_flood_dos()
    elif choice == "3": sim.simulate_downgrade_evil_twin(target_ssid=TARGET_SSID)

def menu_analyze():
    print("\n--- PHÂN TÍCH THUỘC TÍNH BẢO MẬT (PROPERTIES) ---")
    if not os.path.exists(PCAP_FILE):
        print("[-] Không tìm thấy file PCAP nào. Hãy chạy giả lập tấn công trước.")
        return
        
    packets = rdpcap(PCAP_FILE)
    print(f"[*] Đọc thành công {len(packets)} gói tin.")
    
    # Check Evil Twin
    alerts = Wpa3Analyzer.analyze_downgrade_evil_twin(packets, TARGET_SSID)
    if alerts:
        for a in alerts: print(a)
        
    # Check SAE & PMF
    for pkt in packets:
        sae_log = Wpa3Analyzer.parse_sae_handshake(pkt)
        if sae_log: print(sae_log)
        if Wpa3Analyzer.check_pmf_mandatory(pkt):
            print("[+] Xác nhận: Đã tìm thấy cờ báo hiệu PMF (Chuẩn WPA3).")

def main():
    # Khởi tạo thư mục data
    os.makedirs("data", exist_ok=True)
    
    while True:
        print("\n" + "="*35)
        print("   WPA3 SECURITY DEFENSE SYSTEM")
        print("="*35)
        print("1. Giám sát mạng & VPN Endpoint")
        print("2. Giả lập tấn công (Ghi PCAP)")
        print("3. Phân tích bảo mật WPA3 (Analyzer)")
        print("4. Thoát")
        
        choice = input("Vui lòng chọn chức năng (1-4): ")
        
        if choice == "1":
            menu_monitor()
        elif choice == "2":
            menu_attack()
            # Theo yêu cầu của bạn: sẵn ghi vào pcap -> gửi VPN luôn. 
            # Sau khi tạo file attack xong, tự động gọi monitor đọc file đó ném lên VPN
            print("[*] Tự động đẩy file mô phỏng vào luồng Monitor -> VPN...")
            threading.Thread(target=run_monitor, args=(PCAP_FILE, None, 5), daemon=True).start()
        elif choice == "3":
            menu_analyze()
        elif choice == "4":
            print("[!] Đang đóng hệ thống...")
            break
        else:
            print("[-] Lựa chọn không hợp lệ.")
            
        time.sleep(0.5) # Chống spam terminal

if __name__ == "__main__":
    main()