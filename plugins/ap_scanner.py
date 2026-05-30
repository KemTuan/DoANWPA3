# plugins/ap_scanner.py
import sys
from scapy.all import sniff, Dot11Beacon, Dot11Elt

# =======================================================
# CẤU HÌNH BỘ LỌC AN TOÀN (HARDCODED FILTER)
# Hỗ trợ nhiều Router Lab, không quan tâm SSID là gì
# =======================================================
TARGET_MACS = [
    "c0:b1:01:29:e8:cd", # Thay địa chỉ MAC của Router WPA3 vào đây
    "aa:bb:cc:dd:ee:ff"  # Thay địa chỉ MAC của Router WPA2 (Fake AP) vào đây
]

# Biến lưu trữ những MAC đã tìm thấy để tránh in trùng lặp ra màn hình
found_macs = set()

def packet_handler(packet):
    """Xử lý gói tin: Bỏ qua SSID, chỉ kiểm tra MAC có nằm trong danh sách không"""
    if packet.haslayer(Dot11Beacon):
        bssid = packet.addr3
        
        if bssid is None:
            return

        # Đưa tất cả về chữ thường để so sánh tránh lỗi gõ hoa/thường
        bssid_lower = bssid.lower()
        target_macs_lower = [mac.lower() for mac in TARGET_MACS]

        # BỘ LỌC TĨNH: Nếu MAC nằm trong danh sách Lab của bạn
        if bssid_lower in target_macs_lower:
            
            # Nếu MAC này chưa được báo cáo lên màn hình
            if bssid_lower not in found_macs:
                try:
                    ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore')
                except Exception:
                    ssid = "Unknown (Hidden SSID)"

                print(f"\n[+] TÌM THẤY THIẾT BỊ LAB:")
                print(f"    - BSSID: {bssid}")
                print(f"    - SSID : {ssid}")
                
                # Đánh dấu là đã tìm thấy
                found_macs.add(bssid_lower)

            # TỐI ƯU TRẢI NGHIỆM: Nếu đã tìm thấy đủ số lượng Router trong list thì dừng luôn,
            # không cần chờ hết thời gian timeout.
            if len(found_macs) == len(TARGET_MACS):
                print("\n[+] Đã tìm thấy toàn bộ thiết bị trong danh sách. Tự động dừng quét sớm.")
                sys.exit(0)

def main():
    if len(sys.argv) < 3:
        print("[-] Lỗi: Cần truyền vào tham số [Interface] và [Timeout]")
        sys.exit(1)
        
    interface = sys.argv[1]
    timeout_sec = int(sys.argv[2])
    
    print(f"[*] Cảm biến đang quét tín hiệu Beacon trên kênh vô tuyến ({interface})...")
    print(f"[*] Bộ lọc Tĩnh: Tìm kiếm {len(TARGET_MACS)} thiết bị Lab...")
    
    # Quét sóng
    sniff(iface=interface, prn=packet_handler, timeout=timeout_sec, store=0)
    
    # Báo cáo kết quả nếu hết thời gian mà chưa tìm đủ
    if len(found_macs) < len(TARGET_MACS):
        print(f"\n[*] Đã hết thời gian quét ({timeout_sec}s). Tìm thấy {len(found_macs)}/{len(TARGET_MACS)} thiết bị.")

if __name__ == "__main__":
    main()