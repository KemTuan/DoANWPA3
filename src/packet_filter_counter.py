from scapy.all import sniff, Dot11, Dot11Deauth, Dot11Auth, Dot11AssoReq
import time

# Khởi tạo các biến đếm số lượng gói tin trong một chu kỳ
packet_counts = {
    "deauth": 0,
    "ddos_auth": 0,
    "downgrade_wpa2": 0
}

# Địa chỉ MAC của AP mục tiêu bạn muốn giám sát (Thay bằng MAC của AP Lab của bạn)
TARGET_BSSID = "aa:bb:cc:dd:ee:ff" 

def packet_callback(packet):
    global packet_counts

    # Kiểm tra xem gói tin có phải là gói Wifi (Dot11) không
    if not packet.haslayer(Dot11):
        return

    # Lấy thông tin địa chỉ MAC nguồn, đích và BSSID (MAC của AP)
    addr1 = packet.addr1 # Đích (Receiver)
    addr2 = packet.addr2 # Nguồn (Transmitter)
    addr3 = packet.addr3 # BSSID (Thường là MAC của AP)

    # Lọc: Chỉ phân tích các gói tin liên quan đến AP mục tiêu của mình để tránh rác số liệu
    if TARGET_BSSID not in [addr1, addr2, addr3]:
        return

    # --- 1. LỌC GÓI TIN DEAUTH ---
    if packet.haslayer(Dot11Deauth):
        packet_counts["deauth"] += 1
        return

    # --- 2. LỌC GÓI TIN DDOS (Auth Flood / Association Flood) ---
    # Kẻ tấn công DDoS thường giả lập hàng ngàn gói Auth hoặc Assoc Request tới AP
    if packet.haslayer(Dot11Auth) and addr1 == TARGET_BSSID:
        packet_counts["ddos_auth"] += 1
        return

    # --- 3. LỌC DẤU HIỆU DOWNGRADE ATTACK (Tấn công hạ cấp) ---
    # Bản chất đơn giản ở mức 7-8 điểm: Phát hiện client đáng lẽ dùng WPA3 nhưng lại bị 
    # ép phải kết nối bằng WPA2 (Xác thực qua gói Association Request chứa chuẩn WPA2)
    if packet.haslayer(Dot11AssoReq) and addr1 == TARGET_BSSID:
        # Kiểm tra xem trong gói tin kết nối có chứa thông tin mã hóa cũ hay không
        packet_str = str(packet)
        # RSN là lớp chứa thông tin bảo mật. Nếu có RSN nhưng thiếu các trường của WPA3 (SAE)
        # mà chỉ có các trường cũ, ta ghi nhận là có kết nối WPA2 đổ vào AP WPA3
        if "RSN" in packet_str and "SAE" not in packet_str:
            packet_counts["downgrade_wpa2"] += 1

def start_sniffing(interface="wlan0", duration=10):
    global packet_counts
    print(f"[*] Đang tiến hành nghe trộm và lọc gói tin trên {interface} trong {duration} giây...")
    
    # Reset lại bộ đếm trước khi quét chu kỳ mới
    packet_counts = {"deauth": 0, "ddos_auth": 0, "downgrade_wpa2": 0}
    
    # Bắt đầu quét dữ liệu
    sniff(iface=interface, prn=packet_callback, timeout=duration, store=0)
    
    # Trả về kết quả đếm được sau chu kỳ (duration) giây
    return packet_counts

if __name__ == "__main__":
    # Test chạy thử hàm lọc độc lập
    # Trước khi chạy, hãy đảm bảo wlan0 đã ở Monitor Mode nhờ hàm setup trước đó của bạn
    while True:
        # Cứ 10 giây thu thập dữ liệu một lần
        results = start_sniffing(interface="wlan0", duration=10)
        
        print(f"\n--- KẾT QUẢ CHU KỲ VỪA QUA ---")
        print(f"[+] Số gói Deauth bắt được: {results['deauth']}")
        print(f"[+] Số gói Auth (Nghi vấn DDoS): {results['ddos_auth']}")
        print(f"[+] Số gói kết nối WPA2 (Nghi vấn Hạ cấp): {results['downgrade_wpa2']}")
        print(f"-------------------------------\n")
        
        # Đây chính là cục dữ liệu sau này bạn sẽ ghi ra file hoặc bắn về cho PRTG!
        time.sleep(1)