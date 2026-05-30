# src/monitor.py
import time
import requests
import os
import threading
from scapy.all import sniff, Dot11, Dot11Deauth, Dot11Auth, Dot11AssoReq, Dot11ProbeReq
from analyzer import Wpa3Analyzer 

# --- CẤU HÌNH ĐA MỤC TIÊU ---
ROUTER_MACS = [
    "c0:b1:01:29:e8:cd", # MAC Router 1 (Lab A)
    "aa:bb:cc:dd:ee:ff"  # MAC Router 2 (Lab B) - BẠN NHỚ THAY MAC THẬT VÀO ĐÂY NHÉ
]
TARGET_SSID = "WPA3_Lab_Network"
DESKTOP_TAILSCALE_IP = "100.124.99.87"
VPN_URL = f"http://{DESKTOP_TAILSCALE_IP}:8000/api/metrics"

# Khởi tạo bộ đếm MỚI: Là một Dictionary chứa dữ liệu riêng cho từng Router
# Cấu trúc: { "MAC_1": {"deauth": 0, "ddos_auth": 0...}, "MAC_2": {...} }
packet_counts = {mac: {"deauth": 0, "ddos_auth": 0, "downgrade": 0, "probe_scan": 0} for mac in ROUTER_MACS}
last_send_time = time.time()
lock = threading.Lock() 

def _send_to_dashboard(force_send=False):
    """Gửi dữ liệu về SOC Dashboard qua VPN theo chu kỳ"""
    global packet_counts, last_send_time
    current_time = time.time()
    
    if force_send or (current_time - last_send_time >= 2.0):
        with lock:
            # Tạo bản sao dữ liệu hiện tại để gửi đi
            current_payload = packet_counts.copy()
            # Reset lại toàn bộ bộ đếm cho tất cả Router về 0
            packet_counts = {mac: {"deauth": 0, "ddos_auth": 0, "downgrade": 0, "probe_scan": 0} for mac in ROUTER_MACS}
            last_send_time = current_time
            
        try:
            # Thay vì gửi 1 cục, chúng ta gửi MẢNG dữ liệu chứa nhiều Router
            payload_to_send = []
            for mac, data in current_payload.items():
                # Chỉ gửi những Router có dữ liệu > 0 để tiết kiệm băng thông (Tùy chọn)
                # Tuy nhiên, để biểu đồ không bị đứt quãng, ta gửi tất cả.
                data["bssid"] = mac # Gắn nhãn MAC vào dữ liệu của Router đó
                payload_to_send.append(data)
                
            requests.post(VPN_URL, json=payload_to_send, timeout=2)
            
            if not force_send:
                 # Code in log cho đẹp (Tùy chọn, có thể tắt đi nếu thấy rối)
                 for item in payload_to_send:
                     if sum([v for k, v in item.items() if k != "bssid"]) > 0:
                         print(f"[⇄ VPN Sync] Đồng bộ Router {item['bssid']}: {item}")
                         
        except Exception:
            pass 

def live_packet_callback(packet):
    global packet_counts
    if not packet.haslayer(Dot11): return
    
    addr1, addr2, addr3 = packet.addr1, packet.addr2, packet.addr3
    
    # 1. BẮT DOWNGRADE
    if packet.haslayer(Dot11AssoReq):
        if Wpa3Analyzer.detect_downgrade(packet):
            fake_ap_mac = packet.addr1 
            # Giả sử Evil Twin nhắm vào Router 1 (Hoặc bạn có thể tạo logic nhận diện phức tạp hơn)
            # Tạm thời gán downgrade cho Router 1 để dễ quản lý.
            target_mac = ROUTER_MACS[0] 
            
            with lock: packet_counts[target_mac]["downgrade"] += 1
            print(f"\n🚨 [CRITICAL] PHÁT HIỆN EVIL TWIN. Rogue AP MAC: {fake_ap_mac}")
            _send_to_dashboard(force_send=True)
            return

    # 2. BẮT PROBE REQUEST (Rà quét)
    # Probe request là rà quét chung toàn mạng, không nhắm đích danh MAC nào.
    # Nhưng để hiển thị lên Dashboard, ta sẽ cộng điểm probe này cho CẢ 2 ROUTER.
    if packet.haslayer(Dot11ProbeReq):
        with lock:
            for mac in ROUTER_MACS:
                packet_counts[mac]["probe_scan"] += 1

    # ===================================================================
    # LỌC RÁC: Chỉ xử lý tiếp nếu gói tin có liên quan đến 1 trong 2 Router
    # ===================================================================
    matched_mac = None
    for mac in ROUTER_MACS:
        if mac in [addr1, addr2, addr3]:
            matched_mac = mac
            break
            
    if not matched_mac: return # Gói tin của mạng hàng xóm -> Bỏ qua

    # 3. BẮT DEAUTH (Chỉ cộng cho Router bị tấn công)
    if packet.haslayer(Dot11Deauth):
        with lock: packet_counts[matched_mac]["deauth"] += 1
        
    # 4. BẮT DoS AUTH (Chỉ cộng cho Router bị tấn công)
    elif packet.haslayer(Dot11Auth) and packet.addr1 == matched_mac:
        if not Wpa3Analyzer.is_sae_auth(packet):
            with lock: packet_counts[matched_mac]["ddos_auth"] += 1

def run_real_monitor(live_interface="wlan0"):
    print("\n" + "═" * 50)
    print("  🛡️ WPA3 MULTI-TARGET IDS SENSOR ĐANG CHẠY NGẦM 🛡️")
    print("═" * 50)
    print(f"[*] Đang giám sát đồng thời {len(ROUTER_MACS)} Router.")
    
    def vpn_sync_loop():
        while True:
            time.sleep(2)
            _send_to_dashboard()
            
    sync_thread = threading.Thread(target=vpn_sync_loop, daemon=True)
    sync_thread.start()

    try:
        sniff(iface=live_interface, prn=live_packet_callback, store=0)
    except Exception as e:
        print(f"\n[!] Cảm biến lỗi: {e}")