# src/simulator.py
import time
import os
import subprocess

class Wpa3AttackSimulator:
    # Đã sửa lại target_bssid thành rỗng mặc định để bắt buộc quét trước
    def __init__(self, target_bssid="", interface="wlan0", plugin_dir="plugins"):
        self.target_bssid = target_bssid
        self.interface = interface
        self.plugin_dir = plugin_dir
        os.makedirs(self.plugin_dir, exist_ok=True)

    def _run_plugin_safely(self, script_name, args_list):
        script_path = os.path.join(self.plugin_dir, script_name)
        if not os.path.exists(script_path):
            print(f"[-] LỖI AN TOÀN: Không tìm thấy script '{script_name}' trong thư mục '{self.plugin_dir}'.")
            return False

        print(f"[*] Đang nạp module từ: {script_path}...")
        command = ["python3", script_path] + args_list
        try:
            subprocess.run(command, check=True)
            return True
        except subprocess.CalledProcessError as e:
            print(f"\n[-] MODULE CRASH: Script '{script_name}' đã dừng đột ngột (Mã lỗi: {e.returncode}).")
            return False
        except KeyboardInterrupt:
            print("\n[!] Đã ép dừng module bằng tay.")
            return False

    # --- BỔ SUNG: HÀM QUÉT MẠNG ---
    def run_network_scan(self, timeout="15"):
        print("\n" + "📡" * 20)
        print(f"[!] KHỞI CHẠY KIỂM THỬ: RÀ QUÉT MẠNG (RECONNAISSANCE)")
        print(f"[*] Đang quét Beacon frames trên giao diện: {self.interface}")
        print("📡" * 20)
        self._run_plugin_safely("ap_scanner.py", [self.interface, str(timeout)])
        print("\n[+] Trạm điều phối: Hoàn tất quá trình trinh sát. Hãy copy BSSID mục tiêu để khóa.")

    # --- BỔ SUNG: HÀM KHÓA MỤC TIÊU ---
    def set_target(self, bssid):
        self.target_bssid = bssid
        print(f"[+] Đã khóa mục tiêu mới: {self.target_bssid}")

    def run_deauth_test(self, client_mac="ff:ff:ff:ff:ff:ff", count="150"):
        if not self.target_bssid:
            print("[-] LỖI: Bạn phải thực hiện Khóa mục tiêu (BSSID) trước khi tấn công!")
            return
            
        print("\n" + "⚔️" * 20)
        print(f"[!] KHỞI CHẠY KIỂM THỬ: DEAUTHENTICATION ATTACK")
        print(f"[*] Mục tiêu: {self.target_bssid} | Nạn nhân: {client_mac}")
        print("⚔️" * 20)
        self._run_plugin_safely("deauth_test.py", [self.interface, self.target_bssid, client_mac, str(count)])
        print("\n[+] Trạm điều phối: Đã thu hồi quyền kiểm soát từ module Deauth.")

    def run_sae_dos_test(self, duration_sec="10"):
        if not self.target_bssid:
            print("[-] LỖI: Bạn phải thực hiện Khóa mục tiêu (BSSID) trước khi tấn công!")
            return
            
        print("\n" + "🔥" * 20)
        print(f"[!] KHỞI CHẠY KIỂM THỬ: SAE AUTHENTICATION FLOOD (DoS)")
        print(f"[*] Mục tiêu: {self.target_bssid} | Thời lượng: {duration_sec}s")
        print("🔥" * 20)
        self._run_plugin_safely("sae_dos_test.py", [self.interface, self.target_bssid, str(duration_sec)])
        print("\n[+] Trạm điều phối: Đã thu hồi quyền kiểm soát từ module DoS.")

    def run_evil_twin_setup(self, target_ssid):
        print("\n" + "🎭" * 20)
        print(f"[!] KHỞI CHẠY KIỂM THỬ: EVIL TWIN / DOWNGRADE AP")
        print(f"[*] Mục tiêu SSID: {target_ssid}")
        print("🎭" * 20)
        self._run_plugin_safely("evil_twin_setup.py", [self.interface, target_ssid])
        print("\n[+] Trạm điều phối: Đã thu hồi quyền kiểm soát từ module Evil Twin.")
        
    def run_probe_flood_test(self, target_ssid, count="100"):
        """Kịch bản mới: Trinh sát ồn ào (Probe Request Flood)"""
        print("\n" + "🛰️" * 20)
        print(f"[!] KHỞI CHẠY KIỂM THỬ: PROBE REQUEST FLOOD")
        print(f"[*] Mục tiêu tìm kiếm (SSID): {target_ssid}")
        print("🛰️" * 20)
        
        # Gọi file plugin 'probe_flood.py' và truyền 3 tham số: interface, ssid, count
        self._run_plugin_safely("probe_flood.py", [self.interface, target_ssid, str(count)])
        
        print("\n[+] Trạm điều phối: Đã thu hồi quyền kiểm soát từ module Probe Flood.")