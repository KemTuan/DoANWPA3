# src/setup_network.py
import subprocess

def prepare_interface(interface="wlan0", channel=36):
    print(f"[*] Đang cấu hình {interface} sang chế độ Monitor ở kênh {channel} (5GHz)...")
    try:
        # Ngắt card mạng khỏi sự quản lý của Network Manager để tránh xung đột
        subprocess.run(["sudo", "nmcli", "device", "set", interface, "managed", "no"], check=True)
        subprocess.run(["sudo", "systemctl", "stop", "wpa_supplicant"], check=True, stderr=subprocess.DEVNULL)
        
        # Chuyển đổi sang chế độ Monitor
        subprocess.run(["sudo", "ip", "link", "set", interface, "down"], check=True)
        subprocess.run(["sudo", "iw", interface, "set", "type", "monitor"], check=True)
        subprocess.run(["sudo", "ip", "link", "set", interface, "up"], check=True)
        
        # Ép phần cứng nghe trên kênh cụ thể
        subprocess.run(["sudo", "iw", interface, "set", "channel", str(channel)], check=True)
        
        print(f"[+] Cấu hình thành công: {interface} đã sẵn sàng (Monitor Mode - Channel {channel}).")
    except subprocess.CalledProcessError as e:
        print(f"[-] Lỗi cấu hình mạng: Lệnh {e.cmd} thất bại.")
        print("[!] Gợi ý: Hãy đảm bảo bạn chạy script với quyền 'sudo' và tên card mạng chính xác.")
    except Exception as e:
         print(f"[-] Lỗi không xác định: {e}")