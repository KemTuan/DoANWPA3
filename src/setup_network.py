import subprocess

def prepare_interface(interface="wlan0", channel=6):
    print(f"[*] Đang cấu hình {interface} sang chế độ Monitor...")
    try:
        subprocess.run(["sudo", "nmcli", "device", "set", interface, "managed", "no"], check=True)
        subprocess.run(["sudo", "systemctl", "stop", "wpa_supplicant"], check=True)
        subprocess.run(["sudo", "ip", "link", "set", interface, "down"], check=True)
        subprocess.run(["sudo", "iw", interface, "set", "type", "monitor"], check=True)
        subprocess.run(["sudo", "ip", "link", "set", interface, "up"], check=True)
        subprocess.run(["sudo", "iw", interface, "set", "channel", str(channel)], check=True)
        print(f"[+] {interface} đã sẵn sàng ở kênh {channel}.")
    except Exception as e:
        print(f"[-] Lỗi cấu hình mạng: {e}")